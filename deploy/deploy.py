#!/usr/bin/env python3
"""Pull tested public releases; deploy static files or a Docker API image."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request


def fetch(url, limit=2 * 1024 * 1024):
    request = urllib.request.Request(url, headers={
        'User-Agent': 'rps9-deployer', 'Accept': 'application/vnd.github+json',
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Download exceeds configured size limit')
    return data


def api(repo, path):
    return json.loads(fetch(f'https://api.github.com/repos/{repo}/{path}'))


def download(url, destination, limit):
    request = urllib.request.Request(url, headers={'User-Agent': 'rps9-deployer'})
    total = 0
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=120) as response, destination.open('wb') as output:
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError('Release archive too large')
            digest.update(chunk)
            output.write(chunk)
    return digest.hexdigest()


def extract_site(archive, destination):
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        if len(members) > 10000 or sum(m.size for m in members) > 512 * 1024 * 1024:
            raise ValueError('Expanded release exceeds size limit')
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise ValueError('Unsafe archive member')
        # Extract only regular files/directories, with fixed public permissions.
        for member in members:
            target = destination.joinpath(*PurePosixPath(member.name).parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as content, target.open('wb') as output:
                    shutil.copyfileobj(content, output)
                target.chmod(0o644)


def switch_link(link, target):
    temporary = link.with_name(link.name + '.next')
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    temporary.replace(link)


def health(url, version=None, attempts=20, expected_status=200):
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={
                'Host': 'rps9.net', 'User-Agent': 'rps9-deployer', 'Cache-Control': 'no-cache',
            })
            with urllib.request.urlopen(request, timeout=5) as response:
                body = response.read(2 * 1024 * 1024)
                if response.status == expected_status and (version is None or body.decode().strip() == version):
                    return
        except urllib.error.HTTPError as error:
            if error.code == expected_status and version is None:
                return
        except (OSError, ValueError):
            pass
        if attempt + 1 < attempts:
            time.sleep(2)
    raise RuntimeError(f'Health check failed: {url}')


def deploy_site(config, archive, sha):
    root = Path(config['root'])
    release = root / sha
    current = root / 'current'
    previous = current.resolve(strict=True)
    if previous == release:
        health(config['health_url'] + 'version.txt', version=sha)
        return
    if release.exists():
        shutil.rmtree(release)
    with tempfile.TemporaryDirectory(prefix='.stage-', dir=root) as temporary:
        staging = Path(temporary) / 'site'
        staging.mkdir()
        extract_site(archive, staging)
        if not (staging / 'index.html').is_file() or (staging / 'version.txt').read_text().strip() != sha:
            raise ValueError('Build is missing its entrypoint or has the wrong commit')
        # Keep previous hashed assets working for browsers with an old page open.
        old_assets = previous / 'assets'
        if old_assets.is_dir():
            for asset in old_assets.iterdir():
                target = staging / 'assets' / asset.name
                if asset.is_file() and not target.exists():
                    target.parent.mkdir(exist_ok=True)
                    shutil.copy2(asset, target)
        staging.rename(release)
    switch_link(current, release)
    try:
        health(config['health_url'] + 'version.txt', version=sha)
        health(config['health_url'])
        health(config['health_url'] + 'api/db/health', expected_status=401)
    except Exception:
        switch_link(current, previous)
        raise
    switch_link(root / 'previous', previous)


def compose(config, image, *arguments, candidate=False):
    env = dict(os.environ, API_IMAGE=image)
    project = config['project'] + ('-candidate' if candidate else '')
    path = config['candidate_compose'] if candidate else config['compose']
    return subprocess.run(
        ['docker', 'compose', '-p', project, '-f', path, *arguments],
        check=True, env=env, text=True, stdout=subprocess.PIPE,
    ).stdout.strip()


def deploy_api(config, archive, sha):
    image = f'rps9-api:{sha}'
    container = compose(config, image, 'ps', '-q', 'api')
    if not container:
        raise RuntimeError('No current API container; refusing a deployment without rollback')
    previous = subprocess.check_output(
        ['docker', 'inspect', '--format', '{{.Image}}', container], text=True,
    ).strip()
    subprocess.run(['docker', 'load', '--input', str(archive)], check=True, stdout=subprocess.PIPE)
    # Ensure the archive supplied precisely the expected image before switching.
    subprocess.run(['docker', 'image', 'inspect', image], check=True, stdout=subprocess.DEVNULL)
    try:
        compose(config, image, 'up', '-d', '--no-build', candidate=True)
        health('http://127.0.0.1:18000/api/health')
    finally:
        compose(config, image, 'down', candidate=True)
    try:
        compose(config, image, 'up', '-d', '--no-build', 'api')
        health('http://127.0.0.1:8000/api/health')
        health('http://127.0.0.1/api/health')
    except Exception:
        compose(config, previous, 'up', '-d', '--no-build', 'api')
        health('http://127.0.0.1:8000/openapi.json')
        raise
    Path(config['root'], 'previous-image').write_text(previous + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--check', action='store_true', help='Read-only: report release readiness')
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    root = Path(config['root'])
    root.mkdir(parents=True, exist_ok=True)
    with (root / '.deploy.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.rollback:
            if config['kind'] == 'site':
                previous = (root / 'previous').resolve(strict=True)
                switch_link(root / 'current', previous)
                health(config['health_url'])
            else:
                previous = (root / 'previous-image').read_text().strip()
                compose(config, previous, 'up', '-d', '--no-build', 'api')
                health('http://127.0.0.1:8000/openapi.json')
            (root / 'deployed-sha').unlink(missing_ok=True)
            print('Rolled back. Keep the timer stopped until ready to deploy again.')
            return
        repo = config['repo']
        sha = api(repo, 'git/ref/heads/main')['object']['sha']
        if not re.fullmatch(r'[0-9a-f]{40}', sha):
            raise ValueError('Invalid main commit')
        state = root / 'deployed-sha'
        if state.exists() and state.read_text().strip() == sha:
            print(f'Already deployed {sha}')
            return
        try:
            release = api(repo, f'releases/tags/deploy-{sha}')
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
            print(f'No tested release for main {sha}; leaving live version unchanged')
            return
        if release['draft']:
            print('Release is still being uploaded')
            return
        runs = api(repo, f'actions/workflows/ci-deploy.yml/runs?head_sha={sha}&per_page=10')['workflow_runs']
        if not any(run['head_branch'] == 'main' and run['event'] in ('push', 'workflow_dispatch')
                   and run['conclusion'] == 'success' and run['status'] == 'completed' for run in runs):
            print('Waiting for a completed successful workflow')
            return
        name = 'website.tar.gz' if config['kind'] == 'site' else 'api-image.tar.gz'
        assets = {asset['name']: asset['browser_download_url'] for asset in release['assets']}
        if name not in assets or name + '.sha256' not in assets:
            raise ValueError('Release is incomplete')
        for asset_name in (name, name + '.sha256'):
            prefix = f'https://github.com/{repo}/releases/download/deploy-{sha}/'
            if not assets[asset_name].startswith(prefix):
                raise ValueError('Unexpected download location')
        if args.check:
            print(f'Tested release ready: {repo}@{sha}')
            return
        with tempfile.TemporaryDirectory(prefix='.download-', dir=root) as temporary:
            archive = Path(temporary) / name
            expected = fetch(assets[name + '.sha256'], limit=1024).decode().split()[0]
            if not re.fullmatch(r'[0-9a-f]{64}', expected):
                raise ValueError('Invalid checksum')
            actual = download(assets[name], archive, 1024 * 1024 * 1024)
            if actual != expected:
                raise ValueError('Release checksum mismatch')
            # A newer merge may have arrived during download; skip stale builds.
            if api(repo, 'git/ref/heads/main')['object']['sha'] != sha:
                print('Main changed during download; waiting for the new build')
                return
            if config['kind'] == 'site':
                deploy_site(config, archive, sha)
            else:
                deploy_api(config, archive, sha)
        temporary_state = root / 'deployed-sha.next'
        temporary_state.write_text(sha + '\n')
        temporary_state.replace(state)
        print(f'Deployed {repo}@{sha}', flush=True)


if __name__ == '__main__':
    main()
