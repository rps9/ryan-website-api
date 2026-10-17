# API CI and deployment to the home server

PRs compile Python, run deployment safety tests, test authentication/roles/CORS
against disposable PostgreSQL 16, and build and smoke test the production Docker
image. Tests do not send email or contact Spotify/OpenAI. Successful builds on
`main` publish the exact tested image as `api-image.tar.gz` and its SHA-256
checksum in a prerelease tagged `deploy-<commit SHA>`. This avoids registry
credentials: downloads are public, like the repository. `.dockerignore` excludes
all `.env` files, Git metadata, tests, and development environments from images.

## Activation

```sh
sudo bash /opt/ryan-website-api/deploy/install.sh
```

The installer requires the current Compose-managed API to be running and the
existing `.env.prod` file to be present. It discovers the current Compose project
name, installs root-owned deployment code and Compose configuration, and enables
a five-minute polling timer. It leaves the existing container running until a
tested release exists. It uses the original production env file, which remains
on this computer and is never uploaded. The Docker daemon requires root access
for the deployment service; no Docker permission is granted to a GitHub runner.

Review and push the repository changes when ready. GitHub must allow Actions and
the requested `contents: write` permission. A merge into `main` publishes a
release only after the checks pass. No additional GitHub secrets are required.
The timer verifies the current main SHA, completed successful workflow, release
assets, and checksum before loading the image.

In GitHub Settings > Rules > Rulesets, protect `main`, require pull requests, and
require the `API checks` status check after it has run once. Direct pushes to
`main` also deploy unless blocked by the ruleset. These GitHub settings require
separate account access and are not configured by repository files.

## Deployment behavior

A candidate container runs on loopback port 18000 using the production env and
the same restrictions as the live API. `/api/health` checks database connectivity
without exposing credentials or error details. After the candidate passes, the
live Compose service switches to the tested image on port 8000. This recreation
causes a brief API interruption. Checks verify readiness directly and through
Nginx; failures recreate the previous image. The database is external and never
recreated or migrated by deployment. Schema migrations need a separate plan.

The current source checkout is not pulled or rebuilt. Installed deployment code
and units only update when the installer is rerun. Downloads and temporary
candidate containers are cleaned up; old Docker images remain for rollback.
Monitor disk usage and avoid deleting an image needed for rollback.

```sh
systemctl status rps9-api-deploy.timer
journalctl -u rps9-api-deploy.service -n 50
sudo systemctl start rps9-api-deploy.service
```

Manual rollback:

```sh
sudo systemctl stop rps9-api-deploy.timer rps9-api-deploy.service
sudo python3 /usr/local/lib/rps9-api-deploy/deploy.py \
  --config /etc/rps9-api-deploy/config.json --rollback
```

Fix or revert the change through a PR before restarting the timer. For local
integration tests, use a disposable database named `website_test` and set the CI
environment variables shown in `.github/workflows/ci-deploy.yml`; then run:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
RUN_DB_TESTS=1 .venv/bin/pytest -q tests/test_api.py
python3 -m unittest discover -s tests/deploy -v
```
