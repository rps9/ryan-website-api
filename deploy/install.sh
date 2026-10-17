#!/usr/bin/env bash
set -euo pipefail
if [[ ${EUID} -ne 0 ]]; then
  echo "Run: sudo bash $0" >&2
  exit 1
fi
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
source_dir=$(cd -- "$script_dir/.." && pwd)
docker compose version >/dev/null
test -s "$source_dir/.env.prod"
docker compose -f "$source_dir/docker-compose.yml" config --quiet
container=$(docker compose -f "$source_dir/docker-compose.yml" ps -q api)
test -n "$container" || { echo 'Current API container not found; refusing setup.' >&2; exit 1; }
project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container")
install -d -m 0700 /etc/rps9-api-deploy /var/lib/rps9-api-deploy
install -d -m 0755 /usr/local/lib/rps9-api-deploy
install -m 0644 "$script_dir/deploy.py" /usr/local/lib/rps9-api-deploy/deploy.py
# Compose receives the original local env file; secrets never enter GitHub releases.
python3 - "$source_dir" "$project" <<'PY'
import json
from pathlib import Path
import sys
source, project = sys.argv[1:]
service = {
    'image': '${API_IMAGE:?API_IMAGE is required}',
    'env_file': [source + '/.env.prod'],
    'ports': ['127.0.0.1:8000:8000'],
    'command': ['uvicorn', 'app:app', '--host', '0.0.0.0', '--port', '8000'],
    'restart': 'unless-stopped', 'init': True, 'read_only': True,
    'tmpfs': ['/tmp:size=64m,mode=1777'], 'cap_drop': ['ALL'],
    'security_opt': ['no-new-privileges:true'], 'pids_limit': 256,
    'mem_limit': '768m',
}
compose = Path('/etc/rps9-api-deploy/compose.json')
candidate = compose.with_name('candidate.json')
compose.write_text(json.dumps({'services': {'api': service}}, indent=2) + '\n')
service['ports'] = ['127.0.0.1:18000:8000']
service['restart'] = 'no'
candidate.write_text(json.dumps({'services': {'api': service}}, indent=2) + '\n')
config = {
    'kind': 'api', 'repo': 'rps9/ryan-website-api',
    'root': '/var/lib/rps9-api-deploy', 'project': project,
    'compose': str(compose), 'candidate_compose': str(candidate),
}
Path('/etc/rps9-api-deploy/config.json').write_text(json.dumps(config, indent=2) + '\n')
PY
install -m 0644 "$script_dir/rps9-api-deploy.service" /etc/systemd/system/
install -m 0644 "$script_dir/rps9-api-deploy.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rps9-api-deploy.timer
echo 'API deployment timer installed. Existing API stays running until a tested release is available.'
