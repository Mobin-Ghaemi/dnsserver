#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v docker >/dev/null || { echo 'Install Docker Engine and the Compose plugin first.' >&2; exit 1; }
docker compose version >/dev/null
if [[ ! -f .env ]]; then
  cp .env.example .env
  chmod 600 .env
  echo 'Created .env. Set production hosts, HTTPS, secrets, PostgreSQL password and PowerDNS API; then run this command again.'
  exit 1
fi
# Validate production configuration before creating containers.
docker compose config --quiet
docker compose build web
docker compose run --rm --no-deps --entrypoint python web -c 'import os; os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings"); import django; django.setup(); from django.conf import settings; assert not settings.DEBUG, "Set DJANGO_DEBUG=False"; assert len(settings.SECRET_KEY) >= 50, "Set a random secret of at least 50 characters"'
docker compose up -d --wait --wait-timeout 180
docker compose exec -T web python manage.py check --deploy --fail-level ERROR
echo 'Installed. Configure Nginx/TLS using deploy/nginx.conf, then create an administrator:'
echo 'docker compose exec web python manage.py createsuperuser'
