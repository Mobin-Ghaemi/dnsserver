#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${1:-}" == '--host' ]]; then
  exec "$(dirname "${BASH_SOURCE[0]}")/update-host.sh"
fi
umask 077
cd "$(dirname "${BASH_SOURCE[0]}")/.."
command -v flock >/dev/null || { echo 'flock is required (util-linux).' >&2; exit 1; }
exec 9> .git/orbit-update.lock
flock -n 9 || { echo 'An update is already running.' >&2; exit 1; }
[[ -f .env ]] || { echo 'Run deploy/install.sh first.' >&2; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || { echo 'Commit or stash local source changes before updating.' >&2; exit 1; }
git rev-parse --abbrev-ref '@{upstream}' >/dev/null
if ! GIT_TERMINAL_PROMPT=0 git fetch origin; then
  echo 'اتصال به GitHub برقرار نشد. کلید دسترسی مخزن را تنظیم کنید؛ آپدیت اجرا نشد.' >&2
  exit 1
fi
if ! git merge-base --is-ancestor HEAD '@{upstream}'; then
  echo 'کامیت‌های محلی هنوز روی upstream نیستند؛ ابتدا git push انجام دهید. کد محلی حفظ شد.' >&2
  exit 1
fi
previous=$(git rev-parse HEAD)
mkdir -p backups
backup="backups/$(date -u +%Y%m%dT%H%M%SZ)-$previous"
mkdir "$backup"
printf '%s\n' "$previous" > "$backup/commit"
cp .env "$backup/env"
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > "$backup/panel.sql"
[[ -s "$backup/panel.sql" ]] || { echo 'Empty backup; update aborted.' >&2; exit 1; }
trap 'echo "Update failed. Backup: $backup. Previous commit: $previous. Check logs; migrations may require database restoration before rollback." >&2' ERR
git merge --ff-only '@{upstream}'
docker compose config --quiet
docker compose build web
docker compose up -d --wait --wait-timeout 180
docker compose exec -T web python manage.py check --deploy --fail-level ERROR
printf 'Update complete. Panel backup: %s\n' "$backup"
