#!/usr/bin/env bash
# For the native BIND-connected installation on this host.
set -Eeuo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
exec 9> .git/orbit-update.lock
flock -n 9 || { echo 'An update is running.' >&2; exit 1; }
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || { echo 'Commit or stash source changes first.' >&2; exit 1; }
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
backup="/srv/dns/snapshots/orbit-update-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 700 "$backup"
docker exec orbit-dns-db pg_dump -U orbit orbit > "$backup/panel.sql"
cp -a /opt/orbit-dns/.env "$backup/panel.env"
cp -a /etc/bind "$backup/bind"
cp -a /var/lib/orbit-bind "$backup/bridge"
printf '%s\n' "$previous" > "$backup/commit"
trap 'echo "Update failed; inspect services. Backup: $backup; old source: $previous. Database rollback requires a matching restore." >&2' ERR
git merge --ff-only '@{upstream}'
rsync -a --exclude='/.git/' --exclude='/.venv/' --exclude='/.env' --exclude='/data/' --exclude='/backups/' --exclude='/staticfiles/' ./ /opt/orbit-dns/
cd /opt/orbit-dns
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python manage.py migrate --noinput
.venv/bin/python manage.py collectstatic --noinput
.venv/bin/python manage.py check --deploy --fail-level ERROR
systemctl restart orbit-bind-bridge orbit-dns
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:18009/healthz/ >/dev/null
curl --fail --silent --show-error https://62.60.211.103/login/ >/dev/null
echo "Update complete. Backup: $backup"
