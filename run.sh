#!/bin/sh
# Local development launcher; always use this project's Python environment.
set -eu
DNS_PROJECT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
cd "$DNS_PROJECT_DIR"

if [ ! -x .venv/bin/python ]; then
    python3 -m venv .venv
fi

if ! .venv/bin/python -c 'import django, axes, dotenv, dns, requests, whitenoise, gunicorn, psycopg' >/dev/null 2>&1; then
    .venv/bin/python -m pip install -r requirements.txt
fi

.venv/bin/python manage.py migrate --noinput
if [ "$#" -eq 0 ]; then
    set -- 127.0.0.1:8000
fi
exec .venv/bin/python manage.py runserver "$@"
