import os
from datetime import timedelta
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / '.env')


def flag(name, default=False):
    return os.getenv(name, str(default)).lower() in {'1', 'true', 'yes'}


DEBUG = flag('DJANGO_DEBUG', True)
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', '')
if not SECRET_KEY:
    if not DEBUG:
        raise ImproperlyConfigured('DJANGO_SECRET_KEY must be set in production.')
    SECRET_KEY = 'development-only-orbit-dns-do-not-use-in-production'
ALLOWED_HOSTS = [v.strip() for v in os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1,[::1]').split(',') if v.strip()]
CSRF_TRUSTED_ORIGINS = [v.strip() for v in os.getenv('DJANGO_CSRF_TRUSTED_ORIGINS', '').split(',') if v.strip()]
INSTALLED_APPS = [
    'django.contrib.admin', 'django.contrib.auth', 'django.contrib.contenttypes',
    'django.contrib.sessions', 'django.contrib.messages', 'django.contrib.staticfiles',
    'axes', 'dnsmanager',
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware', 'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware', 'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware', 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware', 'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware', 'axes.middleware.AxesMiddleware',
    'dnsmanager.security.PrivatePagesMiddleware',
]
ROOT_URLCONF = 'config.urls'
TEMPLATES = [{'BACKEND': 'django.template.backends.django.DjangoTemplates', 'DIRS': [BASE_DIR / 'templates'],
              'APP_DIRS': True, 'OPTIONS': {'context_processors': [
                  'django.template.context_processors.request', 'django.contrib.auth.context_processors.auth',
                  'django.contrib.messages.context_processors.messages', 'dnsmanager.context.navigation',
              ]}}]
WSGI_APPLICATION = 'config.wsgi.application'
if os.getenv('POSTGRES_HOST'):
    DATABASES = {'default': {
        'ENGINE': 'django.db.backends.postgresql', 'HOST': os.environ['POSTGRES_HOST'],
        'NAME': os.getenv('POSTGRES_DB', 'orbit'), 'USER': os.getenv('POSTGRES_USER', 'orbit'),
        'PASSWORD': os.environ['POSTGRES_PASSWORD'], 'PORT': os.getenv('POSTGRES_PORT', '5432'),
        'CONN_MAX_AGE': 60,
    }}
else:
    (BASE_DIR / 'data').mkdir(exist_ok=True)
    DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': BASE_DIR / 'data/db.sqlite3', 'OPTIONS': {'timeout': 20}}}
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]
AUTHENTICATION_BACKENDS = ['axes.backends.AxesStandaloneBackend', 'django.contrib.auth.backends.ModelBackend']
AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=15)
AXES_LOCKOUT_PARAMETERS = ['username', 'ip_address']
AXES_RESET_ON_SUCCESS = True
AXES_CLIENT_IP_CALLABLE = 'dnsmanager.security.client_ip'
AXES_LOCKOUT_TEMPLATE = 'registration/locked.html'
AXES_ENABLE_ADMIN = True
LANGUAGE_CODE = 'fa'
LANGUAGES = [('fa', 'فارسی')]
TIME_ZONE = 'Asia/Tehran'
USE_I18N = True
USE_TZ = True
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STORAGES = {'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
            'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'}}
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'login'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_AGE = 28800
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_SSL_REDIRECT = flag('DJANGO_SECURE_SSL_REDIRECT', not DEBUG)
SECURE_REDIRECT_EXEMPT = [r'^healthz/$']
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = 2592000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = flag('DJANGO_HSTS_INCLUDE_SUBDOMAINS')
SECURE_HSTS_PRELOAD = flag('DJANGO_HSTS_PRELOAD')
# Only enable behind a trusted proxy which overwrites X-Forwarded-Proto.
TRUST_PROXY = flag('DJANGO_TRUST_PROXY')
if TRUST_PROXY:
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
DATA_UPLOAD_MAX_MEMORY_SIZE = 1024 * 1024
PDNS_API_URL = os.getenv('PDNS_API_URL', '').rstrip('/')
PDNS_API_KEY = os.getenv('PDNS_API_KEY', '')
PDNS_CONFIG_FILE = os.getenv('PDNS_CONFIG_FILE', '')
PDNS_LOCAL_CONFIG = False
if not PDNS_API_KEY and not PDNS_API_URL:
    from .local_dns import local_powerdns_config
    local_config = local_powerdns_config(PDNS_CONFIG_FILE)
    PDNS_API_URL = local_config.get('url', '')
    PDNS_API_KEY = local_config.get('key', '')
    PDNS_LOCAL_CONFIG = bool(local_config)
elif PDNS_API_KEY and not PDNS_API_URL:
    PDNS_API_URL = 'http://127.0.0.1:8081/api/v1'
PDNS_SERVER_ID = os.getenv('PDNS_SERVER_ID', 'localhost')
DNS_NAMESERVERS = [s.strip().rstrip('.').lower() + '.' for s in os.getenv('DNS_NAMESERVERS', 'ns1.melkata.ir,ns2.melkata.ir,ns1.ezfile.ir,ns2.ezfile.ir').split(',') if s.strip()]
PDNS_TIMEOUT = 10
DNS_AUTO_DISCOVERY = flag('DNS_AUTO_DISCOVERY', True)
DNS_DISCOVERY_OWNER = os.getenv('DNS_DISCOVERY_OWNER', '')
DNS_DISCOVERY_INTERVAL = 60
