import ipaddress
from django.conf import settings
from django.utils.cache import patch_cache_control


def client_ip(request):
    # Enable TRUST_PROXY only when the app is unreachable except via the trusted
    # proxy, which MUST overwrite X-Real-IP (see deploy/nginx.conf).
    candidate = request.META.get('HTTP_X_REAL_IP') if settings.TRUST_PROXY else None
    candidate = candidate or request.META.get('REMOTE_ADDR', '')
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


class PrivatePagesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        if request.path != '/healthz/':
            patch_cache_control(response, no_store=True, private=True)
        return response
