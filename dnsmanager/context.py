from django.conf import settings


def navigation(request):
    section = request.resolver_match.url_name if request.resolver_match else ''
    staff = request.user.is_authenticated and request.user.is_staff
    configured = bool(settings.PDNS_API_URL and settings.PDNS_API_KEY)
    nameservers = settings.DNS_NAMESERVERS
    if request.user.is_authenticated and configured:
        from .configuration import default_nameservers
        nameservers = default_nameservers()
    return {'pdns_configured': configured, 'nameservers': nameservers,
            'nav_section': section, 'auto_discovery': settings.DNS_AUTO_DISCOVERY,
            'show_discovery': staff and section in ('dashboard', 'zones', 'zone_detail', 'connection'),
            'pdns_local_config': settings.PDNS_LOCAL_CONFIG}
