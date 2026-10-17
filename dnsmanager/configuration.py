from django.conf import settings


def default_nameservers():
    configured = settings.DNS_NAMESERVERS
    if configured and not any(ns in ('ns1.example.net.', 'ns2.example.net.') for ns in configured):
        return configured
    # Infer a default only if all discovered zones on this endpoint agree.
    # Different per-zone NS sets require an explicit operator choice.
    from .models import Zone
    from .powerdns import provider_identity
    sets = set()
    for values in Zone.objects.filter(source='server', provider_identity=provider_identity()).values_list('detected_nameservers', flat=True):
        normalized = tuple(sorted(set(values)))
        if normalized:
            sets.add(normalized)
        if len(sets) > 1:
            return configured
    if len(sets) == 1 and len(next(iter(sets))) >= 2:
        return list(next(iter(sets)))
    return configured
