"""Read-only cached NS checks. These do not prove ownership or enumerate zones."""
import dns.exception
import dns.resolver
from django.conf import settings
from django.core.cache import cache
from .dns import zone_name


def check_nameservers(name):
    name = zone_name(name)
    key = 'public-ns:' + name
    cached = cache.get(key)
    if cached is not None:
        return cached
    allowed = {ns.lower().rstrip('.') for ns in settings.DNS_NAMESERVERS}
    observations = []
    for address in ('1.1.1.1', '8.8.8.8'):
        row = {'resolver': address, 'nameservers': [], 'state': 'unknown', 'error': ''}
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [address]
        resolver.timeout = 2
        try:
            answer = resolver.resolve(name + '.', 'NS', lifetime=3, search=False)
            if answer.rrset is None or answer.rrset.name.to_text().lower() != name + '.':
                row['error'] = 'پاسخ متعلق به خود این دامنه نیست.'
            else:
                found = {r.target.to_text().lower().rstrip('.') for r in answer}
                row['nameservers'] = sorted(found)
                row['state'] = 'matched' if len(found) >= 2 and found <= allowed else 'mismatch'
        except dns.resolver.NXDOMAIN:
            row['error'] = 'دامنه در DNS پیدا نشد.'
        except dns.resolver.NoAnswer:
            row['error'] = 'رکورد NS برای این نام وجود ندارد.'
        except dns.exception.DNSException:
            row['error'] = 'پاسخ DNS دریافت نشد؛ دوباره بررسی کنید.'
        observations.append(row)
    first, second = observations
    matched = (first['state'] == second['state'] == 'matched'
               and first['nameservers'] == second['nameservers'])
    result = {'name': name, 'observations': observations, 'matched': matched}
    cache.set(key, result, 60)
    return result
