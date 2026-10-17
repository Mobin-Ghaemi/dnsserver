"""Bounded public NS lookups; never HTTP-fetches the entered domain."""
from concurrent.futures import ThreadPoolExecutor
import hashlib

import dns.exception
import dns.resolver
from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.utils import timezone

from .dns import hostname, zone_name


LABELS = {'matched': 'NSها مطابق‌اند', 'mismatch': 'NSها متفاوت‌اند', 'propagating': 'پاسخ‌ها یکسان نیستند',
          'unavailable': 'بررسی کامل نشد', 'not_found': 'دامنه پیدا نشد', 'unconfigured': 'NSهای مقصد تنظیم نشده‌اند'}


def expected_groups():
    raw_groups = [settings.DNS_CHECK_NAMESERVERS] if settings.DNS_CHECK_NAMESERVERS else settings.DNS_CHECK_NS_GROUPS
    groups = [sorted({hostname(value) + '.' for value in group}) for group in raw_groups]
    if not groups or any(len(group) < 2 or any(value in ('ns1.example.net.', 'ns2.example.net.') for value in group) for group in groups):
        raise ValidationError('جفت نام‌سرورهای معتبر را در DNS_CHECK_NS_GROUPS تنظیم کنید.')
    return groups


def expected_nameservers():
    return sorted({name for group in expected_groups() for name in group})


def query_nameservers(name, address):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [address]
    resolver.timeout = 2
    resolver.lifetime = 5
    try:
        answer = resolver.resolve(name + '.', 'NS', search=False, lifetime=5)
        # CNAME to a different domain must never count as a delegation match.
        if str(answer.canonical_name).rstrip('.').lower() != name:
            return {'resolver': address, 'status': 'alias', 'nameservers': []}
        return {'resolver': address, 'status': 'ok', 'nameservers': sorted({str(row.target).lower() for row in answer})}
    except dns.resolver.NXDOMAIN:
        return {'resolver': address, 'status': 'not_found', 'nameservers': []}
    except dns.resolver.NoAnswer:
        return {'resolver': address, 'status': 'no_ns', 'nameservers': []}
    except (dns.exception.DNSException, OSError):
        return {'resolver': address, 'status': 'unavailable', 'nameservers': []}


def check_domain(name):
    name = zone_name(name)
    groups = expected_groups()
    expected = sorted({value for group in groups for value in group})
    cache_key = 'ns-check:' + hashlib.sha256((name + ':' + str(groups)).encode()).hexdigest()
    cached = cache.get(cache_key)
    if cached:
        return dict(cached, cached=True)
    with ThreadPoolExecutor(max_workers=2) as executor:
        answers = list(executor.map(lambda address: query_nameservers(name, address), settings.DNS_CHECK_RESOLVERS))
    good = [row for row in answers if row['status'] == 'ok']
    if len(good) == 2:
        if good[0]['nameservers'] != good[1]['nameservers']:
            status = 'propagating'
        else:
            found_set = set(good[0]['nameservers'])
            status = 'matched' if found_set <= set(expected) and any(set(group) <= found_set for group in groups) else 'mismatch'
    elif all(row['status'] == 'not_found' for row in answers):
        status = 'not_found'
    else:
        status = 'unavailable'
    found = sorted({value for row in good for value in row['nameservers']})
    result = {'domain': name, 'expected': expected, 'expected_groups': groups, 'found': found, 'answers': answers, 'status': status,
              'label': LABELS[status], 'checked_at': timezone.now().isoformat(), 'cached': False}
    cache.set(cache_key, result, 60)
    return result
