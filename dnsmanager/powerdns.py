from collections import defaultdict
import hashlib
import json
import dns.exception
import dns.rdata
from urllib.parse import quote, urlsplit

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from .dns import RECORD_TYPES, hostname


class ProviderError(Exception):
    pass


class PowerDNS:
    """Server-side only. API credentials never reach browser code or error messages."""

    def __init__(self):
        url = urlsplit(settings.PDNS_API_URL)
        if not settings.PDNS_API_KEY or url.scheme not in ('http', 'https') or not url.netloc or url.query or url.fragment or url.username:
            raise ProviderError('اتصال PowerDNS تنظیم نشده است. متغیرهای سرور را مطابق README تنظیم کنید.')
        self.base = settings.PDNS_API_URL + '/servers/' + quote(settings.PDNS_SERVER_ID, safe='')
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({'X-API-Key': settings.PDNS_API_KEY, 'Accept': 'application/json'})

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def request(self, method, path='', *, payload=None, allow_missing=False, expect_list=False):
        try:
            response = self.session.request(method, self.base + path, json=payload,
                                            timeout=(3, settings.PDNS_TIMEOUT), allow_redirects=False)
            if allow_missing and response.status_code == 404:
                return None
            if not 200 <= response.status_code < 300:
                raise ProviderError(f'PowerDNS درخواست را نپذیرفت (HTTP {response.status_code}). تنظیمات و لاگ سرویس DNS را بررسی کنید.')
            data = response.json() if response.content else {}
            if not isinstance(data, list if expect_list else dict):
                raise ProviderError('ساختار پاسخ PowerDNS معتبر نیست.')
            return data
        except (requests.RequestException, ValueError):
            raise ProviderError('ارتباط با PowerDNS برقرار نشد یا پاسخ معتبر نبود. شبکه، آدرس API و کلید دسترسی را بررسی کنید.') from None

    def health(self):
        self.request('GET')

    @property
    def identity(self):
        return provider_identity()

    def list_zones(self):
        zones = self.request('GET', '/zones', expect_list=True)
        if any(not isinstance(zone, dict) or not isinstance(zone.get('name'), str) for zone in zones):
            raise ProviderError('فهرست دامنه‌های PowerDNS معتبر نیست.')
        return zones

    def read_zone(self, name):
        return self.request('GET', '/zones/' + quote(name.rstrip('.') + '.', safe=''), allow_missing=True)

    def path(self, zone):
        return '/zones/' + quote(zone.name + '.', safe='')

    def owned_zone(self, zone):
        remote = self.read_zone(zone.name)
        imported = zone.source == 'server' and zone.provider_identity == self.identity
        expected_account = zone.remote_account if imported else f'orbit-{zone.external_id}'
        if zone.source == 'server' and not imported:
            raise ProviderError('سرور DNS این دامنه تغییر کرده است؛ اتصال را بررسی کنید.')
        if remote is not None and remote.get('account', '') != expected_account:
            raise ProviderError('این دامنه در PowerDNS وجود دارد اما متعلق به این پنل نیست. برای جلوگیری از بازنویسی، انتشار متوقف شد؛ راهنمای انتقال در README را ببینید.')
        if remote is not None:
            rrsets = remote.get('rrsets', [])
            if not isinstance(rrsets, list) or any(not isinstance(row, dict) or not isinstance(row.get('name'), str) or not isinstance(row.get('type'), str) for row in rrsets):
                raise ProviderError('ساختار رکوردهای دریافتی از PowerDNS معتبر نیست.')
        return remote

    def check_snapshot(self, zone, remote):
        if remote is not None and zone.remote_snapshot and zone.remote_snapshot != rrset_fingerprint(remote.get('rrsets', [])):
            raise ProviderError('رکوردهای سرور خارج از پنل تغییر کرده‌اند. ابتدا همگام‌سازی را بررسی کنید؛ تغییرات سرور بازنویسی نشدند.')

    def ensure_zone(self, zone):
        remote = self.owned_zone(zone)
        if remote is None:
            if zone.source == 'server':
                raise ProviderError('این دامنه دیگر روی سرور وجود ندارد؛ برای بازسازی آن ابتدا وضعیت سرور را بررسی کنید.')
            self.request('POST', '/zones', payload={
                'name': zone.name + '.', 'kind': 'Native', 'nameservers': checked_nameservers(zone.nameservers),
                'account': f'orbit-{zone.external_id}', 'soa_edit_api': 'INCREASE',
            })
            remote = self.owned_zone(zone)
            if remote is None:
                raise ProviderError('ساخت دامنه در PowerDNS تأیید نشد. دوباره تلاش کنید.')
        # An ownership marker also makes retry after an interrupted create safe.
        type(zone).objects.filter(pk=zone.pk).update(provisioned=True)
        return remote

    def publish(self, zone, records):
        nameservers = checked_nameservers(zone.nameservers) if zone.source == 'local' else []
        remote = self.ensure_zone(zone)
        self.check_snapshot(zone, remote)
        if zone.is_readonly or remote.get('kind', '').lower() in ('slave', 'secondary', 'consumer'):
            raise ProviderError('رکوردهای این دامنهٔ ثانویه باید روی سرور اصلی ویرایش شوند.')
        grouped = defaultdict(list)
        ttls = {}
        for record in records:
            key = (record.fqdn, record.type)
            ttls[key] = record.ttl
            grouped[key].append({'content': record.dns_content, 'disabled': not record.enabled})
        apex_ns = (zone.name + '.', 'NS')
        if zone.source == 'local':
            grouped[apex_ns] = [{'content': ns, 'disabled': False} for ns in nameservers]
            ttls[apex_ns] = zone.default_ttl
        rrsets = [{'name': name, 'type': kind, 'ttl': ttls[(name, kind)], 'changetype': 'REPLACE', 'records': values}
                  for (name, kind), values in grouped.items()]
        for rrset in remote.get('rrsets', []):
            key = (rrset['name'], rrset['type'])
            if rrset['type'] in RECORD_TYPES and key not in grouped and not (zone.source == 'server' and key == apex_ns):
                rrsets.append({'name': key[0], 'type': key[1], 'changetype': 'DELETE'})
        self.request('PATCH', self.path(zone), payload={'rrsets': rrsets})
        retained = [row for row in remote.get('rrsets', []) if row['type'] not in RECORD_TYPES or (zone.source == 'server' and (row['name'], row['type']) == apex_ns)]
        return rrset_fingerprint(retained + [row for row in rrsets if row['changetype'] == 'REPLACE'])

    def delete(self, zone):
        remote = self.owned_zone(zone)
        self.check_snapshot(zone, remote)
        if remote is not None:
            self.request('DELETE', self.path(zone))


def rrset_fingerprint(rrsets):
    rows = []
    for rrset in rrsets:
        if rrset.get('type') == 'SOA':
            continue
        records = []
        for row in rrset.get('records', []):
            content = str(row.get('content', ''))
            try:
                content = dns.rdata.from_text('IN', rrset['type'], content).to_digestable().hex()
            except (dns.exception.DNSException, ValueError):
                pass
            records.append((content, bool(row.get('disabled', False))))
        records.sort()
        rows.append((rrset['name'].lower(), rrset['type'], rrset.get('ttl', 0), records))
    rows.sort()
    return hashlib.sha256(json.dumps(rows, ensure_ascii=True).encode()).hexdigest()


def provider_identity():
    base = settings.PDNS_API_URL + '/servers/' + quote(settings.PDNS_SERVER_ID, safe='')
    return hashlib.sha256(base.encode()).hexdigest()


def checked_nameservers(values=None):
    from .configuration import default_nameservers
    try:
        names = list(dict.fromkeys(hostname(ns) + '.' for ns in (values if values is not None else default_nameservers())))
    except ValidationError:
        raise ProviderError('DNS_NAMESERVERS معتبر نیست.') from None
    if len(names) < 2 or any(ns.endswith('.example.net.') or ns.endswith('.example.com.') for ns in names):
        raise ProviderError('حداقل دو نام‌سرور واقعی و متفاوت را در DNS_NAMESERVERS تنظیم کنید.')
    return names
