import ipaddress
import re

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
from dns.rdtypes.ANY.TXT import TXT
from django.core.exceptions import ValidationError

RECORD_TYPES = ('A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR')


def hostname(value):
    value = value.strip().rstrip('.').lower()
    try:
        value = value.encode('idna').decode('ascii')
    except UnicodeError:
        raise ValidationError('نام دامنه معتبر نیست.')
    if len(value) > 253 or not value or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in value.split('.')):
        raise ValidationError('نام دامنه معتبر نیست؛ مانند example.com وارد کنید.')
    return value


def zone_name(value):
    result = hostname(value)
    if '.' not in result:
        raise ValidationError('نام دامنه باید حداقل دو بخش داشته باشد.')
    return result


def record_name(value, zone):
    value = value.strip().lower()
    if value in ('', '@', zone, zone + '.'):
        return '@'
    if value.endswith('.'):
        if not value.endswith('.' + zone + '.'):
            raise ValidationError('نام رکورد باید زیرمجموعهٔ همین دامنه باشد.')
        value = value[:-(len(zone) + 2)]
    elif value.endswith('.' + zone):
        value = value[:-(len(zone) + 1)]
    labels = value.split('.')
    if len(value + '.' + zone) > 253 or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?|\*', label) for label in labels):
        raise ValidationError('نام رکورد معتبر نیست؛ از @، www یا _service._tcp استفاده کنید.')
    if '*' in labels[1:]:
        raise ValidationError('ستاره فقط در ابتدای نام مجاز است.')
    return value


def target(value):
    if value.strip() == '.':
        return '.'
    return hostname(value) + '.'


def canonical_content(kind, value, priority=None, weight=None, port=None):
    value = value.strip() if kind != 'TXT' else value
    try:
        if kind == 'A':
            return str(ipaddress.IPv4Address(value))
        if kind == 'AAAA':
            return str(ipaddress.IPv6Address(value))
        if kind in ('CNAME', 'NS', 'PTR'):
            if value == '.':
                raise ValueError()
            return target(value)
        if kind == 'MX':
            if priority is None:
                raise ValidationError('اولویت MX را وارد کنید.')
            if value == '.' and priority != 0:
                raise ValidationError('Null MX باید اولویت صفر داشته باشد.')
            return f'{priority} {target(value)}'
        if kind == 'SRV':
            if any(v is None for v in (priority, weight, port)):
                raise ValidationError('اولویت، وزن و پورت SRV الزامی است.')
            return f'{priority} {weight} {port} {target(value)}'
        if kind == 'TXT':
            raw = value.encode('utf-8')
            if not raw or len(raw) > 4096:
                raise ValidationError('متن TXT باید بین ۱ تا ۴۰۹۶ بایت باشد.')
            return TXT(dns.rdataclass.IN, dns.rdatatype.TXT, [raw[i:i+255] for i in range(0, len(raw), 255)]).to_text()
        if kind == 'CAA':
            return dns.rdata.from_text('IN', 'CAA', value).to_text()
    except ValidationError:
        raise
    except (ValueError, dns.exception.DNSException, UnicodeError):
        raise ValidationError(f'مقدار رکورد {kind} معتبر نیست.')
    raise ValidationError('نوع رکورد پشتیبانی نمی‌شود.')
