"""Read existing authoritative zones. Discovery never writes to PowerDNS."""
import time
import uuid
from datetime import timedelta

import dns.rdata
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, PermissionDenied
from django.db import transaction, IntegrityError
from django.db.models import Q
from django.utils import timezone

from .dns import RECORD_TYPES, zone_name, record_name, hostname
from .models import Zone, Record, DiscoveryState
from .powerdns import PowerDNS, ProviderError, rrset_fingerprint
from .services import audit, ZoneBusy, acquire


def discovery_owner(actor):
    if not actor or not actor.is_active or not actor.is_staff:
        raise PermissionDenied('شناسایی دامنه‌های سرور فقط برای مدیر سامانه مجاز است.')
    if not settings.DNS_DISCOVERY_OWNER:
        return actor
    try:
        return get_user_model().objects.get(username=settings.DNS_DISCOVERY_OWNER, is_active=True, is_staff=True)
    except get_user_model().DoesNotExist:
        raise ProviderError('کاربر مدیر تعیین‌شده در DNS_DISCOVERY_OWNER پیدا نشد.') from None


def parse_zone(remote):
    """Validate the complete supported portion before replacing local records."""
    name = zone_name(remote.get('name', ''))
    rrsets = remote.get('rrsets')
    if not isinstance(rrsets, list):
        raise ProviderError('پاسخ سرور باید همهٔ رکوردهای دامنه را شامل شود.')
    records, nameservers, unmanaged = [], [], []
    default_ttl = 3600
    for rrset in rrsets:
        if not isinstance(rrset, dict) or not isinstance(rrset.get('type'), str) or not isinstance(rrset.get('name'), str):
            raise ProviderError('ساختار مجموعهٔ رکوردهای سرور معتبر نیست.')
        kind = rrset['type']
        label = record_name(rrset['name'], name)
        if kind == 'SOA':
            continue
        values = rrset.get('records')
        if not isinstance(values, list) or not isinstance(rrset.get('ttl'), int) or not 0 <= rrset['ttl'] <= 2147483647:
            raise ProviderError('TTL یا ساختار رکوردهای سرور معتبر نیست.')
        if kind == 'NS' and label == '@':
            for value in values:
                if not value.get('disabled', False):
                    nameservers.append(hostname(value['content']) + '.')
            default_ttl = max(60, rrset['ttl'])
            continue
        if kind not in RECORD_TYPES:
            unmanaged.append(rrset)
            continue
        for value in values:
            if not isinstance(value, dict) or not isinstance(value.get('content'), str) or not isinstance(value.get('disabled', False), bool):
                raise ProviderError('مقدار رکورد سرور معتبر نیست.')
            content = value['content']
            extra = {}
            if kind == 'TXT':
                parsed = dns.rdata.from_text('IN', kind, content)
                content = b''.join(parsed.strings).decode('utf-8')
            elif kind == 'MX':
                parsed = dns.rdata.from_text('IN', kind, content)
                content = parsed.exchange.to_text()
                extra['priority'] = parsed.preference
            elif kind == 'SRV':
                parsed = dns.rdata.from_text('IN', kind, content)
                content = parsed.target.to_text()
                extra = {'priority': parsed.priority, 'weight': parsed.weight, 'port': parsed.port}
            records.append({'name': label, 'type': kind, 'content': content, 'ttl': rrset['ttl'],
                            'enabled': not value.get('disabled', False), **extra})
    return name, records, list(dict.fromkeys(nameservers)), unmanaged, default_ttl


@transaction.atomic
def import_zone(remote, owner, actor, provider_identity, *, discard_draft=False, lease_token=None, expected_state=None):
    name, records, nameservers, unmanaged, ttl = parse_zone(remote)
    fingerprint = rrset_fingerprint(remote['rrsets'])
    if not isinstance(remote.get('account', ''), str) or len(remote.get('account', '')) > 255 or not isinstance(remote.get('kind', 'Native'), str):
        raise ProviderError('مشخصات مالکیت دامنه در پاسخ سرور معتبر نیست.')
    zone = Zone.objects.select_for_update().filter(name=name).first()
    created = zone is None
    if zone is not None:
        if zone.owner_id != owner.pk:
            return 'other_owner'
        if zone.publishing_until and zone.publishing_until > timezone.now() and not (lease_token and zone.publish_token == lease_token):
            return 'busy'
        if expected_state and (zone.revision, zone.published_revision, zone.remote_snapshot) != expected_state:
            return 'busy'
        if zone.source == 'server':
            if zone.provider_identity != provider_identity or zone.remote_account != remote.get('account', ''):
                zone.sync_note = 'شناسهٔ سرور یا مالکیت دامنه در سرویس DNS تغییر کرده است.'
                zone.save(update_fields=['sync_note'])
                return 'conflict'
        elif remote.get('account') != f'orbit-{zone.external_id}':
            zone.sync_note = 'هم‌نام این دامنه روی سرور موجود است؛ پیش‌نویس پنل حفظ شد و مالکیت آن تغییر نکرد.'
            zone.save(update_fields=['sync_note'])
            return 'conflict'
        if zone.revision != zone.published_revision and not discard_draft:
            note = 'رکوردهای سرور تغییر کرده‌اند؛ پیش‌نویس شما حفظ شده است. قبل از انتشار اختلاف را بررسی کنید.' if zone.remote_snapshot and zone.remote_snapshot != fingerprint else ''
            zone.sync_note = note
            zone.last_synced_at = timezone.now()
            zone.save(update_fields=['sync_note', 'last_synced_at'])
            return 'draft'
        if fingerprint == zone.remote_snapshot and not discard_draft:
            zone.last_synced_at = timezone.now()
            zone.sync_note = ''
            zone.save(update_fields=['last_synced_at', 'sync_note'])
            return 'unchanged'
        comments = {(record.name, record.type, record.dns_content): record.comment for record in zone.records.all() if record.comment}
        zone.records.all().delete()
        zone.revision += 1
    else:
        zone = Zone.objects.create(name=name, owner=owner, source='server', description='شناسایی‌شده از سرور DNS')
        comments = {}
    zone.provider_identity = provider_identity
    zone.remote_account = remote.get('account', '')
    zone.remote_kind = remote.get('kind', 'Native')
    zone.remote_snapshot = fingerprint
    zone.detected_nameservers = nameservers
    zone.unmanaged_rrsets = unmanaged
    if created:
        zone.default_ttl = ttl
    zone.provisioned = True
    zone.published_revision = zone.revision
    zone.last_synced_at = timezone.now()
    zone.sync_note = zone.last_error = ''
    zone.save()
    for values in records:
        record = Record(zone=zone, **values)
        record.comment = comments.get((record.name, record.type, record.dns_content), '')
        record.full_clean()
        record.save()
    audit(actor, zone, 'شناسایی دامنه از سرور' if created else 'دریافت تغییرات سرور', f'{len(records)} رکورد دریافت شد؛ تنظیمات سرور تغییر نکرد.')
    return 'created' if created else 'updated'


def discover_zones(actor, force=False):
    owner = discovery_owner(actor)
    now = timezone.now()
    state, _ = DiscoveryState.objects.get_or_create(pk=1)
    token = uuid.uuid4()
    eligible = DiscoveryState.objects.filter(pk=1).filter(Q(locked_until__isnull=True) | Q(locked_until__lte=now))
    if not force:
        eligible = eligible.filter(Q(last_attempt__isnull=True) | Q(last_attempt__lte=now - timedelta(seconds=settings.DNS_DISCOVERY_INTERVAL)))
    if not eligible.update(token=token, locked_until=now + timedelta(minutes=3), last_attempt=now):
        return {'changed': False, 'deferred': True, 'last_success': state.last_success.isoformat() if state.last_success else None}
    summary = {'created': 0, 'updated': 0, 'skipped': 0, 'scanned': 0, 'problems': []}
    try:
        with PowerDNS() as provider:
            listing = sorted(provider.list_zones(), key=lambda row: row['name'])
            start = state.cursor if state.cursor < len(listing) else 0
            deadline = time.monotonic() + 40
            next_cursor = start
            for index in range(start, min(len(listing), start + 20)):
                item = listing[index]
                if time.monotonic() > deadline:
                    break
                # Extend a previously acquired global lease only while still owning it.
                if not DiscoveryState.objects.filter(pk=1, token=token).exists():
                    raise ZoneBusy('شناسایی دیگری آغاز شده است؛ دوباره تلاش کنید.')
                next_cursor = index + 1
                try:
                    name = zone_name(item['name'])
                    existing = Zone.objects.filter(name=name).first()
                    if existing and existing.owner_id != owner.pk:
                        summary['skipped'] += 1
                        continue
                    remote = provider.read_zone(name)
                    if remote is None:
                        summary['skipped'] += 1
                        continue
                    if zone_name(remote.get('name', '')) != name:
                        raise ProviderError('نام دامنه در پاسخ سرور با درخواست یکسان نیست.')
                    expected = (existing.revision, existing.published_revision, existing.remote_snapshot) if existing else None
                    result = import_zone(remote, owner, actor, provider.identity, expected_state=expected)
                    if result in ('created', 'updated'):
                        summary[result] += 1
                    elif result != 'unchanged':
                        summary['skipped'] += 1
                    summary['scanned'] += 1
                except (ValidationError, ProviderError, IntegrityError, UnicodeError, ValueError, KeyError, TypeError, AttributeError, dns.exception.DNSException):
                    summary['skipped'] += 1
                    summary['problems'].append(item['name'])
                    Zone.objects.filter(name=item['name'].rstrip('.').lower(), owner=owner).update(sync_note='رکوردهای سرور به‌طور کامل قابل دریافت نبودند؛ دادهٔ قبلی حفظ شد. تنظیمات و انواع رکورد را بررسی کنید.')
            summary['total'] = len(listing)
            summary['remaining'] = len(listing) - next_cursor
            present = [row['name'].rstrip('.').lower() for row in listing]
            Zone.objects.filter(owner=owner, provisioned=True, provider_identity=provider.identity).exclude(name__in=present).update(sync_note='این دامنه دیگر در فهرست سرور دیده نمی‌شود؛ داده‌های پنل برای بررسی حفظ شده‌اند.')
        summary['changed'] = bool(summary['created'] or summary['updated'])
        DiscoveryState.objects.filter(pk=1, token=token).update(last_success=timezone.now(), summary=summary, error='', cursor=next_cursor if next_cursor < len(listing) else 0)
        return summary
    except ProviderError as error:
        DiscoveryState.objects.filter(pk=1, token=token).update(error=str(error)[:500])
        raise
    finally:
        DiscoveryState.objects.filter(pk=1, token=token).update(locked_until=None, token=None)


def pull_zone(zone, actor, expected_revision):
    """Explicitly discard a reviewed local draft; never changes the DNS service."""
    token = acquire(zone)
    try:
        zone.refresh_from_db()
        if zone.revision != expected_revision:
            raise ZoneBusy('نسخهٔ دامنه تغییر کرده است؛ صفحه را تازه و دوباره بررسی کنید.')
        with PowerDNS() as provider:
            remote = provider.owned_zone(zone)
            if remote is None:
                raise ProviderError('دامنه روی سرور پیدا نشد. پیش‌نویس پنل حفظ شد.')
            if zone_name(remote.get('name', '')) != zone.name:
                raise ProviderError('نام دامنه در پاسخ سرور معتبر نیست.')
            result = import_zone(remote, actor, actor, provider.identity, discard_draft=True, lease_token=token)
            if result not in ('updated', 'unchanged'):
                raise ProviderError('دریافت نسخهٔ سرور انجام نشد. پیش‌نویس پنل حفظ شد.')
    except (ValidationError, UnicodeError, ValueError, KeyError, TypeError, dns.exception.DNSException):
        raise ProviderError('رکوردهای سرور به‌طور کامل قابل دریافت نیستند؛ پیش‌نویس پنل حفظ شد.') from None
    finally:
        Zone.objects.filter(pk=zone.pk, publish_token=token).update(publishing_until=None, publish_token=None)
