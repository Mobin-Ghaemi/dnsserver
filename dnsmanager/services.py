import uuid
from datetime import timedelta

from django.db import transaction
from django.db.models import F, Q
from django.utils import timezone
from .models import Zone, Activity
from .powerdns import PowerDNS, ProviderError


class ZoneBusy(Exception):
    pass


def audit(user, zone, action, detail=''):
    Activity.objects.create(user=user, zone=zone, zone_name=zone.name, action=action, detail=detail)


def editable_zone(pk, user):
    # Caller holds a transaction; all writes serialize on this row in PostgreSQL.
    zone = Zone.objects.select_for_update().get(pk=pk, owner=user)
    if zone.is_readonly:
        raise ZoneBusy('این دامنه ثانویه است؛ رکوردها را روی سرور اصلی تغییر دهید.')
    if zone.publishing_until and zone.publishing_until > timezone.now():
        raise ZoneBusy('انتشار یا حذف دامنه در حال انجام است؛ کمی بعد تلاش کنید.')
    return zone


def changed(zone):
    Zone.objects.filter(pk=zone.pk).update(revision=F('revision') + 1, last_error='', updated_at=timezone.now())


def acquire(zone):
    token = uuid.uuid4()
    count = Zone.objects.filter(pk=zone.pk).filter(
        Q(publishing_until__isnull=True) | Q(publishing_until__lte=timezone.now())
    ).update(publishing_until=timezone.now() + timedelta(minutes=3), publish_token=token)
    if not count:
        raise ZoneBusy('عملیات دیگری در حال انجام است؛ کمی بعد تلاش کنید.')
    return token


def publish_zone(zone, user, expected_revision):
    token = acquire(zone)
    try:
        zone.refresh_from_db()
        revision = zone.revision
        if revision != expected_revision:
            raise ZoneBusy('نسخهٔ دامنه تغییر کرده است. صفحه را تازه و تغییرات را بررسی کنید.')
        records = list(zone.records.all())
        with PowerDNS() as provider:
            snapshot = provider.publish(zone, records)
        with transaction.atomic():
            updated = Zone.objects.filter(pk=zone.pk, publish_token=token).update(
                published_revision=revision, last_published_at=timezone.now(), last_error='', remote_snapshot=snapshot, sync_note='')
            if updated:
                audit(user, zone, 'انتشار دامنه', f'نسخه {revision} · {len(records)} رکورد')
    except ProviderError as error:
        with transaction.atomic():
            Zone.objects.filter(pk=zone.pk, publish_token=token).update(last_error=str(error)[:500])
            audit(user, zone, 'خطای انتشار', str(error)[:300])
        raise
    finally:
        Zone.objects.filter(pk=zone.pk, publish_token=token).update(publishing_until=None, publish_token=None)


def delete_zone(zone, user):
    token = acquire(zone)
    try:
        zone.refresh_from_db()
        # Check configured providers even after a failed/uncertain first creation.
        from django.conf import settings
        if zone.provisioned or (settings.PDNS_API_URL and settings.PDNS_API_KEY):
            with PowerDNS() as provider:
                provider.delete(zone)
        with transaction.atomic():
            locked = Zone.objects.select_for_update().get(pk=zone.pk, publish_token=token)
            audit(user, locked, 'حذف دامنه', 'دامنه و رکوردهای آن حذف شدند.')
            locked.delete()
    finally:
        Zone.objects.filter(pk=zone.pk, publish_token=token).update(publishing_until=None, publish_token=None)
