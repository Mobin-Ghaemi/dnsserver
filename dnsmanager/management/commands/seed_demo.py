from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from dnsmanager.models import Zone, Record
from dnsmanager.services import audit


class Command(BaseCommand):
    help = 'Add clearly labeled draft example domains to an existing local user (DEBUG only).'

    def add_arguments(self, parser):
        parser.add_argument('--username', required=True)

    @transaction.atomic
    def handle(self, *args, **options):
        if not settings.DEBUG:
            raise CommandError('Demo data is only available with DJANGO_DEBUG=True.')
        try:
            user = get_user_model().objects.get(username=options['username'])
        except get_user_model().DoesNotExist:
            raise CommandError('Create the user first with createsuperuser.')
        zones = [
            ('orbit.example', 'نمونهٔ آزمایشی · وب‌سایت اصلی', [('A', '@', '203.0.113.10', None), ('CNAME', 'www', 'orbit.example.', None), ('MX', '@', 'mail.orbit.example.', 10), ('TXT', '@', 'v=spf1 -all', None), ('AAAA', '@', '2001:db8::10', None)]),
            ('studio.example', 'نمونهٔ آزمایشی · استودیوی طراحی', [('A', '@', '203.0.113.20', None), ('CNAME', 'www', 'studio.example.', None), ('TXT', '_verify', 'orbit-demo-verification', None)]),
            ('api.example', 'نمونهٔ آزمایشی · سرویس‌ها و API', [('A', '@', '203.0.113.30', None), ('A', 'staging', '203.0.113.31', None), ('AAAA', '@', '2001:db8::30', None), ('TXT', '@', 'environment=demo', None)]),
            ('mail.example', 'نمونهٔ آزمایشی · سرویس ایمیل', [('A', '@', '203.0.113.40', None), ('MX', '@', 'mx.mail.example.', 10), ('TXT', '_dmarc', 'v=DMARC1; p=reject;', None)]),
        ]
        created = 0
        for name, description, records in zones:
            zone, new = Zone.objects.get_or_create(name=name, defaults={'owner': user, 'description': description})
            if not new:
                continue
            created += 1
            audit(user, zone, 'افزودن دامنه', 'دادهٔ نمونه؛ منتشر نشده است.')
            for kind, label, content, priority in records:
                record = Record(zone=zone, type=kind, name=label, content=content, priority=priority)
                record.full_clean()
                record.save()
                audit(user, zone, 'افزودن رکورد', f'{label} · {kind} · نمونهٔ آزمایشی')
        self.stdout.write(self.style.SUCCESS(f'Created {created} draft example domains. Nothing was sent to DNS.'))
