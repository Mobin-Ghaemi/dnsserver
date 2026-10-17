from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from dnsmanager.discovery import discover_zones
from dnsmanager.powerdns import ProviderError


class Command(BaseCommand):
    help = 'Discover existing zones and records without writing to the DNS service.'

    def add_arguments(self, parser):
        parser.add_argument('--username', default='')
        parser.add_argument('--force', action='store_true')

    def handle(self, *args, **options):
        username = options['username'] or settings.DNS_DISCOVERY_OWNER
        if not username:
            raise CommandError('Set DNS_DISCOVERY_OWNER or pass --username ADMIN_USERNAME.')
        try:
            actor = get_user_model().objects.get(username=username, is_active=True, is_staff=True)
        except get_user_model().DoesNotExist:
            raise CommandError('An active staff user is required.') from None
        try:
            result = discover_zones(actor, force=options['force'])
        except ProviderError as error:
            raise CommandError(str(error)) from None
        self.stdout.write(str(result))
