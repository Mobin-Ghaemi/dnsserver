import copy
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.core.exceptions import PermissionDenied, ValidationError
from django.test import TestCase, SimpleTestCase, override_settings
from django.utils import timezone

from config.local_dns import local_powerdns_config
from .discovery import discover_zones, import_zone, pull_zone
from .models import Zone, Record, DiscoveryState
from .powerdns import PowerDNS, ProviderError, rrset_fingerprint
from .services import publish_zone, editable_zone, ZoneBusy
from .tests import User, PASSWORD, PROVIDER, TEST_STORAGES, response


def remote_zone():
    def rrset(name, kind, content, ttl=300, disabled=False):
        return {'name': name, 'type': kind, 'ttl': ttl, 'records': [{'content': content, 'disabled': disabled}]}
    return {'name': 'existing.test.', 'account': 'legacy-account', 'kind': 'Native', 'rrsets': [
        rrset('existing.test.', 'SOA', 'ns1.dns.test. hostmaster.existing.test. 10 10800 3600 604800 300'),
        {'name': 'existing.test.', 'type': 'NS', 'ttl': 300, 'records': [{'content': 'ns1.old.test.', 'disabled': False}, {'content': 'ns2.old.test.', 'disabled': False}]},
        rrset('existing.test.', 'A', '192.0.2.10', ttl=0),
        rrset('existing.test.', 'AAAA', '2001:db8::10'),
        rrset('existing.test.', 'MX', '10 mail.existing.test.'),
        rrset('existing.test.', 'TXT', '"hello " "DNS"', disabled=True),
        rrset('_sip._tcp.existing.test.', 'SRV', '0 5 443 sip.existing.test.'),
        rrset('www.existing.test.', 'CNAME', 'existing.test.'),
        rrset('_443._tcp.existing.test.', 'TLSA', '3 1 1 ' + 'ab' * 32),
    ]}


@override_settings(**PROVIDER, DNS_DISCOVERY_OWNER='')
class DiscoveryTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.admin = User.objects.create_user('manager', password=PASSWORD, is_staff=True)
        cls.other = User.objects.create_user('other-manager', password=PASSWORD, is_staff=True)
        cls.user = User.objects.create_user('ordinary', password=PASSWORD)

    def import_remote(self, remote=None):
        with PowerDNS() as provider:
            result = import_zone(remote or remote_zone(), self.admin, self.admin, provider.identity)
        return Zone.objects.get(name='existing.test'), result

    @patch('requests.Session.request')
    def test_discover_imports_all_records_without_any_dns_write(self, request):
        request.side_effect = [response(200, [{'name': 'existing.test.'}]), response(200, remote_zone())]
        result = discover_zones(self.admin)
        zone = Zone.objects.get(name='existing.test')
        self.assertEqual(result['created'], 1)
        self.assertTrue(result['changed'])
        self.assertEqual(zone.records.count(), 6)
        self.assertEqual(zone.status, 'published')
        self.assertIsNone(zone.last_published_at)
        self.assertEqual(zone.nameservers, ['ns1.old.test.', 'ns2.old.test.'])
        self.assertEqual(zone.remote_account, 'legacy-account')
        self.assertEqual(zone.unmanaged_rrsets[0]['type'], 'TLSA')
        self.assertEqual(zone.records.get(type='A').ttl, 0)
        self.assertEqual(zone.records.get(type='TXT').content, 'hello DNS')
        self.assertFalse(zone.records.get(type='TXT').enabled)
        self.assertEqual(zone.records.get(type='MX').priority, 10)
        self.assertEqual(zone.records.get(type='SRV').port, 443)
        self.assertTrue(all(call.args[0] == 'GET' for call in request.call_args_list))

    def test_repeated_import_keeps_record_ids_and_revision(self):
        zone, result = self.import_remote()
        ids = list(zone.records.values_list('pk', flat=True))
        same, result = self.import_remote()
        self.assertEqual(result, 'unchanged')
        self.assertEqual(same.revision, 1)
        self.assertEqual(list(same.records.values_list('pk', flat=True)), ids)

    def test_external_changes_refresh_clean_zone(self):
        zone, _ = self.import_remote()
        remote = remote_zone()
        remote['rrsets'][2]['records'][0]['content'] = '192.0.2.20'
        zone, result = self.import_remote(remote)
        self.assertEqual(result, 'updated')
        self.assertEqual(zone.records.get(type='A').content, '192.0.2.20')
        self.assertEqual(zone.revision, 2)
        self.assertEqual(zone.published_revision, 2)

    def test_local_draft_survives_remote_changes_and_publish_is_blocked(self):
        zone, _ = self.import_remote()
        zone.revision += 1
        zone.save()
        record = zone.records.get(type='A')
        record.content = '192.0.2.99'
        record.save()
        remote = remote_zone()
        remote['rrsets'][2]['records'][0]['content'] = '192.0.2.88'
        zone, result = self.import_remote(remote)
        self.assertEqual(result, 'draft')
        self.assertEqual(zone.records.get(type='A').content, '192.0.2.99')
        self.assertTrue(zone.sync_note)
        with patch('requests.Session.request', return_value=response(200, remote)) as request:
            with self.assertRaises(ProviderError):
                publish_zone(zone, self.admin, zone.revision)
            self.assertEqual(request.call_count, 1)

    def test_invalid_record_rolls_back_entire_import(self):
        zone, _ = self.import_remote()
        old_snapshot = zone.remote_snapshot
        remote = remote_zone()
        remote['rrsets'][2]['records'][0]['content'] = 'invalid-ip'
        with self.assertRaises(ValidationError):
            self.import_remote(remote)
        zone.refresh_from_db()
        self.assertEqual(zone.remote_snapshot, old_snapshot)
        self.assertEqual(zone.records.get(type='A').content, '192.0.2.10')

    def test_other_admin_cannot_reassign_existing_zone(self):
        zone, _ = self.import_remote()
        with PowerDNS() as provider:
            result = import_zone(remote_zone(), self.other, self.other, provider.identity)
        zone.refresh_from_db()
        self.assertEqual(result, 'other_owner')
        self.assertEqual(zone.owner, self.admin)

    def test_ordinary_user_cannot_discover(self):
        with self.assertRaises(PermissionDenied):
            discover_zones(self.user)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post('/domains/discover/').status_code, 403)

    @patch('requests.Session.request')
    def test_discovery_is_throttled_and_shared_across_workers(self, request):
        request.return_value = response(200, [])
        discover_zones(self.admin)
        self.assertTrue(discover_zones(self.admin)['deferred'])
        self.assertEqual(request.call_count, 1)
        discover_zones(self.admin, force=True)
        self.assertEqual(request.call_count, 2)

    @patch('requests.Session.request')
    def test_missing_remote_zone_preserves_local_records(self, request):
        zone, _ = self.import_remote()
        request.return_value = response(200, [])
        discover_zones(self.admin)
        zone.refresh_from_db()
        self.assertTrue(zone.sync_note)
        self.assertEqual(zone.records.count(), 6)

    @patch('requests.Session.request')
    def test_imported_zone_publish_preserves_ns_unknown_types_and_account(self, request):
        zone, _ = self.import_remote()
        request.side_effect = [response(200, remote_zone()), response(204)]
        publish_zone(zone, self.admin, zone.revision)
        rrsets = request.call_args.kwargs['json']['rrsets']
        self.assertFalse(any(row['type'] in ('NS', 'TLSA', 'SOA') for row in rrsets))
        self.assertEqual([call.args[0] for call in request.call_args_list], ['GET', 'PATCH'])

    def test_changed_provider_or_account_cannot_be_adopted_silently(self):
        zone, _ = self.import_remote()
        with PowerDNS() as provider:
            self.assertEqual(import_zone(remote_zone(), self.admin, self.admin, 'different-provider'), 'conflict')
        remote = remote_zone()
        remote['account'] = 'new-account'
        with patch('requests.Session.request', return_value=response(200, remote)):
            with self.assertRaises(ProviderError):
                publish_zone(zone, self.admin, 1)

    def test_secondary_records_are_readonly(self):
        remote = remote_zone()
        remote['kind'] = 'Slave'
        zone, _ = self.import_remote(remote)
        self.assertTrue(zone.is_readonly)
        with self.assertRaises(ZoneBusy):
            editable_zone(zone.pk, self.admin)

    @patch('requests.Session.request')
    def test_explicit_pull_discards_draft_without_writing_dns(self, request):
        zone, _ = self.import_remote()
        zone.revision = 2
        zone.save()
        record = zone.records.get(type='A')
        record.content = '192.0.2.99'
        record.save()
        request.return_value = response(200, remote_zone())
        pull_zone(zone, self.admin, 2)
        zone.refresh_from_db()
        self.assertEqual(zone.records.get(type='A').content, '192.0.2.10')
        self.assertEqual(zone.status, 'published')
        self.assertIsNone(zone.publish_token)
        self.assertEqual(request.call_count, 1)
        self.assertEqual(request.call_args.args[0], 'GET')

    @override_settings(DNS_NAMESERVERS=['ns1.example.net.', 'ns2.example.net.'])
    def test_new_domains_infer_shared_real_nameservers(self):
        self.import_remote()
        zone = Zone(owner=self.admin, name='new.test')
        self.assertEqual(zone.nameservers, ['ns1.old.test.', 'ns2.old.test.'])

    @override_settings(DNS_NAMESERVERS=['ns1.example.net.', 'ns2.example.net.'])
    def test_conflicting_nameserver_sets_require_explicit_configuration(self):
        self.import_remote()
        with PowerDNS() as provider:
            Zone.objects.create(owner=self.admin, name='different.test', source='server', provider_identity=provider.identity,
                                detected_nameservers=['ns1.different.test.', 'ns2.different.test.'])
        self.assertEqual(Zone(owner=self.admin, name='new.test').nameservers, ['ns1.example.net.', 'ns2.example.net.'])

    def test_inflight_publish_and_stale_read_are_not_imported(self):
        from datetime import timedelta
        zone, _ = self.import_remote()
        Zone.objects.filter(pk=zone.pk).update(publishing_until=timezone.now() + timedelta(minutes=1))
        with PowerDNS() as provider:
            self.assertEqual(import_zone(remote_zone(), self.admin, self.admin, provider.identity), 'busy')
        Zone.objects.filter(pk=zone.pk).update(publishing_until=None)
        with PowerDNS() as provider:
            self.assertEqual(import_zone(remote_zone(), self.admin, self.admin, provider.identity, expected_state=(1, 1, 'outdated')), 'busy')

    @override_settings(DNS_DISCOVERY_OWNER='other-manager')
    @patch('requests.Session.request')
    def test_configured_owner_receives_discovered_zones(self, request):
        request.side_effect = [response(200, [{'name': 'existing.test.'}]), response(200, remote_zone())]
        discover_zones(self.admin)
        self.assertEqual(Zone.objects.get(name='existing.test').owner, self.other)


@override_settings(STORAGES=TEST_STORAGES)
class ModalTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('modal-owner', password=PASSWORD)
        cls.zone = Zone.objects.create(owner=cls.user, name='modal.test')

    def setUp(self):
        self.client.force_login(self.user)
        self.headers = {'HTTP_X_ORBIT_MODAL': '1'}

    def test_domain_form_is_json_fragment_with_csrf_and_no_page_shell(self):
        result = self.client.get('/domains/new/', **self.headers)
        self.assertEqual(result.status_code, 200)
        self.assertIn('csrfmiddlewaretoken', result.json()['html'])
        self.assertNotIn('<html', result.json()['html'])

    @override_settings(DNS_NAMESERVERS=['ns1.real.test.', 'ns2.real.test.'])
    def test_domain_creation_returns_nameserver_onboarding(self):
        result = self.client.post('/domains/new/', {'name': 'new-modal.test', 'default_ttl': 300}, **self.headers)
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()['ok'])
        self.assertIn('ns1.real.test.', result.json()['html'])
        self.assertIn('ثبت‌کننده', result.json()['html'])

    def test_record_validation_stays_inside_modal(self):
        result = self.client.post(f'/domains/{self.zone.pk}/records/new/', {'name': '@', 'type': 'A', 'content': 'bad', 'ttl': 300}, **self.headers)
        self.assertEqual(result.status_code, 422)
        self.assertFalse(result.json()['ok'])
        self.assertIn('معتبر نیست', result.json()['html'])
        self.assertEqual(self.zone.records.count(), 0)

    def test_record_create_and_edit_return_success(self):
        result = self.client.post(f'/domains/{self.zone.pk}/records/new/', {'name': 'www', 'type': 'A', 'content': '192.0.2.1', 'ttl': 300, 'enabled': 'on'}, **self.headers)
        self.assertTrue(result.json()['ok'])
        record = self.zone.records.get()
        result = self.client.post(f'/domains/{self.zone.pk}/records/{record.pk}/', {'name': 'www', 'type': 'A', 'content': '192.0.2.2', 'ttl': 300, 'enabled': 'on'}, **self.headers)
        self.assertTrue(result.json()['ok'])
        record.refresh_from_db()
        self.assertEqual(record.content, '192.0.2.2')

    def test_pull_requires_confirmation_and_foreign_zone_is_hidden(self):
        result = self.client.post(f'/domains/{self.zone.pk}/pull/', {'confirm_name': 'wrong', 'revision': 1}, **self.headers)
        self.assertEqual(result.status_code, 422)
        self.assertIn('تأیید', result.json()['html'])
        other = User.objects.create_user('another-modal-owner')
        foreign = Zone.objects.create(owner=other, name='foreign-modal.test')
        self.assertEqual(self.client.get(f'/domains/{foreign.pk}/pull/', **self.headers).status_code, 404)


class LocalConfigTests(SimpleTestCase):
    def test_local_config_and_includes_are_read_without_shell(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            include = root / 'pdns.d'
            include.mkdir()
            (root / 'pdns.conf').write_text(f'api=yes\nwebserver-address=0.0.0.0\ninclude-dir={include}\n')
            (include / 'api.conf').write_text('api-key=test-only-secret\nwebserver-port=8082\n')
            result = local_powerdns_config(str(root / 'pdns.conf'))
            self.assertEqual(result, {'url': 'http://127.0.0.1:8082/api/v1', 'key': 'test-only-secret'})

    def test_disabled_missing_and_unreadable_configs_are_not_connections(self):
        self.assertEqual(local_powerdns_config('/nonexistent/orbit-test.conf'), {})
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'pdns.conf'
            path.write_text('api=no\napi-key=secret\n')
            self.assertEqual(local_powerdns_config(str(path)), {})

    def test_snapshot_ignores_rrset_order_soa_serial_and_ipv6_spelling(self):
        remote = remote_zone()
        other = copy.deepcopy(remote)
        other['rrsets'].reverse()
        next(row for row in other['rrsets'] if row['type'] == 'AAAA')['records'][0]['content'] = '2001:0db8:0:0:0:0:0:10'
        next(row for row in other['rrsets'] if row['type'] == 'SOA')['records'][0]['content'] = 'different serial'
        self.assertEqual(rrset_fingerprint(remote['rrsets']), rrset_fingerprint(other['rrsets']))


class DiscoveryHTTPTests(TestCase):
    def test_discovery_uses_real_http_list_and_detail_with_no_remote_writes(self):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                calls.append((self.command, self.path, self.headers.get('X-API-Key')))
                body = [{'name': 'existing.test.'}] if self.path.endswith('/zones') else remote_zone()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            actor = User.objects.create_user('http-discovery-admin', is_staff=True)
            with override_settings(PDNS_API_URL=f'http://127.0.0.1:{server.server_port}/api/v1', PDNS_API_KEY='http-test-only', DNS_DISCOVERY_OWNER=''):
                result = discover_zones(actor)
            self.assertEqual(result['created'], 1)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(method == 'GET' and key == 'http-test-only' for method, _, key in calls))
            self.assertEqual(Zone.objects.get(name='existing.test').records.count(), 6)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

@override_settings(STORAGES=TEST_STORAGES)
class AutoPublishTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('auto-publish-owner')
        self.zone = Zone.objects.create(owner=self.user, name='auto-publish.test')
        self.client.force_login(self.user)

    @patch('dnsmanager.views.publish_zone')
    def test_create_edit_toggle_delete_publish_current_revision(self, publish):
        data = {'name': 'www', 'type': 'A', 'content': '192.0.2.1', 'ttl': 300, 'enabled': 'on'}
        root = f'/domains/{self.zone.pk}/records/'
        result = self.client.post(root + 'new/', data, HTTP_X_ORBIT_MODAL='1')
        self.assertTrue(result.json()['published'])
        record = self.zone.records.get()
        data['content'] = '192.0.2.2'
        self.client.post(root + f'{record.pk}/', data)
        self.client.post(root + f'{record.pk}/toggle/')
        self.client.post(root + f'{record.pk}/delete/')
        self.assertEqual(publish.call_count, 4)
        self.assertEqual([call.args[2] for call in publish.call_args_list], [2, 3, 4, 5])
        self.assertEqual(self.zone.records.count(), 0)

    @patch('dnsmanager.views.publish_zone', side_effect=ProviderError('provider offline'))
    def test_failure_preserves_record_and_reports_dns_not_applied(self, publish):
        result = self.client.post(f'/domains/{self.zone.pk}/records/new/',
            {'name': 'www', 'type': 'A', 'content': '192.0.2.1', 'ttl': 300, 'enabled': 'on'},
            HTTP_X_ORBIT_MODAL='1')
        self.assertFalse(result.json()['published'])
        self.assertEqual(self.zone.records.count(), 1)
        from django.contrib.messages import get_messages
        self.assertTrue(any('روی DNS اعمال نشد' in str(m) for m in get_messages(result.wsgi_request)))

    @patch('dnsmanager.views.publish_zone')
    def test_invalid_record_never_publishes(self, publish):
        self.client.post(f'/domains/{self.zone.pk}/records/new/',
                         {'name': 'www', 'type': 'A', 'content': 'invalid', 'ttl': 300})
        publish.assert_not_called()
