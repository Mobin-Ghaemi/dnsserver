import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

import dns.zone
import requests
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, SimpleTestCase, Client, override_settings, RequestFactory
from django.utils import timezone

from .dns import canonical_content, record_name, zone_name
from .forms import RecordForm
from .models import Zone, Record, Activity
from .powerdns import PowerDNS, ProviderError
from .security import client_ip
from .services import publish_zone, delete_zone, ZoneBusy, editable_zone

User = get_user_model()
PASSWORD = 'Test-only!LongPassword-9385'
PROVIDER = {'PDNS_API_URL': 'http://127.0.0.1:8081/api/v1', 'PDNS_API_KEY': 'test-key-do-not-use',
            'DNS_NAMESERVERS': ['ns1.dns.test.', 'ns2.dns.test.']}
TEST_STORAGES = {'default': {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
                 'staticfiles': {'BACKEND': 'django.contrib.staticfiles.storage.StaticFilesStorage'}}


def response(status=200, body=None):
    result = Mock(status_code=status, content=b'json' if body is not None else b'')
    result.json.return_value = body
    return result


class DNSParsingTests(SimpleTestCase):
    def test_domains_and_idna(self):
        self.assertEqual(zone_name('EXAMPLE.COM.'), 'example.com')
        self.assertTrue(zone_name('مثال.ir').startswith('xn--'))
        for invalid in ['https://example.com', 'bad..com', '-bad.com', 'localhost', 'bad/name.com', 'a.' + 'b' * 64]:
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                zone_name(invalid)

    def test_record_owners(self):
        for value, expected in [('@', '@'), ('www', 'www'), ('www.example.com.', 'www'), ('example.com.', '@'), ('_sip._tcp', '_sip._tcp'), ('*.api', '*.api')]:
            self.assertEqual(record_name(value, 'example.com'), expected)
        for invalid in ['foreign.com.', 'a.*', 'bad/name', '..', 'http://api']:
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                record_name(invalid, 'example.com')

    def test_addresses_and_targets(self):
        self.assertEqual(canonical_content('AAAA', '2001:0db8:0:0::1'), '2001:db8::1')
        self.assertEqual(canonical_content('MX', 'mail.example.com', 10), '10 mail.example.com.')
        self.assertEqual(canonical_content('SRV', 'sip.example.com', 0, 5, 443), '0 5 443 sip.example.com.')
        self.assertEqual(canonical_content('MX', '.', 0), '0 .')
        for kind, value in [('A', '::1'), ('AAAA', '1.2.3.4'), ('CNAME', 'bad_name'), ('CAA', 'bad')]:
            with self.subTest(kind=kind), self.assertRaises(ValidationError):
                canonical_content(kind, value)

    def test_txt_round_trip_quotes_unicode_and_long_strings(self):
        original = 'سلام ' * 80 + '"quoted" \\ backslash\nnext'
        encoded = canonical_content('TXT', original)
        parsed = dns.rdata.from_text('IN', 'TXT', encoded)
        self.assertEqual(b''.join(parsed.strings).decode(), original)
        self.assertTrue(all(len(part) <= 255 for part in parsed.strings))

    def test_txt_limit(self):
        for value in ['', 'x' * 4097]:
            with self.assertRaises(ValidationError):
                canonical_content('TXT', value)


class RecordValidationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('owner', password=PASSWORD)
        cls.zone = Zone.objects.create(owner=cls.user, name='example.com')

    def save_record(self, **kwargs):
        record = Record(zone=self.zone, **kwargs)
        record.full_clean()
        record.save()
        return record

    def test_cname_conflicts_both_directions_even_disabled(self):
        self.save_record(name='www', type='A', content='192.0.2.1', enabled=False)
        with self.assertRaises(ValidationError):
            self.save_record(name='www', type='CNAME', content='target.example.com')
        self.save_record(name='alias', type='CNAME', content='target.example.com')
        with self.assertRaises(ValidationError):
            self.save_record(name='alias', type='TXT', content='verification')

    def test_apex_cname_apex_ns_and_self_cname_rejected(self):
        for name, kind, content in [('@', 'CNAME', 'elsewhere.com'), ('@', 'NS', 'ns.elsewhere.com'), ('www', 'CNAME', 'www.example.com')]:
            with self.subTest(kind=kind), self.assertRaises(ValidationError):
                self.save_record(name=name, type=kind, content=content)

    def test_rrset_ttl_and_duplicates(self):
        self.save_record(name='@', type='A', content='192.0.2.1', ttl=300)
        with self.assertRaises(ValidationError):
            self.save_record(name='@', type='A', content='192.0.2.2', ttl=600)
        with self.assertRaises(ValidationError):
            self.save_record(name='@', type='A', content='192.0.2.1', ttl=300)
        self.save_record(name='@', type='A', content='192.0.2.2', ttl=300)

    def test_null_mx_cannot_coexist(self):
        self.save_record(name='@', type='MX', content='.', priority=0)
        with self.assertRaises(ValidationError):
            self.save_record(name='@', type='MX', content='mail.example.com', priority=10)

    def test_required_srv_fields_and_numeric_ranges(self):
        form = RecordForm({'name': '_sip._tcp', 'type': 'SRV', 'content': 'sip.example.com', 'ttl': 3600, 'enabled': 'on'}, zone=self.zone)
        self.assertFalse(form.is_valid())
        form = RecordForm({'name': '_sip._tcp', 'type': 'SRV', 'content': 'sip.example.com', 'ttl': 3600, 'priority': 0, 'weight': 5, 'port': 70000}, zone=self.zone)
        self.assertFalse(form.is_valid())

    def test_form_clears_irrelevant_numeric_values(self):
        form = RecordForm({'name': 'www', 'type': 'A', 'content': '192.0.2.1', 'ttl': 3600, 'priority': 10, 'weight': 20, 'port': 80, 'enabled': 'on'}, zone=self.zone)
        self.assertTrue(form.is_valid(), form.errors)
        record = form.save()
        self.assertIsNone(record.priority)
        self.assertIsNone(record.weight)
        self.assertIsNone(record.port)


@override_settings(STORAGES=TEST_STORAGES)
class PagesAndAccessTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('owner', password=PASSWORD, is_staff=True)
        cls.other = User.objects.create_user('other', password=PASSWORD)
        cls.zone = Zone.objects.create(owner=cls.user, name='example.com', description='<script>alert(1)</script>')
        cls.record = Record.objects.create(zone=cls.zone, name='@', type='A', content='192.0.2.1')
        cls.foreign = Zone.objects.create(owner=cls.other, name='private.example')
        cls.foreign_record = Record.objects.create(zone=cls.foreign, name='@', type='A', content='192.0.2.2')

    def setUp(self):
        self.client.force_login(self.user)

    def test_all_pages_render_and_escape_user_content(self):
        paths = ['/', '/domains/', '/domains/new/', f'/domains/{self.zone.pk}/', f'/domains/{self.zone.pk}/settings/',
                 f'/domains/{self.zone.pk}/records/new/', f'/domains/{self.zone.pk}/records/{self.record.pk}/',
                 f'/domains/{self.zone.pk}/records/{self.record.pk}/delete/', f'/domains/{self.zone.pk}/delete/',
                 '/activity/', '/connection/', '/guide/', '/account/password/', '/account/password/done/']
        for path in paths:
            with self.subTest(path=path):
                result = self.client.get(path)
                self.assertEqual(result.status_code, 200)
                self.assertIn('no-store', result.headers['Cache-Control'])
                self.assertNotIn('<script>alert(1)</script>', result.content.decode())

    def test_auth_required_everywhere(self):
        self.client.logout()
        for path in ['/', '/domains/', '/activity/', '/connection/', '/guide/', f'/domains/{self.zone.pk}/export/']:
            self.assertEqual(self.client.get(path).status_code, 302)

    def test_foreign_zone_is_inaccessible_even_for_staff(self):
        for suffix in ['', 'settings/', 'delete/', 'export/', 'records/new/']:
            self.assertEqual(self.client.get(f'/domains/{self.foreign.pk}/{suffix}').status_code, 404)
        for path in [f'/domains/{self.foreign.pk}/publish/', f'/domains/{self.foreign.pk}/records/{self.foreign_record.pk}/toggle/']:
            self.assertEqual(self.client.post(path).status_code, 404)
        result = self.client.get('/domains/')
        self.assertNotContains(result, 'private.example')

    def test_foreign_record_cannot_be_attached_to_owned_zone(self):
        for suffix in ['', 'delete/', 'toggle/']:
            path = f'/domains/{self.zone.pk}/records/{self.foreign_record.pk}/{suffix}'
            result = self.client.post(path) if suffix == 'toggle/' else self.client.get(path)
            self.assertEqual(result.status_code, 404)

    def test_mutations_require_post_and_csrf(self):
        self.assertEqual(self.client.get(f'/domains/{self.zone.pk}/publish/').status_code, 405)
        self.assertEqual(self.client.get(f'/domains/{self.zone.pk}/records/{self.record.pk}/toggle/').status_code, 405)
        self.assertEqual(self.client.get('/logout/').status_code, 405)
        secure = Client(enforce_csrf_checks=True)
        secure.force_login(self.user)
        self.assertEqual(secure.post(f'/domains/{self.zone.pk}/publish/', {'revision': 1}).status_code, 403)
        self.assertEqual(secure.post('/domains/new/', {'name': 'evil.example'}).status_code, 403)

    def test_create_edit_toggle_delete_record_changes_revision(self):
        path = f'/domains/{self.zone.pk}/records/new/'
        self.assertEqual(self.client.post(path, {'name': 'www', 'type': 'A', 'content': '192.0.2.5', 'ttl': 3600, 'enabled': 'on'}).status_code, 302)
        record = self.zone.records.get(name='www')
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.revision, 2)
        self.client.post(f'/domains/{self.zone.pk}/records/{record.pk}/', {'name': 'www', 'type': 'A', 'content': '192.0.2.6', 'ttl': 3600, 'enabled': 'on'})
        record.refresh_from_db()
        self.assertEqual(record.content, '192.0.2.6')
        self.client.post(f'/domains/{self.zone.pk}/records/{record.pk}/toggle/')
        record.refresh_from_db()
        self.assertFalse(record.enabled)
        self.client.post(f'/domains/{self.zone.pk}/records/{record.pk}/delete/')
        self.assertFalse(Record.objects.filter(pk=record.pk).exists())
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.revision, 5)
        self.assertEqual(Activity.objects.filter(zone=self.zone).count(), 4)

    def test_create_zone_normalizes_and_delete_needs_exact_name(self):
        self.client.post('/domains/new/', {'name': 'NEW.Example.', 'default_ttl': 300, 'description': 'new'})
        zone = Zone.objects.get(name='new.example')
        self.assertEqual(zone.owner, self.user)
        self.client.post(f'/domains/{zone.pk}/delete/', {'confirm_name': 'wrong'})
        self.assertTrue(Zone.objects.filter(pk=zone.pk).exists())
        self.client.post(f'/domains/{zone.pk}/delete/', {'confirm_name': zone.name})
        self.assertFalse(Zone.objects.filter(pk=zone.pk).exists())
        self.assertTrue(Activity.objects.filter(action='حذف دامنه', zone_name=zone.name, zone=None).exists())

    def test_zone_name_immutable(self):
        self.client.post(f'/domains/{self.zone.pk}/settings/', {'name': 'renamed.example', 'default_ttl': 300, 'description': 'changed'})
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.name, 'example.com')
        self.assertEqual(self.zone.default_ttl, 300)

    def test_search_and_filters(self):
        self.assertEqual(list(self.client.get('/domains/?q=absent').context['page_obj']), [])
        self.assertNotContains(self.client.get(f'/domains/{self.zone.pk}/?type=TXT'), '192.0.2.1')

    def test_export_is_valid_zone_and_disabled_is_comment(self):
        Record.objects.create(zone=self.zone, name='off', type='A', content='192.0.2.100', enabled=False)
        Record.objects.create(zone=self.zone, name='@', type='TXT', content='text "with quotes"')
        result = self.client.get(f'/domains/{self.zone.pk}/export/')
        text = result.content.decode()
        parsed = dns.zone.from_text(text, origin=self.zone.name)
        self.assertEqual(parsed.get_rdataset('@', 'A')[0].address, '192.0.2.1')
        self.assertIsNone(parsed.get_rdataset('off', 'A'))
        self.assertIn('; DISABLED off', text)
        self.assertIn('attachment', result.headers['Content-Disposition'])

    def test_stale_publish_does_not_call_backend(self):
        with patch('dnsmanager.services.PowerDNS') as provider:
            self.client.post(f'/domains/{self.zone.pk}/publish/', {'revision': 0})
            provider.assert_not_called()

    def test_empty_dashboard_is_honest(self):
        self.client.force_login(self.other)
        Record.objects.filter(zone=self.foreign).delete()
        result = self.client.get('/')
        self.assertEqual(result.context['published_count'], 0)
        self.assertEqual(result.context['distribution'], [])

    def test_nonstaff_cannot_test_shared_api(self):
        self.client.force_login(self.other)
        with patch('dnsmanager.views.PowerDNS') as provider:
            self.client.post('/connection/')
            provider.assert_not_called()

    def test_password_change_invalidates_old_login(self):
        result = self.client.post('/account/password/', {'old_password': PASSWORD, 'new_password1': 'Changed!Strong-Password-4829', 'new_password2': 'Changed!Strong-Password-4829'})
        self.assertEqual(result.status_code, 302)
        self.user.refresh_from_db()
        self.assertFalse(self.user.check_password(PASSWORD))
        self.assertTrue(self.user.check_password('Changed!Strong-Password-4829'))
        self.assertEqual(self.client.get('/').status_code, 200)


@override_settings(STORAGES=TEST_STORAGES)
class LoginTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('owner', password=PASSWORD)

    def test_login_and_logout(self):
        self.assertEqual(self.client.get('/login/').status_code, 200)
        result = self.client.post('/login/', {'username': 'owner', 'password': PASSWORD, 'next': 'https://evil.test/'})
        self.assertRedirects(result, '/', fetch_redirect_response=False)
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(self.client.post('/logout/').status_code, 302)
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_brute_force_is_locked_out(self):
        for _ in range(5):
            result = self.client.post('/login/', {'username': 'owner', 'password': 'wrong'})
        self.assertEqual(result.status_code, 429)
        self.assertContains(result, '۱۵ دقیقه', status_code=429)
        self.assertEqual(self.client.post('/login/', {'username': 'owner', 'password': PASSWORD}).status_code, 429)


@override_settings(**PROVIDER)
class PublicationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('owner', password=PASSWORD)
        cls.zone = Zone.objects.create(owner=cls.user, name='example.com')
        Record.objects.create(zone=cls.zone, name='@', type='A', content='192.0.2.1', enabled=False)

    def remote(self, **extra):
        return {'account': f'orbit-{self.zone.external_id}', 'rrsets': [], **extra}

    @patch('requests.Session.request')
    def test_new_zone_created_then_records_published(self, request):
        request.side_effect = [response(404), response(201, {}), response(200, self.remote()), response(204)]
        publish_zone(self.zone, self.user, 1)
        self.zone.refresh_from_db()
        self.assertTrue(self.zone.provisioned)
        self.assertEqual(self.zone.status, 'published')
        self.assertIsNone(self.zone.publish_token)
        self.assertEqual(request.call_args_list[1].kwargs['json']['account'], f'orbit-{self.zone.external_id}')
        rrsets = request.call_args_list[-1].kwargs['json']['rrsets']
        self.assertEqual(next(item for item in rrsets if item['type'] == 'A')['records'][0]['disabled'], True)
        self.assertEqual(len(next(item for item in rrsets if item['type'] == 'NS')['records']), 2)

    @patch('requests.Session.request')
    def test_reconcile_removes_deleted_supported_rrset_but_preserves_soa_and_unknown(self, request):
        request.side_effect = [response(200, self.remote(rrsets=[
            {'name': 'old.example.com.', 'type': 'MX'}, {'name': 'example.com.', 'type': 'SOA'}, {'name': 'example.com.', 'type': 'DNSKEY'},
        ])), response(204)]
        publish_zone(self.zone, self.user, 1)
        rrsets = request.call_args.kwargs['json']['rrsets']
        self.assertIn({'name': 'old.example.com.', 'type': 'MX', 'changetype': 'DELETE'}, rrsets)
        self.assertFalse(any(item['type'] in ('SOA', 'DNSKEY') for item in rrsets))

    @patch('requests.Session.request')
    def test_foreign_zone_not_overwritten(self, request):
        request.return_value = response(200, {'account': 'someone-else', 'rrsets': []})
        with self.assertRaises(ProviderError):
            publish_zone(self.zone, self.user, 1)
        self.assertEqual(request.call_count, 1)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, 'error')
        self.assertIsNone(self.zone.publishing_until)

    @patch('requests.Session.request')
    def test_patch_failure_keeps_draft_and_allows_owned_retry(self, request):
        request.side_effect = [response(200, self.remote()), response(422)]
        with self.assertRaises(ProviderError):
            publish_zone(self.zone, self.user, 1)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.published_revision, 0)
        self.assertTrue(self.zone.last_error)
        request.side_effect = [response(200, self.remote()), response(204)]
        publish_zone(self.zone, self.user, 1)
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.status, 'published')

    @patch('requests.Session.request')
    def test_connection_error_does_not_leak_secret(self, request):
        request.side_effect = requests.ConnectionError('sensitive-api-key / private URL')
        with self.assertRaises(ProviderError) as error:
            publish_zone(self.zone, self.user, 1)
        self.assertNotIn('sensitive', str(error.exception))
        self.assertNotIn('test-key', str(error.exception))

    @patch('requests.Session.request')
    def test_owned_zone_deletion_also_removes_local_data(self, request):
        request.side_effect = [response(200, self.remote()), response(204)]
        pk = self.zone.pk
        delete_zone(self.zone, self.user)
        self.assertFalse(Zone.objects.filter(pk=pk).exists())
        self.assertEqual(request.call_args.args[0], 'DELETE')
        self.assertTrue(Activity.objects.filter(action='حذف دامنه', zone=None).exists())

    @patch('requests.Session.request')
    def test_failed_remote_delete_preserves_local_data(self, request):
        request.side_effect = [response(200, self.remote()), response(500)]
        with self.assertRaises(ProviderError):
            delete_zone(self.zone, self.user)
        self.zone.refresh_from_db()
        self.assertIsNone(self.zone.publish_token)
        self.assertEqual(self.zone.records.count(), 1)

    @patch('requests.Session.request')
    def test_busy_and_stale_versions_never_publish(self, request):
        Zone.objects.filter(pk=self.zone.pk).update(publishing_until=timezone.now() + timedelta(minutes=2))
        with self.assertRaises(ZoneBusy):
            publish_zone(self.zone, self.user, 1)
        with self.assertRaises(ZoneBusy):
            editable_zone(self.zone.pk, self.user)
        Zone.objects.filter(pk=self.zone.pk).update(publishing_until=None, revision=2)
        with self.assertRaises(ZoneBusy):
            publish_zone(self.zone, self.user, 1)
        request.assert_not_called()

    @override_settings(PDNS_API_KEY='')
    def test_missing_configuration(self):
        with self.assertRaises(ProviderError):
            PowerDNS()

    @override_settings(DNS_NAMESERVERS=['ns1.example.net.', 'ns2.example.net.'])
    @patch('requests.Session.request')
    def test_placeholder_nameservers_cannot_publish(self, request):
        with self.assertRaises(ProviderError):
            publish_zone(self.zone, self.user, 1)
        request.assert_not_called()


class ProxyTests(SimpleTestCase):
    @override_settings(TRUST_PROXY=False)
    def test_untrusted_header_ignored(self):
        request = RequestFactory().get('/', REMOTE_ADDR='192.0.2.1', HTTP_X_REAL_IP='203.0.113.1')
        self.assertEqual(client_ip(request), '192.0.2.1')

    @override_settings(TRUST_PROXY=True)
    def test_trusted_proxy_header_and_invalid_values(self):
        request = RequestFactory().get('/', REMOTE_ADDR='127.0.0.1', HTTP_X_REAL_IP='2001:db8::1')
        self.assertEqual(client_ip(request), '2001:db8::1')
        request.META['HTTP_X_REAL_IP'] = 'not-an-ip'
        self.assertIsNone(client_ip(request))


class HTTPContractTests(TestCase):
    def test_real_http_create_patch_health_and_delete(self):
        state = {'zone': None, 'patch': None, 'authorized': True}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def answer(self, code, body=None):
                state['authorized'] &= self.headers.get('X-API-Key') == 'test-key'
                self.send_response(code)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                if body is not None:
                    self.wfile.write(json.dumps(body).encode())

            def do_GET(self):
                if self.path.endswith('/servers/localhost'):
                    self.answer(200, {'id': 'localhost'})
                else:
                    self.answer(200, state['zone']) if state['zone'] else self.answer(404)

            def do_POST(self):
                state['zone'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                state['zone']['rrsets'] = []
                self.answer(201, state['zone'])

            def do_PATCH(self):
                state['patch'] = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                state['zone']['rrsets'] = [dict(row) for row in state['patch']['rrsets'] if row['changetype'] == 'REPLACE']
                self.answer(204)

            def do_DELETE(self):
                state['zone'] = None
                self.answer(204)

        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with override_settings(PDNS_API_URL=f'http://127.0.0.1:{server.server_port}/api/v1', PDNS_API_KEY='test-key', DNS_NAMESERVERS=['ns1.dns.test.', 'ns2.dns.test.']):
                user = User.objects.create_user('integration')
                zone = Zone.objects.create(owner=user, name='integration.test')
                Record.objects.create(zone=zone, name='@', type='TXT', content='hello "DNS"')
                PowerDNS().health()
                publish_zone(zone, user, 1)
                self.assertTrue(state['authorized'])
                self.assertEqual(state['patch']['rrsets'][0]['records'][0]['content'], '"hello \\"DNS\\""')
                delete_zone(zone, user)
                self.assertIsNone(state['zone'])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
