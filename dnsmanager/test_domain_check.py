from unittest.mock import patch

import dns.name
import dns.resolver
from django.core.cache import cache
from django.test import TestCase, SimpleTestCase, override_settings, Client

from .domain_check import check_domain, query_nameservers
from .models import Zone, Record
from .tests import User, PASSWORD, TEST_STORAGES

GROUPS = [['ns1.melkata.ir.', 'ns2.melkata.ir.'], ['ns1.ezfile.ir.', 'ns2.ezfile.ir.']]


def answer(names, address='1.1.1.1', status='ok'):
    return {'resolver': address, 'status': status, 'nameservers': names}


@override_settings(DNS_CHECK_NS_GROUPS=GROUPS, DNS_CHECK_NAMESERVERS=[])
class DomainResolutionTests(SimpleTestCase):
    def setUp(self):
        cache.clear()

    @patch('dnsmanager.domain_check.query_nameservers')
    def test_each_complete_pair_and_all_four_are_accepted(self, query):
        for index, names in enumerate([GROUPS[0], GROUPS[1], sorted(GROUPS[0] + GROUPS[1])]):
            query.side_effect = [answer(names), answer(names, '8.8.8.8')]
            result = check_domain(f'pair{index}.test')
            self.assertEqual(result['status'], 'matched')
            self.assertEqual(result['found'], names)

    @patch('dnsmanager.domain_check.query_nameservers')
    def test_foreign_or_incomplete_or_mixed_pair_is_not_accepted(self, query):
        for index, names in enumerate([GROUPS[0] + ['ns.attacker.test.'], [GROUPS[0][0]], [GROUPS[0][0], GROUPS[1][1]]]):
            query.side_effect = [answer(sorted(names)), answer(sorted(names), '8.8.8.8')]
            self.assertEqual(check_domain(f'wrong{index}.test')['status'], 'mismatch')

    @patch('dnsmanager.domain_check.query_nameservers')
    def test_disagreeing_resolvers_are_inconclusive(self, query):
        query.side_effect = [answer(GROUPS[0]), answer(GROUPS[1], '8.8.8.8')]
        self.assertEqual(check_domain('split.test')['status'], 'propagating')

    @patch('dnsmanager.domain_check.query_nameservers')
    def test_partial_failure_does_not_report_match(self, query):
        query.side_effect = [answer(GROUPS[0]), answer([], '8.8.8.8', 'unavailable')]
        self.assertEqual(check_domain('timeout.test')['status'], 'unavailable')

    @patch('dnsmanager.domain_check.query_nameservers')
    def test_results_are_cached_without_repeating_network_calls(self, query):
        query.side_effect = [answer(GROUPS[0]), answer(GROUPS[0], '8.8.8.8')]
        self.assertFalse(check_domain('cached.test')['cached'])
        self.assertTrue(check_domain('cached.test')['cached'])
        self.assertEqual(query.call_count, 2)

    @patch('dnsmanager.domain_check.dns.resolver.Resolver')
    def test_dns_queries_do_not_use_local_authoritative_service(self, resolver_class):
        resolver = resolver_class.return_value
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        self.assertEqual(query_nameservers('missing.test', '1.1.1.1')['status'], 'not_found')
        resolver_class.assert_called_once_with(configure=False)
        self.assertEqual(resolver.nameservers, ['1.1.1.1'])
        resolver.resolve.assert_called_once_with('missing.test.', 'NS', search=False, lifetime=5)

    @patch('dnsmanager.domain_check.dns.resolver.Resolver')
    def test_alias_cannot_masquerade_as_matching_delegation(self, resolver_class):
        resolver_class.return_value.resolve.return_value.canonical_name = dns.name.from_text('different.test.')
        self.assertEqual(query_nameservers('alias.test', '1.1.1.1')['status'], 'alias')


@override_settings(STORAGES=TEST_STORAGES)
class DomainCheckPagesTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user('domain-check-owner', password=PASSWORD)
        cls.other = User.objects.create_user('domain-check-other', password=PASSWORD)
        cls.zone = Zone.objects.create(owner=cls.user, name='site.test')
        cls.foreign = Zone.objects.create(owner=cls.other, name='foreign.test')

    def setUp(self):
        self.client.force_login(self.user)
        cache.clear()

    def result(self, domain='checked.test', status='matched'):
        return {'domain': domain, 'expected': GROUPS[0] + GROUPS[1], 'expected_groups': GROUPS, 'found': GROUPS[0],
                'answers': [answer(GROUPS[0]), answer(GROUPS[0], '8.8.8.8')], 'status': status,
                'label': 'NSها مطابق‌اند' if status == 'matched' else 'NSها متفاوت‌اند', 'checked_at': '2026-10-17T14:00:00+00:00', 'cached': False}

    @patch('dnsmanager.domain_check.check_domain')
    def test_matching_domain_added_as_draft_with_original_nameservers(self, check):
        check.return_value = self.result()
        result = self.client.post('/domains/check/', {'name': 'checked.test', 'add_on_match': 'on'}, HTTP_ACCEPT='application/json')
        self.assertTrue(result.json()['result']['added'])
        zone = Zone.objects.get(name='checked.test')
        self.assertEqual(zone.owner, self.user)
        self.assertEqual(zone.status, 'draft')
        self.assertEqual(zone.nameservers, GROUPS[0])
        self.assertEqual(zone.records.count(), 0)
        self.assertEqual(zone.ns_check['status'], 'matched')

    @patch('dnsmanager.domain_check.check_domain')
    def test_mismatch_and_unchecked_add_checkbox_do_not_create_zone(self, check):
        check.return_value = self.result(status='mismatch')
        self.client.post('/domains/check/', {'name': 'checked.test', 'add_on_match': 'on'}, HTTP_ACCEPT='application/json')
        self.assertFalse(Zone.objects.filter(name='checked.test').exists())
        cache.clear()
        check.return_value = self.result()
        self.client.post('/domains/check/', {'name': 'checked.test'}, HTTP_ACCEPT='application/json')
        self.assertFalse(Zone.objects.filter(name='checked.test').exists())

    @patch('dnsmanager.domain_check.check_domain')
    def test_foreign_zone_cannot_be_taken_over_or_checked_by_id(self, check):
        check.return_value = self.result(domain='foreign.test')
        result = self.client.post('/domains/check/', {'name': 'foreign.test', 'add_on_match': 'on'}, HTTP_ACCEPT='application/json')
        self.assertNotIn('zone_url', result.json()['result'])
        self.foreign.refresh_from_db()
        self.assertEqual(self.foreign.owner, self.other)
        self.assertEqual(self.foreign.ns_check, {})
        self.assertEqual(self.client.post(f'/domains/{self.foreign.pk}/check/').status_code, 404)

    @patch('dnsmanager.domain_check.check_domain')
    def test_owned_domain_result_persists_and_filters(self, check):
        check.return_value = self.result(domain='site.test')
        self.client.post(f'/domains/{self.zone.pk}/check/', HTTP_ACCEPT='application/json')
        self.zone.refresh_from_db()
        self.assertEqual(self.zone.ns_check['status'], 'matched')
        self.assertContains(self.client.get('/domains/?ns=matched'), 'site.test')
        self.assertNotContains(self.client.get('/domains/?ns=mismatch'), 'site.test')

    def test_checker_is_post_only_and_domain_validation_precedes_network(self):
        self.assertEqual(self.client.get('/domains/check/').status_code, 405)
        with patch('dnsmanager.domain_check.check_domain') as check:
            result = self.client.post('/domains/check/', {'name': 'https://invalid.test/a'}, HTTP_ACCEPT='application/json')
            self.assertEqual(result.status_code, 400)
            check.assert_not_called()

    def test_checker_requires_csrf_even_when_domain_is_only_being_checked(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        with patch('dnsmanager.domain_check.check_domain') as check:
            self.assertEqual(client.post('/domains/check/', {'name': 'checked.test', 'add_on_match': 'on'}).status_code, 403)
            check.assert_not_called()

    def test_complete_record_content_details_and_safe_site_links(self):
        content = 'v=DKIM1; k=rsa; p=' + 'Abc123' * 90
        record = Record.objects.create(zone=self.zone, name='dkim._domainkey', type='TXT', content=content)
        web = Record.objects.create(zone=self.zone, name='sso', type='A', content='192.0.2.12')
        response = self.client.get(f'/domains/{self.zone.pk}/')
        self.assertContains(response, content)
        self.assertContains(response, 'dkim._domainkey.site.test')
        self.assertContains(response, 'https://sso.site.test/')
        self.assertContains(response, 'noopener noreferrer')
        self.assertEqual(record.website_url, '')
        self.assertEqual(web.website_url, 'https://sso.site.test/')
        result = self.client.get(f'/domains/{self.zone.pk}/records/{record.pk}/details/', HTTP_X_ORBIT_MODAL='1')
        self.assertIn(content, result.json()['html'])
        self.assertIn('DKIM', result.json()['html'])
        self.assertIn('نمای استاندارد DNS', result.json()['html'])
        self.assertEqual(self.client.get(f'/domains/{self.zone.pk}/records/{record.pk}/details/').status_code, 200)

    def test_record_details_are_scoped_to_owner(self):
        foreign_record = Record.objects.create(zone=self.foreign, name='@', type='A', content='192.0.2.3')
        self.assertEqual(self.client.get(f'/domains/{self.foreign.pk}/records/{foreign_record.pk}/details/', HTTP_X_ORBIT_MODAL='1').status_code, 404)
        self.assertEqual(self.client.get(f'/domains/{self.zone.pk}/records/{foreign_record.pk}/details/', HTTP_X_ORBIT_MODAL='1').status_code, 404)

    def test_full_hostname_search_and_enabled_filter(self):
        Record.objects.create(zone=self.zone, name='sso', type='A', content='192.0.2.5')
        Record.objects.create(zone=self.zone, name='off', type='A', content='192.0.2.6', enabled=False)
        result = self.client.get(f'/domains/{self.zone.pk}/?q=sso.site.test')
        self.assertContains(result, '192.0.2.5')
        self.assertNotContains(result, '192.0.2.6')
        result = self.client.get(f'/domains/{self.zone.pk}/?enabled=0')
        self.assertNotContains(result, '192.0.2.5')
        self.assertContains(result, '192.0.2.6')
