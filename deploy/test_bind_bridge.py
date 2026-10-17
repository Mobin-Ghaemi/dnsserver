"""Isolated bridge tests; never touch the live BIND installation."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('bridge', Path(__file__).with_name('bind_bridge.py'))
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'bind'
        self.root.mkdir(); (self.root / 'customers').mkdir()
        self.state = Path(self.tmp.name) / 'state'; self.state.mkdir()
        (self.root / 'orbit.conf').write_text('')
        for name, value in [('ROOT', self.root), ('STATE', self.state)]:
            p = patch.object(bridge, name, value); p.start(); self.addCleanup(p.stop)
        self.commands = patch.object(bridge, 'command'); self.command = self.commands.start()
        self.addCleanup(self.commands.stop)
        self.rows = [
            {'name': 'example.test.', 'type': 'SOA', 'ttl': 300, 'records': [{'content': 'ns1.example.test. hostmaster.example.test. 1 3600 600 1209600 300'}]},
            {'name': 'example.test.', 'type': 'NS', 'ttl': 300, 'records': [{'content': 'ns1.example.test.'}, {'content': 'ns2.example.test.'}]},
            {'name': 'app.example.test.', 'type': 'A', 'ttl': 300, 'records': [{'content': '192.0.2.10'}, {'content': '192.0.2.11', 'disabled': True}]},
        ]

    def test_create_read_disabled_and_delete(self):
        bridge.apply('example.test', self.rows, 'orbit-test')
        remote = bridge.read_zone('example.test')
        self.assertEqual(remote['account'], 'orbit-test')
        self.assertTrue(any(r.get('disabled') for row in remote['rrsets'] for r in row['records']))
        zonefile = bridge.catalog()['example.test'][0]
        self.assertNotIn('192.0.2.11', zonefile.read_text())
        bridge.apply('example.test', delete=True)
        self.assertNotIn('example.test', bridge.catalog())

    def test_reload_failure_restores_config_and_zone(self):
        bridge.apply('example.test', self.rows, 'orbit-test')
        path, config, _ = bridge.catalog()['example.test']
        old = path.read_bytes(), config.read_bytes()
        def fail_once(*args):
            if args == ('rndc', 'reload', 'example.test'):
                self.command.side_effect = None
                raise subprocess.CalledProcessError(1, args)
        self.command.side_effect = fail_once
        with self.assertRaises(subprocess.CalledProcessError):
            bridge.apply('example.test', self.rows, 'orbit-test')
        self.assertEqual((path.read_bytes(), config.read_bytes()), old)

    def test_out_of_zone_owner_and_invalid_ip_do_not_write(self):
        self.rows[-1]['name'] = 'foreign.test.'
        with self.assertRaises(ValueError):
            bridge.apply('example.test', self.rows)
        self.assertNotIn('example.test', bridge.catalog())
        self.rows[-1]['name'] = 'app.example.test.'
        self.rows[-1]['records'][0]['content'] = 'bad-ip'
        with self.assertRaises(bridge.dns.exception.DNSException):
            bridge.apply('example.test', self.rows)
        self.assertNotIn('example.test', bridge.catalog())

    def test_external_edit_discards_stale_disabled_overlay(self):
        bridge.apply('example.test', self.rows, 'orbit-test')
        path = bridge.catalog()['example.test'][0]
        path.write_text(path.read_text() + '\n; external change\n')
        remote = bridge.read_zone('example.test')
        self.assertFalse(any(r.get('disabled') for row in remote['rrsets'] for r in row['records']))


if __name__ == '__main__':
    unittest.main()
