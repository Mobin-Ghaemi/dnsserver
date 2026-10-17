#!/usr/bin/env python3
"""Local, authenticated PowerDNS-compatible subset for the existing static BIND zones.
Never expose this service or its key to the public network.
"""
import copy
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote, urlsplit

import dns.name
import dns.rdata
import dns.rdataset
import dns.zone

ROOT = Path('/etc/bind/startup')
STATE = Path('/var/lib/orbit-bind')
PATTERN = re.compile(r'zone\s+"([a-zA-Z0-9.-]+)"\s*\{\s*type\s+(?:primary|master);\s*file\s+"([^"]+)";\s*\};')


def atomic(path, content, mode=0o644):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.orbit-')
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def command(*args):
    subprocess.run(args, check=True, capture_output=True, timeout=10)


def catalog():
    result = {}
    for config in (ROOT / 'zones.conf', ROOT / 'customers.conf', ROOT / 'orbit.conf'):
        if not config.exists():
            continue
        for match in PATTERN.finditer(config.read_text()):
            name, filename = match.groups()
            path = Path(filename).resolve()
            if not path.is_relative_to(ROOT.resolve()) or path.is_symlink():
                raise ValueError('Unsupported zone path')
            result[name.lower()] = (path, config, match.group())
    return result


def valid_name(name):
    name = name.rstrip('.').lower()
    if len(name) > 253 or '.' not in name or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in name.split('.')):
        raise ValueError('Invalid zone name')
    return name


def metadata(name):
    path = STATE / (name + '.json')
    return json.loads(path.read_text()) if path.exists() else {}


def read_zone(name):
    path, _, _ = catalog()[name]
    zone = dns.zone.from_file(str(path), origin=name + '.', relativize=False, allow_include=False)
    rrsets = []
    for owner, node in zone.nodes.items():
        for dataset in node.rdatasets:
            rrsets.append({'name': owner.to_text(), 'type': dns.rdatatype.to_text(dataset.rdtype),
                           'ttl': dataset.ttl, 'records': [{'content': value.to_text(), 'disabled': False} for value in dataset]})
    meta = metadata(name)
    if meta.get('file_hash') == hashlib.sha256(path.read_bytes()).hexdigest():
        for disabled in meta.get('disabled', []):
            row = next((r for r in rrsets if (r['name'], r['type']) == (disabled['name'], disabled['type'])), None)
            if row is None:
                row = {'name': disabled['name'], 'type': disabled['type'], 'ttl': disabled['ttl'], 'records': []}
                rrsets.append(row)
            row['records'].extend(disabled['records'])
    return {'id': name + '.', 'name': name + '.', 'kind': 'Native', 'account': meta.get('account', ''), 'rrsets': rrsets}


def render_zone(name, rrsets):
    origin = dns.name.from_text(name + '.')
    zone = dns.zone.Zone(origin, relativize=False)
    disabled = []
    seen = set()
    for row in rrsets:
        owner = dns.name.from_text(row['name'])
        if not owner.is_subdomain(origin):
            raise ValueError('Owner outside zone')
        kind = dns.rdatatype.from_text(row['type'])
        key = (owner, kind)
        if key in seen:
            raise ValueError('Duplicate RRset')
        seen.add(key)
        ttl = row['ttl']
        if not isinstance(ttl, int) or not 0 <= ttl <= 2147483647:
            raise ValueError('Invalid TTL')
        dataset = dns.rdataset.Rdataset(dns.rdataclass.IN, kind)
        off = []
        for record in row['records']:
            value = dns.rdata.from_text('IN', kind, record['content'], origin=origin, relativize=False)
            if record.get('disabled', False):
                off.append({'content': value.to_text(), 'disabled': True})
            else:
                dataset.add(value, ttl)
        if off:
            disabled.append({'name': owner.to_text(), 'type': row['type'], 'ttl': ttl, 'records': off})
        if dataset:
            zone.replace_rdataset(owner, dataset)
    zone.check_origin()
    soa = zone.get_rdataset(origin, 'SOA')
    updated = soa[0].replace(serial=(soa[0].serial + 1) % 4294967296)
    zone.replace_rdataset(origin, dns.rdataset.from_rdata(soa.ttl, updated))
    return zone.to_text(relativize=False), disabled


def apply(name, rrsets=None, account=None, delete=False):
    zones = catalog()
    existing = name in zones
    path, config, statement = zones.get(name, (ROOT / 'customers' / ('db.' + name), ROOT / 'orbit.conf', ''))
    # Every mutation retains recoverable copies before validation/reload.
    backup = STATE / 'backups' / (str(time.time_ns()) + '-' + name)
    backup.mkdir(parents=True, mode=0o700)
    old_config = config.read_text() if config.exists() else ''
    old_zone = path.read_text() if path.exists() else None
    (backup / 'config').write_text(old_config)
    if old_zone is not None:
        (backup / 'zone').write_text(old_zone)
    meta_path = STATE / (name + '.json')
    if meta_path.exists():
        (backup / 'metadata.json').write_bytes(meta_path.read_bytes())
    if not delete:
        text, disabled = render_zone(name, rrsets)
        trial = backup / 'candidate.zone'
        trial.write_text(text)
        command('named-checkzone', name, str(trial))
    try:
        if delete:
            atomic(config, old_config.replace(statement, ''))
        else:
            atomic(path, text)
            if not existing:
                atomic(config, old_config + f'\nzone "{name}" {{ type primary; file "{path}"; }};\n')
        command('named-checkconf')
        command('rndc', 'reconfig')
        if existing and not delete:
            command('rndc', 'reload', name)
    except Exception:
        atomic(config, old_config)
        if old_zone is not None:
            atomic(path, old_zone)
        elif path.exists():
            path.unlink()
        command('rndc', 'reconfig')
        if existing:
            command('rndc', 'reload', name)
        raise
    if delete:
        # Keep the old file as an additional backup; remove only the active declaration.
        meta_path.unlink(missing_ok=True)
    else:
        atomic(meta_path, json.dumps({'account': account or '', 'disabled': disabled,
               'file_hash': hashlib.sha256(path.read_bytes()).hexdigest()}), mode=0o600)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self): self.handle_api()
    def do_POST(self): self.handle_api()
    def do_PATCH(self): self.handle_api()
    def do_DELETE(self): self.handle_api()

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_api(self):
        self.connection.settimeout(10)
        if not hmac.compare_digest(self.headers.get('X-API-Key', ''), os.environ['BIND_BRIDGE_KEY']):
            return self.respond(403, {'error': 'Forbidden'})
        try:
            prefix = '/api/v1/servers/localhost'
            route = unquote(urlsplit(self.path).path)
            if route == prefix and self.command == 'GET':
                return self.respond(200, {'id': 'localhost', 'daemon_type': 'authoritative', 'version': 'BIND bridge'})
            if route == prefix + '/zones':
                if self.command == 'GET':
                    return self.respond(200, [{'name': n + '.', 'kind': 'Native'} for n in sorted(catalog())])
                if self.command != 'POST':
                    return self.respond(405, {})
                body = self.body()
                name = valid_name(body['name'])
                if name in catalog():
                    return self.respond(409, {})
                nameservers = body['nameservers']
                origin = dns.name.from_text(name + '.')
                if len(nameservers) < 2:
                    raise ValueError('At least two nameservers required')
                nameservers = [dns.name.from_text(n).to_text() for n in nameservers]
                rows = [{'name': origin.to_text(), 'type': 'NS', 'ttl': 3600,
                         'records': [{'content': n, 'disabled': False} for n in nameservers]},
                        {'name': origin.to_text(), 'type': 'SOA', 'ttl': 3600,
                         'records': [{'content': f'{nameservers[0]} hostmaster.{name}. 1 3600 600 1209600 300', 'disabled': False}]}]
                apply(name, rows, body.get('account', ''))
                return self.respond(201, read_zone(name))
            if not route.startswith(prefix + '/zones/'):
                return self.respond(404, {})
            name = valid_name(route[len(prefix + '/zones/'):])
            if name not in catalog():
                return self.respond(404, {})
            if self.command == 'GET':
                return self.respond(200, read_zone(name))
            if self.command == 'DELETE':
                apply(name, delete=True)
                return self.respond(200, {})
            if self.command != 'PATCH':
                return self.respond(405, {})
            current = read_zone(name)
            rows = copy.deepcopy(current['rrsets'])
            for row in self.body()['rrsets']:
                if row['type'] in ('SOA', 'DNSKEY', 'RRSIG', 'NSEC', 'NSEC3'):
                    raise ValueError('Protected record type')
                key = (row['name'], row['type'])
                rows = [r for r in rows if (r['name'], r['type']) != key]
                if row['changetype'] == 'REPLACE':
                    rows.append(row)
                elif row['changetype'] != 'DELETE':
                    raise ValueError('Invalid change type')
            apply(name, rows, current['account'])
            return self.respond(200, {})
        except (ValueError, KeyError, TypeError, dns.exception.DNSException):
            return self.respond(422, {'error': 'Invalid DNS payload'})
        except Exception:
            logging.exception('BIND bridge operation failed')
            return self.respond(500, {'error': 'BIND operation failed; inspect local service logs'})

    def body(self):
        size = int(self.headers.get('Content-Length', '0'))
        if not 0 < size <= 1024 * 1024:
            raise ValueError('Invalid request size')
        return json.loads(self.rfile.read(size))


if __name__ == '__main__':
    if len(os.environ.get('BIND_BRIDGE_KEY', '')) < 32:
        raise RuntimeError('A strong BIND_BRIDGE_KEY is required')
    STATE.mkdir(exist_ok=True, mode=0o700)
    HTTPServer(('127.0.0.1', 18081), Handler).serve_forever()
