"""Read a local administrator-owned PowerDNS config without exposing secrets."""
from pathlib import Path


def local_powerdns_config(explicit_path=''):
    candidates = [Path(explicit_path)] if explicit_path else [Path('/etc/powerdns/pdns.conf'), Path('/etc/pdns/pdns.conf')]
    values = {}
    for path in candidates:
        try:
            lines = path.read_text().splitlines()
        except (OSError, UnicodeError):
            continue
        for line in lines:
            if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                values[key.strip()] = value.strip()
        includes = Path(values.get('include-dir', str(path.parent / 'pdns.d')))
        try:
            children = sorted(includes.glob('*.conf')) if includes.is_absolute() else []
        except OSError:
            children = []
        for child in children:
            try:
                for line in child.read_text().splitlines():
                    if line.strip() and not line.lstrip().startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        values[key.strip()] = value.strip()
            except (OSError, UnicodeError):
                continue
        break
    if not values.get('api-key') or values.get('api', 'yes').lower() not in ('yes', 'true', '1', 'on'):
        return {}
    address = values.get('webserver-address', '127.0.0.1')
    if address in ('0.0.0.0', '::', '[::]'):
        address = '127.0.0.1'
    if ':' in address and not address.startswith('['):
        address = f'[{address}]'
    port = values.get('webserver-port', '8081')
    if not port.isdigit():
        return {}
    return {'url': f'http://{address}:{port}/api/v1', 'key': values['api-key']}
