#!/usr/bin/env python3
"""ORDER SOC: read-only abuse.ch ThreatFox and URLhaus collection.
Never downloads malware samples, changes FortiGate, or writes to GitHub.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/'
URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'


def retrieve_json(url, key, payload=None):
    headers = {'Auth-Key': key, 'Accept': 'application/json', 'User-Agent': 'OrderSOC-IOC-Pilot/1.0'}
    if payload is not None:
        payload = json.dumps(payload).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    request = Request(url, headers=headers, data=payload, method='POST' if payload else 'GET')
    try:
        with urlopen(request, timeout=35) as response:
            raw = response.read(15_000_000 + 1)
        if len(raw) > 15_000_000:
            raise ValueError('Respuesta supera el limite de seguridad de 15 MB')
        return json.loads(raw)
    except (HTTPError, URLError, ValueError, json.JSONDecodeError) as ex:
        raise RuntimeError(f'Fallo consulta a {url.split("/")[2]}: {type(ex).__name__}: {ex}') from ex


def collect(auth_key, days=1):
    threatfox = retrieve_json(THREATFOX_API, auth_key, {'query': 'get_iocs', 'days': days})
    urlhaus = retrieve_json(URLHAUS_API, auth_key)
    for label, payload, field in [('ThreatFox', threatfox, 'data'), ('URLhaus', urlhaus, 'urls')]:
        if not isinstance(payload, dict) or payload.get('query_status') not in ('ok', 'no_results'):
            raise RuntimeError(f'{label}: respuesta inesperada: {repr(payload)[:200]}')
        if payload.get('query_status') == 'ok' and not isinstance(payload.get(field), list):
            raise RuntimeError(f'{label}: no hay arreglo {field}')
    return {
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'sources': ['ThreatFox', 'URLhaus'],
        'threatfox': threatfox.get('data') or [],
        'urlhaus': urlhaus.get('urls') or [],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='build/raw_iocs.json')
    parser.add_argument('--days', type=int, default=1, choices=range(1, 8))
    args = parser.parse_args()
    key = os.getenv('ABUSECH_AUTH_KEY', '').strip()
    if not key:
        sys.exit('ERROR: falta ABUSECH_AUTH_KEY. Configure GitHub Actions Secret y revise licencia/condiciones.')
    data = collect(key, args.days)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"Recolectados: ThreatFox={len(data['threatfox'])}, URLhaus={len(data['urlhaus'])} -> {target}")


if __name__ == '__main__':
    main()
