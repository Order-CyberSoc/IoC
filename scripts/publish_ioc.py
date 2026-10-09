#!/usr/bin/env python3
"""ORDER SOC v2: stage REVIEW ONLY feeds and merge historical IOC state. No firewall changes."""
import argparse
import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

TTL_DAYS = {'ip': 7, 'domain': 14, 'sha256': 30}
FEED_NAMES = ('ips-critical.txt', 'ips-suspicious.txt', 'domains-malicious.txt', 'hashes-sha256.txt')


def dt(value):
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (TypeError, ValueError, AttributeError):
        return None


def output_file(path, contents):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding='utf-8')


def feed_file(path, values):
    vals = sorted(set(values))
    output_file(path, '\n'.join(vals) + '\n')
    return len(vals)


def load_history(path):
    if not path.exists():
        return {'schema_version': 2, 'indicators': {}}
    previous = json.loads(path.read_text(encoding='utf-8'))
    if previous.get('schema_version') != 2 or not isinstance(previous.get('indicators'), dict):
        raise ValueError('Formato de historial inesperado, cancelando publicacion')
    return previous


def stage(data, output='build/staging', history=None, now=None):
    if data.get('schema_version') != 2:
        raise ValueError('Se requiere validated_iocs v2')
    now = now or datetime.now(timezone.utc)
    out = Path(output)
    history_file = Path(history) if history else Path('build/previous_history.json')
    prev = load_history(history_file)
    state = dict(prev['indicators'])
    fresh = set()
    new_count = 0
    for c in data['candidates']:
        kind, value = c['type'], c['value']
        key = f'{kind}|{value}'
        old = state.get(key, {})
        if not old:
            new_count += 1
        previous_ports = old.get('observed_ports', [])
        exp = (now + timedelta(days=TTL_DAYS[kind])).isoformat()
        state[key] = {
            'type': kind, 'value': value,
            'first_observed_at': old.get('first_observed_at') or now.isoformat(),
            'last_observed_at': now.isoformat(), 'expires_at': exp,
            'status': 'active',
            'classification': c['classification'],
            'max_confidence': max(c['max_confidence'], old.get('max_confidence', 0)),
            'observed_ports': sorted(set(previous_ports + c.get('ports', []))),
            'risk_flags': sorted(set(old.get('risk_flags', []) + c.get('risk_flags', []))),
            'evidence_count_latest': len(c['evidence']),
        }
        fresh.add(key)
    # Expire previously observed IOCs; retention short to avoid indefinite database growth.
    expired = 0
    for key, item in list(state.items()):
        exp = dt(item.get('expires_at'))
        if not exp or exp <= now:
            del state[key]
            expired += 1
        else:
            if key not in fresh:
                item['status'] = 'historical_within_ttl'
    ips = []
    domains = []
    hashes = []
    for key, item in state.items():
        if item['type'] == 'ip':
            ips.append(item['value'])
        elif item['type'] == 'domain' and item['classification'] == 'high_confidence_candidate':
            domains.append(item['value'])
        elif item['type'] == 'sha256':
            hashes.append(item['value'])
    # critical never auto-promoted from confidence alone
    feeds = {
        'ips-critical.txt': [],
        'ips-suspicious.txt': ips,
        'domains-malicious.txt': domains,
        'hashes-sha256.txt': hashes,
    }
    counts = {name: feed_file(out / 'feeds' / name, values) for name, values in feeds.items()}
    out_state = {'schema_version': 2, 'updated_at': now.isoformat(), 'indicators': state}
    output_file(out / 'data' / 'ioc-history.json', json.dumps(out_state, indent=2, ensure_ascii=False) + '\n')
    output_file(out / 'review' / 'ioc-candidates.json', json.dumps(data, indent=2, ensure_ascii=False) + '\n')
    output_file(out / 'review' / 'url-observations.json',
                json.dumps(data.get('url_observations', []), indent=2, ensure_ascii=False) + '\n')
    columns = ['type', 'indicator', 'classification', 'max_confidence', 'ports', 'risk_flags', 'references']
    sio = io.StringIO()
    writer = csv.DictWriter(sio, fieldnames=columns)
    writer.writeheader()
    for c in data['candidates']:
        writer.writerow({
            'type': c['type'], 'indicator': c['value'],
            'classification': c['classification'], 'max_confidence': c['max_confidence'],
            'ports': ';'.join(map(str, c.get('ports', []))),
            'risk_flags': ';'.join(c.get('risk_flags', [])),
            'references': ';'.join(sorted({str(e['reference']) for e in c['evidence'] if e.get('reference')})),
        })
    output_file(out / 'review' / 'ioc-review.csv', sio.getvalue())
    report = {
        'version': 2, 'mode': 'REVIEW_ONLY', 'applied_to_firewalls': False,
        'production_feeds_changed': False, 'counts': counts,
        'candidates_current': len(data['candidates']), 'new_in_history': new_count,
        'history_active': len(state), 'history_expired_removed': expired,
        'url_observations': len(data.get('url_observations', [])),
        'invalid_skipped': data.get('invalid_skipped', 0),
        'outside_window_skipped': data.get('outside_window_skipped', 0),
        'warning': 'Hashes y dominios en feeds de artefacto NO estan aprobados para bloqueo.'
    }
    output_file(out / 'review' / 'summary.json', json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', default='build/validated_iocs.json')
    p.add_argument('--history', default='build/previous_history.json')
    p.add_argument('--output', default='build/staging')
    args = p.parse_args()
    v = json.loads(Path(args.input).read_text(encoding='utf-8'))
    stage(v, args.output, args.history)


if __name__ == '__main__':
    main()
