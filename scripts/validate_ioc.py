#!/usr/bin/env python3
"""ORDER SOC: validate and classify candidate IOCs (no blocking decisions)."""
import argparse
import ipaddress
import json
import re
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlsplit

HASH256 = re.compile(r'^[0-9a-fA-F]{64}$')
DOMAIN = re.compile(r'^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$')


def ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        return str(ip) if ip.version == 4 and ip.is_global else None
    except ValueError:
        return None


def domain(value):
    try:
        normalized = str(value).strip().rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        return None
    return normalized if DOMAIN.fullmatch(normalized) and not normalized.endswith('.onion') else None


def first_seen(value):
    if not value:
        return None
    try:
        cleaned = str(value).strip().replace(' UTC', '+00:00').replace('Z', '+00:00')
        ts = datetime.fromisoformat(cleaned)
        return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    except ValueError:
        return None


def collect_candidates(raw, now=None):
    now = now or datetime.now(timezone.utc)
    candidates = {}
    url_observations = []
    invalid = 0
    for item in raw.get('threatfox', []):
        typ = str(item.get('ioc_type', '')).lower()
        value = str(item.get('ioc', '')).strip()
        port = None
        if typ == 'ip:port':
            parts = value.rsplit(':', 1)
            if len(parts) != 2 or not parts[1].isdigit() or not 1 <= int(parts[1]) <= 65535:
                invalid += 1
                continue
            port = int(parts[1])
            value = parts[0]
            kind = 'ip'
            normalized = ipv4(value)
        elif typ == 'domain':
            kind = 'domain'
            normalized = domain(value)
        elif typ in ('sha256_hash', 'sha256'):
            kind = 'sha256'
            normalized = value.lower() if HASH256.fullmatch(value) else None
        elif typ in ('url', 'domain:port'):
            url_observations.append({'source': 'ThreatFox', 'value': value, 'reference': item.get('reference')})
            continue
        else:
            continue
        if not normalized:
            invalid += 1
            continue
        observed = first_seen(item.get('first_seen'))
        if observed and (observed > now + timedelta(hours=6) or observed < now - timedelta(days=7)):
            continue
        confidence = int(item.get('confidence_level') or 0)
        threat = str(item.get('threat_type', 'unknown'))
        key = (kind, normalized)
        evidence = {'source': 'ThreatFox', 'reference': item.get('reference'), 'ioc_id': item.get('id'),
                    'ioc_type': typ, 'port': port, 'threat_type': threat, 'confidence': confidence,
                    'first_seen': observed.isoformat() if observed else None}
        entry = candidates.setdefault(key, {'type': kind, 'value': normalized, 'max_confidence': 0,
                                            'classification': 'review', 'evidence': []})
        entry['max_confidence'] = max(entry['max_confidence'], confidence)
        entry['evidence'].append(evidence)
        # High confidence remains a REVIEW CANDIDATE. Never auto-approve IP-wide blocking.
        if confidence >= 90 and threat == 'botnet_cc' and observed:
            entry['classification'] = 'high_confidence_candidate'

    for item in raw.get('urlhaus', []):
        value = str(item.get('url') or '')
        try:
            parsed = urlsplit(value)
        except ValueError:
            invalid += 1
            continue
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            invalid += 1
            continue
        host = ipv4(parsed.hostname) or domain(parsed.hostname)
        if not host:
            invalid += 1
            continue
        # NEVER promote a URLhaus URL's shared host/IP to a host-wide block automatically.
        url_observations.append({'source': 'URLhaus', 'url': value, 'host': host,
                                 'status': item.get('url_status'), 'first_seen': item.get('date_added'),
                                 'reference': item.get('urlhaus_reference')})
    return {
        'validated_at': now.isoformat(),
        'candidates': sorted(candidates.values(), key=lambda e: (e['type'], e['value'])),
        'url_observations': url_observations,
        'invalid_skipped': invalid,
        'safety': 'Todos los IOC son candidatos. Sin aprobacion automatica de bloqueos.'
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='build/raw_iocs.json')
    parser.add_argument('--output', default='build/validated_iocs.json')
    args = parser.parse_args()
    raw = json.loads(Path(args.input).read_text(encoding='utf-8'))
    result = collect_candidates(raw)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"Candidatos: {len(result['candidates'])}; URLs observadas: {len(result['url_observations'])}; "
          f"invalidos: {result['invalid_skipped']}")


if __name__ == '__main__':
    main()
