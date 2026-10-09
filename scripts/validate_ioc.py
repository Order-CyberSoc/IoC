#!/usr/bin/env python3
"""ORDER SOC v2: validate/normalize ThreatFox and URLhaus IOCs. REVIEW ONLY."""
import argparse
import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

HASH256 = re.compile(r"^[0-9a-fA-F]{64}$")
DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
SHARED_SUFFIXES = (
    "workers.dev", "pages.dev", "googleusercontent.com", "cloudfront.net",
    "azurewebsites.net", "amazonaws.com", "github.io", "vercel.app",
    "netlify.app", "wpenginepowered.com", "herokuapp.com",
)


def normalize_ip(value):
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(ip) if ip.version == 4 and ip.is_global else None


def normalize_domain(value):
    try:
        name = str(value).strip().rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return None
    return name if DOMAIN.fullmatch(name) and not name.endswith('.onion') else None


def parse_time(value):
    if not value:
        return None
    try:
        cleaned = str(value).strip().replace(' UTC', '+00:00').replace('Z', '+00:00')
        dt = datetime.fromisoformat(cleaned)
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def classify(kind, confidence, threat):
    if kind == 'sha256':
        return 'malware_hash_review'
    if confidence >= 90 and threat == 'botnet_cc':
        return 'high_confidence_candidate'
    return 'review'


def validate(raw, now=None):
    now = now or datetime.now(timezone.utc)
    if not isinstance(raw, dict) or not isinstance(raw.get('threatfox'), list) or not isinstance(raw.get('urlhaus'), list):
        raise ValueError('Payload no contiene las listas threatfox y urlhaus')
    records = {}
    urls = []
    invalid = 0
    skipped_outside_window = 0
    for item in raw['threatfox']:
        if not isinstance(item, dict):
            invalid += 1
            continue
        original = str(item.get('ioc') or '').strip()
        ioc_type = str(item.get('ioc_type') or '').lower()
        port = None
        if ioc_type == 'ip:port':
            parts = original.rsplit(':', 1)
            if len(parts) != 2 or not parts[1].isdigit() or not 1 <= int(parts[1]) <= 65535:
                invalid += 1
                continue
            value = normalize_ip(parts[0])
            kind = 'ip'
            port = int(parts[1])
        elif ioc_type == 'domain':
            kind = 'domain'
            value = normalize_domain(original)
        elif ioc_type in ('sha256_hash', 'sha256'):
            kind = 'sha256'
            value = original.lower() if HASH256.fullmatch(original) else None
        elif ioc_type in ('url', 'domain:port'):
            # Kept as evidence only. Never promote a path or host to global blocking.
            urls.append({'source': 'ThreatFox', 'value': original, 'reference': item.get('reference')})
            continue
        else:
            continue
        if not value:
            invalid += 1
            continue
        source_first_seen = parse_time(item.get('first_seen'))
        if source_first_seen and (source_first_seen > now + timedelta(hours=6) or
                                  source_first_seen < now - timedelta(days=7)):
            skipped_outside_window += 1
            continue
        try:
            confidence = max(0, min(100, int(item.get('confidence_level') or 0)))
        except (ValueError, TypeError):
            confidence = 0
        threat = str(item.get('threat_type') or 'unknown')
        risk_flags = []
        if kind == 'ip':
            risk_flags.append('ip_wide_block_requires_analyst_approval')
            if port is not None:
                risk_flags.append('reported_as_ip_port_only')
        if kind == 'domain' and any(value == suffix or value.endswith('.' + suffix) for suffix in SHARED_SUFFIXES):
            risk_flags.append('shared_hosting_domain_exact_match_only')
        if kind == 'sha256':
            risk_flags.append('file_inspection_required')
        if not item.get('reference'):
            risk_flags.append('no_independent_reference')
        key = (kind, value)
        entry = records.setdefault(key, {
            'type': kind, 'value': value, 'classification': 'review', 'max_confidence': 0,
            'ports': [], 'risk_flags': [], 'evidence': []
        })
        entry['max_confidence'] = max(entry['max_confidence'], confidence)
        entry['risk_flags'] = sorted(set(entry['risk_flags'] + risk_flags))
        if port is not None and port not in entry['ports']:
            entry['ports'].append(port)
        entry['evidence'].append({
            'source': 'ThreatFox', 'ioc_id': item.get('id'), 'ioc_type': ioc_type,
            'reference': item.get('reference'), 'original_indicator': original,
            'port': port, 'threat_type': threat, 'confidence': confidence,
            'source_first_seen': source_first_seen.isoformat() if source_first_seen else None,
            'source_last_seen': item.get('last_seen'),
        })
        if classify(kind, confidence, threat) == 'high_confidence_candidate':
            entry['classification'] = 'high_confidence_candidate'
        elif kind == 'sha256':
            entry['classification'] = 'malware_hash_review'

    for item in raw['urlhaus']:
        if not isinstance(item, dict):
            invalid += 1
            continue
        value = str(item.get('url') or '').strip()
        try:
            parts = urlsplit(value)
            host_name = parts.hostname
        except ValueError:
            invalid += 1
            continue
        if parts.scheme not in ('http', 'https') or not host_name:
            invalid += 1
            continue
        host = normalize_ip(host_name) or normalize_domain(host_name)
        if not host:
            invalid += 1
            continue
        urls.append({
            'source': 'URLhaus', 'url': value, 'host': host,
            'status': item.get('url_status'), 'first_seen': item.get('date_added'),
            'reference': item.get('urlhaus_reference'), 'block_scope': 'full_url_review_only'
        })
    for entry in records.values():
        entry['ports'].sort()
    return {
        'schema_version': 2, 'validated_at': now.isoformat(),
        'candidates': sorted(records.values(), key=lambda x: (x['type'], x['value'])),
        'url_observations': urls, 'invalid_skipped': invalid,
        'outside_window_skipped': skipped_outside_window,
        'safety': 'REVIEW_ONLY; no se autorizan bloqueos IP/dominio/hash automaticamente.'
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', default='build/raw_iocs.json')
    p.add_argument('--output', default='build/validated_iocs.json')
    args = p.parse_args()
    data = json.loads(Path(args.input).read_text(encoding='utf-8'))
    valid = validate(data)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(valid, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(f"Validados {len(valid['candidates'])} IOC; URL {len(valid['url_observations'])}; "
          f"invalidos {valid['invalid_skipped']}; fuera de ventana {valid['outside_window_skipped']}")


if __name__ == '__main__':
    main()
