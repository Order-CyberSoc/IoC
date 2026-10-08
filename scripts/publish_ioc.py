
#!/usr/bin/env python3
"""ORDER SOC: stage FortiGate-compatible text files as CI artifacts; never push to production."""
import argparse
import json
from pathlib import Path

FEED_NAMES = ('ips-critical.txt', 'ips-suspicious.txt', 'domains-malicious.txt', 'hashes-sha256.txt')


def write_lines(path, values):
    path.parent.mkdir(parents=True, exist_ok=True)
    # A single newline represents an intentionally empty feed during the pilot.
    path.write_text(('\n'.join(sorted(set(values))) + '\n') if values else '\n', encoding='utf-8')


def stage(data, output):
    output = Path(output)
    ips = [c['value'] for c in data['candidates'] if c['type'] == 'ip']
    domains = [c['value'] for c in data['candidates'] if c['type'] == 'domain'
               and c['classification'] == 'high_confidence_candidate']
    hashes = [c['value'] for c in data['candidates'] if c['type'] == 'sha256'
              and c['classification'] == 'high_confidence_candidate']
    # CRITICAL FEED ALWAYS EMPTY until an analyst manually approves individual IPs.
    feeds = {
        'ips-critical.txt': [],
        'ips-suspicious.txt': ips,
        'domains-malicious.txt': domains,
        'hashes-sha256.txt': hashes,
    }
    for name in FEED_NAMES:
        write_lines(output / 'feeds' / name, feeds[name])
    (output / 'review').mkdir(parents=True, exist_ok=True)
    (output / 'review' / 'ioc-candidates.json').write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    report = {'mode': 'REVIEW_ONLY', 'applied_to_firewalls': False, 'committed_to_git': False,
              'counts': {name: len(set(vals)) for name, vals in feeds.items()},
              'url_observations': len(data.get('url_observations', [])),
              'invalid_skipped': data.get('invalid_skipped', 0)}
    (output / 'review' / 'summary.json').write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', default='build/validated_iocs.json')
    parser.add_argument('--output', default='build/staging')
    args = parser.parse_args()
    data = json.loads(Path(args.input).read_text(encoding='utf-8'))
    stage(data, args.output)


if __name__ == '__main__':
    main()
