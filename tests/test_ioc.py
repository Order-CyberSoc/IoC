import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from validate_ioc import validate
from publish_ioc import stage

NOW = datetime(2026, 10, 8, 21, 0, tzinfo=timezone.utc)


def fixture():
    ts = (NOW - timedelta(hours=1)).isoformat()
    return {
        'threatfox': [
            dict(ioc='8.8.8.8:1443', ioc_type='ip:port', confidence_level=100,
                 threat_type='botnet_cc', first_seen=ts, id='1', reference=None),
            dict(ioc='8.8.8.8:9443', ioc_type='ip:port', confidence_level=90,
                 threat_type='botnet_cc', first_seen=ts, id='2', reference='https://example.org/ioc'),
            dict(ioc='subdomain.workers.dev', ioc_type='domain', confidence_level=99,
                 threat_type='botnet_cc', first_seen=ts, id='3', reference='https://example.org/ioc'),
            dict(ioc='a' * 64, ioc_type='sha256_hash', confidence_level=80,
                 threat_type='payload', first_seen=ts, id='4', reference=None),
            dict(ioc='203.0.113.123:443', ioc_type='ip:port', confidence_level=100,
                 threat_type='botnet_cc', first_seen=ts, id='5', reference=None),
        ],
        'urlhaus': [
            dict(url='https://example.org/suspicious.exe', date_added=ts, url_status='online'),
        ],
    }


class TestIOC(unittest.TestCase):
    def test_ports_hash_and_shared_hosting(self):
        result = validate(fixture(), NOW)
        self.assertEqual(len(result['candidates']), 3)
        ip = next(x for x in result['candidates'] if x['type'] == 'ip')
        self.assertEqual(ip['ports'], [1443, 9443])
        self.assertEqual(ip['classification'], 'high_confidence_candidate')
        self.assertIn('ip_wide_block_requires_analyst_approval', ip['risk_flags'])
        sha = next(x for x in result['candidates'] if x['type'] == 'sha256')
        self.assertEqual(sha['classification'], 'malware_hash_review')
        domain = next(x for x in result['candidates'] if x['type'] == 'domain')
        self.assertIn('shared_hosting_domain_exact_match_only', domain['risk_flags'])
        self.assertEqual(len(result['url_observations']), 1)

    def test_review_feeds_and_history(self):
        data = validate(fixture(), NOW)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'staging'
            summary = stage(data, target, Path(tmp) / 'missing.json', NOW)
            self.assertEqual(summary['counts']['ips-critical.txt'], 0)
            self.assertEqual(summary['counts']['ips-suspicious.txt'], 1)
            self.assertEqual(summary['counts']['hashes-sha256.txt'], 1)
            self.assertEqual(summary['counts']['domains-malicious.txt'], 1)
            self.assertEqual(summary['new_in_history'], 3)
            previous = target / 'data/ioc-history.json'
            self.assertTrue(previous.exists())
            summary2 = stage(data, Path(tmp) / 'second', previous, NOW + timedelta(hours=1))
            self.assertEqual(summary2['new_in_history'], 0)
            self.assertEqual(summary2['counts']['ips-critical.txt'], 0)

    def test_fail_closed_for_malformed_history(self):
        data = validate(fixture(), NOW)
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / 'bad.json'
            bad.write_text('{"oops":1}', encoding='utf8')
            with self.assertRaises(ValueError):
                stage(data, Path(tmp) / 'out', bad, NOW)


if __name__ == '__main__':
    unittest.main()
