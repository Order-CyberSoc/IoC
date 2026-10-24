import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from audit_ioc import analyze


def payload():
    v = {'schema_version': 2, 'candidates': [
        {'type': 'ip', 'value': '8.8.8.8', 'max_confidence': 100, 'ports': [4443],
         'risk_flags': ['reported_as_ip_port_only'],
         'evidence': [{'source': 'ThreatFox', 'reference': 'https://example.org/reference', 'threat_type': 'botnet_cc'}]},
        {'type': 'domain', 'value': 'xx.workers.dev', 'max_confidence': 50, 'ports': [],
         'risk_flags': ['shared_hosting_domain_exact_match_only'],
         'evidence': [{'source': 'ThreatFox', 'reference': None, 'threat_type': 'payload_delivery'}]},
    ]}
    s = {'mode': 'REVIEW_ONLY', 'applied_to_firewalls': False, 'production_feeds_changed': False,
         'counts': {'ips-critical.txt': 0, 'ips-suspicious.txt': 1}, 'history_active': 2}
    return v, s


class SOCReviewTests(unittest.TestCase):
    def test_review_queue_contains_no_approved_blocks(self):
        with tempfile.TemporaryDirectory() as temp:
            v, s = payload()
            report = analyze(v, s, temp)
            self.assertFalse(report['automatic_blocking'])
            self.assertEqual(report['by_priority']['P1-hunting'], 1)
            with (Path(temp) / 'soc-review-queue.csv').open(encoding='utf-8', newline='') as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]['ports'], '4443')
            self.assertTrue(all(row['approved_for_block'] == 'NO' for row in rows))
            self.assertTrue((Path(temp) / 'soc-report.md').is_file())
            self.assertEqual(json.loads((Path(temp) / 'soc-quality.json').read_text())['mode'], 'REVIEW_ONLY')

    def test_fail_if_critical_list_is_approved(self):
        with tempfile.TemporaryDirectory() as temp:
            v, s = payload()
            s['counts']['ips-critical.txt'] = 1
            with self.assertRaises(ValueError):
                analyze(v, s, temp)

    def test_fail_if_production_state_changed(self):
        with tempfile.TemporaryDirectory() as temp:
            v, s = payload()
            s['production_feeds_changed'] = True
            with self.assertRaises(ValueError):
                analyze(v, s, temp)


if __name__ == '__main__':
    unittest.main()
