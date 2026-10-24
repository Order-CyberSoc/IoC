import csv
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from daily_ioc_report import compare, save_report

NOW = datetime(2026, 10, 22, 13, 30, tzinfo=timezone.utc)


def entry(kind, val, expires_days=1, confidence=95):
    return {'type': kind, 'value': val, 'status': 'active', 'classification': 'review',
            'max_confidence': confidence, 'observed_ports': [443] if kind == 'ip' else [],
            'expires_at': (NOW + timedelta(days=expires_days)).isoformat()}


def history(indicators):
    return {'schema_version': 2, 'updated_at': NOW.isoformat(), 'indicators': indicators}


class TestDailyReport(unittest.TestCase):
    def test_first_day_baseline_is_not_false_new(self):
        curr = history({'ip|1.1.1.1': entry('ip', '1.1.1.1')})
        summary, adds, removals, snapshot = compare(curr, now=NOW)
        self.assertEqual(summary['mode'], 'BASELINE')
        self.assertEqual(summary['count_current'], 1)
        self.assertEqual(summary['count_added'], 0)
        self.assertEqual(summary['count_removed'], 0)
        self.assertEqual(len(snapshot['indicators']), 1)
        self.assertFalse(adds)
        self.assertFalse(removals)

    def test_new_and_removed_daily_deltas(self):
        prev = {'schema_version': 1, 'date_local': '2026-10-21',
                'generated_at_utc': (NOW-timedelta(days=1)).isoformat(),
                'indicators': {
                    'ip|1.1.1.1': dict(entry('ip', '1.1.1.1'), expires_at=(NOW-timedelta(hours=1)).isoformat()),
                    'domain|example.org': entry('domain', 'example.org'),
                }}
        curr = history({'domain|example.org': entry('domain', 'example.org'),
                        'sha256|' + 'a'*64: entry('sha256', 'a'*64)})
        s, added, removed, snap = compare(curr, prev, NOW)
        self.assertEqual(s['mode'], 'DELTA')
        self.assertEqual(s['count_added'], 1)
        self.assertEqual(s['count_removed'], 1)
        self.assertEqual(s['removed_due_ttl'], 1)
        self.assertEqual(s['added_by_type']['sha256'], 1)
        self.assertEqual(s['removed_by_type']['ip'], 1)
        with tempfile.TemporaryDirectory() as d:
            save_report(d, s, added, removed, snap)
            with (Path(d)/'added.csv').open(newline='', encoding='utf8') as f:
                self.assertEqual(len(list(csv.DictReader(f))), 1)
            with (Path(d)/'removed.csv').open(newline='', encoding='utf8') as f:
                rec = list(csv.DictReader(f))
                self.assertEqual(rec[0]['motivo_salida'], 'TTL_expirado')
            self.assertIn('NO equivalen', (Path(d)/'daily-report.md').read_text())

    def test_same_day_is_idempotent_and_future_rejected(self):
        curr = history({})
        prev = {'schema_version': 1, 'date_local': '2026-10-22', 'indicators': {}}
        summary, _, _, _ = compare(curr, prev, NOW)
        self.assertEqual(summary['mode'], 'ALREADY_REPORTED')
        prev['date_local'] = '2026-10-23'
        with self.assertRaises(ValueError):
            compare(curr, prev, NOW)

    def test_reject_broken_schema_and_expired_state(self):
        with self.assertRaises(ValueError):
            compare({'schema_version': 3, 'indicators': {}}, now=NOW)
        curr = history({'ip|8.8.8.8': entry('ip', '8.8.8.8', -2)})
        s, _, _, _ = compare(curr, now=NOW)
        self.assertEqual(s['count_current'], 0)

    def test_stale_history_rejected(self):
        curr = history({})
        curr['updated_at'] = (NOW - timedelta(hours=27)).isoformat()
        with self.assertRaises(ValueError):
            compare(curr, now=NOW)

    def test_santiago_timezone(self):
        curr = history({})
        s, _, _, _ = compare(curr, now=datetime(2026, 10, 22, 1, 0, tzinfo=timezone.utc))
        self.assertEqual(s['date_local'], '2026-10-21')


if __name__ == '__main__':
    unittest.main()
