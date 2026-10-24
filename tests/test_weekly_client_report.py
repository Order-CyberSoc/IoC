import json
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from weekly_client_report import build_data, render, week_dates

ROOT = Path(__file__).resolve().parents[1]


def write_daily(root, day, *, current=10, added=2, removed=1, mode='DELTA'):
    path = root / day / 'summary.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({'schema_version': 1, 'date_local': day, 'mode': mode,
                    'count_current': current, 'count_added': added, 'count_removed': removed,
                    'current_by_type': {'ip': 4, 'domain': 3, 'sha256': 3}}), encoding='utf-8')


class WeeklyReportTests(unittest.TestCase):
    def test_previous_completed_iso_week(self):
        self.assertEqual(tuple(str(x) for x in week_dates(date(2026, 10, 23))),
                         ('2026-10-12', '2026-10-18'))

    def test_complete_week_aggregates_deltas(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for day in range(12, 19):
                write_daily(root, f'2026-10-{day}', current=100 + day, added=day - 10, removed=1)
            summary = build_data(root, date(2026, 10, 23))
            self.assertTrue(summary['complete'])
            self.assertEqual(summary['coverage_days'], 7)
            self.assertEqual(summary['added_observed'], sum(range(2, 9)))
            self.assertEqual(summary['removed_observed'], 7)
            self.assertEqual(summary['current_observed'], 118)

    def test_partial_week_never_claims_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            write_daily(Path(tmp), '2026-10-12', mode='BASELINE', current=900, added=0, removed=0)
            summary = build_data(tmp, date(2026, 10, 23))
            self.assertFalse(summary['complete'])
            self.assertEqual(summary['coverage_days'], 0)
            self.assertEqual(summary['available_days'], 1)
            self.assertEqual(len(summary['missing_days']), 6)
            self.assertEqual(summary['added_observed'], 0)

    def test_html_escapes_customer_name_and_rejects_fake_client_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = build_data(tmp, date(2026, 10, 23))
            config = json.loads((ROOT / 'config/branding.json').read_text(encoding='utf-8'))
            config['client_name'] = '<script>alert(1)</script>'
            config['logo_path'] = str(ROOT / 'assets/order-wordmark.svg')
            path = render(data, config, ROOT / 'templates/weekly_report_client.html', Path(tmp) / 'report')
            txt = path.read_text(encoding='utf-8')
            self.assertIn('&lt;script&gt;', txt)
            self.assertNotIn('<script>alert(1)</script>', txt)
            self.assertIn('COBERTURA PARCIAL', txt)
            data['client_impact_verified'] = True
            with self.assertRaises(ValueError):
                render(data, config, ROOT / 'templates/weekly_report_client.html', Path(tmp) / 'fail')


if __name__ == '__main__':
    unittest.main()
