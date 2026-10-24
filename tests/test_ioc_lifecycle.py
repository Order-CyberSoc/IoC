import argparse
import json
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ioc_lifecycle import normalize, load_state, save_state, process, find_presence


def args(command, **kwargs):
    x = dict(type='ip', value='8.8.8.8', actor='analista1', ticket='SOC-001',
             reason='investigacion', source='ThreatFox', evidence_url='https://example.org/ioc',
             verdict='confirmed', notes='revisado', decision='monitor', scope='indicator',
             expires_on=(date.today()+timedelta(days=30)).isoformat(), ack_risk=False,
             root='.', history=None)
    x.update(kwargs)
    return argparse.Namespace(command=command, **x)


class IOCLifecycleTests(unittest.TestCase):
    def test_format_validation(self):
        self.assertEqual(normalize('domain', 'Example.ORG.'), 'example.org')
        with self.assertRaises(ValueError): normalize('ip', '192.168.1.12')
        with self.assertRaises(ValueError): normalize('sha256', 'zzz')

    def test_propose_verify_approve_revoke_separation(self):
        state = {'schema_version': 1, 'decisions': {}, 'events': []}
        self.assertEqual(process(args('propose'), state)[0]['status'], 'candidate')
        with self.assertRaises(ValueError): process(args('propose'), state)
        with self.assertRaises(ValueError): process(args('verify'), state)
        self.assertEqual(process(args('verify', actor='analista2'), state)[0]['status'], 'verified')
        with self.assertRaises(ValueError): process(args('approve', actor='analista2'), state)
        self.assertEqual(process(args('approve', actor='lider3'), state)[0]['status'], 'approved_monitoring')
        self.assertEqual(process(args('revoke', actor='lider3', reason='false positive'), state)[0]['status'], 'revoked')
        self.assertEqual(len(state['events']), 4)

    def test_blocking_needs_explicit_ack_and_scope(self):
        state = {'schema_version': 1, 'decisions': {}, 'events': []}
        process(args('propose'), state)
        process(args('verify', actor='analista2'), state)
        with self.assertRaises(ValueError): process(args('approve', actor='lider3', decision='block'), state)
        with self.assertRaises(ValueError): process(args('approve', actor='lider3', decision='block', ack_risk=True), state)
        r, _ = process(args('approve', actor='lider3', decision='block', ack_risk=True, scope='ip_exact'), state)
        self.assertEqual(r['status'], 'approved_blocking')
        self.assertEqual(state['decisions']['ip|8.8.8.8']['deployment_state'], 'NOT_DEPLOYED')

    def test_exact_presence_and_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'ips.txt').write_text('8.8.8.8\n', encoding='utf-8')
            state = {'schema_version': 1, 'decisions': {}, 'events': []}
            x = find_presence('ip', '8.8.8.8', state, tmp)
            self.assertEqual(x['found_in_static_feeds_exact'], ['ips.txt'])
            s = root / 'build/state.json'
            save_state(s, state)
            self.assertEqual(load_state(s)['schema_version'], 1)


if __name__ == '__main__':
    unittest.main()
