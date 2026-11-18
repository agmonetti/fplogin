#!/usr/bin/env python3
"""Synthetic verifier checks; no tracing, PAM, SDDM or reader required."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
BOOT = '123456781234123412341234567890ab'
TRACE = '''heartbeat 1000000000
enter pam 1100000000 42 42
enter gnome 1200000000 42 42
return gnome 1300000000 42 42 25
enter kwallet 1400000000 42 42
return kwallet 1500000000 42 42 0
return pam 1600000000 42 42 0
heartbeat 2000000000
end 2100000000
'''
SESSION = {'boot': BOOT, 'Id': '4', 'Name': 'fplab', 'Seat': 'seat0', 'Leader': '42',
           'Service': 'sddm-fingerprint', 'Type': 'wayland', 'Class': 'user',
           'Active': 'yes', 'observed_ns': 1700000000}


class KeyringEvidenceTest(unittest.TestCase):
    def run_case(self, trace=TRACE, session=None, **overrides):
        # Disposable fixtures only; no guest evidence is written here.
        with tempfile.TemporaryDirectory() as path:
            directory = Path(path)
            files = {'trace.txt': trace, 'session.json': json.dumps(SESSION | (session or {})),
                     'trace.stderr': '', 'trace.status': '0', 'boot.before': BOOT, 'boot.after': BOOT}
            for name, value in (files | overrides).items():
                (directory / name).write_text(value)
            return subprocess.run([sys.executable, str(HERE / 's3-keyring.py'), 'verify', path, 'fplab'],
                                  capture_output=True, text=True, check=False, timeout=5)

    def test_verified_metadata_not_operator_observation(self):
        result = self.run_case()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence['helper_pid'], 42)
        self.assertEqual(evidence['hooks']['gnome']['rc'], 25)
        self.assertEqual(evidence['operator_prompt'], 'not inferred')

    def test_bpftrace_trailing_empty_lines(self):
        result = self.run_case(trace=TRACE + '\n\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_runner_cleanup_preserves_confirmed_session(self):
        # Execute only the real EXIT trap; never run guest commands on the host.
        runner = (HERE / 's3-keyring-physical.sh').read_text()
        _, _, tail = runner.partition('cleanup() {\n')
        body, sep, _ = tail.partition('trap cleanup EXIT\n')
        self.assertTrue(sep)
        for confirmed, stop in (('false', 'stop sddm\n'), ('true', '')):
            with self.subTest(confirmed=confirmed):
                result = subprocess.run(['bash', '-c', '''
set -euo pipefail
systemctl() { printf '%s\\n' "$*"; }
monitor= tracer= started=true session_confirmed=$1
cleanup() {
''' + body + sep + 'false\n', '_', confirmed],
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, stop)
                self.assertEqual('BLOCKED' in result.stderr, confirmed == 'true')

    def test_missing_ambiguous_or_unbound_evidence_blocks(self):
        cases = {
            'missing-return': {'trace': TRACE.replace('return gnome 1300000000 42 42 25\n', '')},
            'different-thread': {'trace': TRACE.replace('42 42 25', '42 44 25')},
            'greeter-pid': {'trace': TRACE.replace('42 42 25', '44 44 25')},
            'wrong-time': {'trace': TRACE.replace('1400000000', '1080000000')},
            'repeated': {'trace': TRACE.replace('return gnome', 'enter gnome 1210000000 42 42\nreturn gnome')},
            'pam-fail': {'trace': TRACE.replace('1600000000 42 42 0', '1600000000 42 42 1')},
            'early-session': {'session': {'observed_ns': 1550000000}},
            'stock-password': {'session': {'Service': 'sddm'}},
            'foreign-boot': {'boot.after': '11111111111111111111111111111111'},
            'dead-tracer': {'trace.status': '1'},
            'lost-events': {'trace.stderr': 'Lost events'},
            'missing-heartbeat': {'trace': TRACE.replace('heartbeat 1000000000\n', '')},
            'missing-end': {'trace': TRACE.replace('end 2100000000\n', '')},
            'unrecognized': {'trace': TRACE + '\nprivate-canary\n'},
            'interior-empty-line': {'trace': TRACE.replace('enter pam', '\nenter pam')},
            'record-after-end': {'trace': TRACE + 'heartbeat 2200000000\n'},
            'extra-end': {'trace': TRACE + 'end 2200000000\n'},
        }
        for name, overrides in cases.items():
            with self.subTest(name=name):
                result = self.run_case(**overrides)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('private-canary', result.stderr)


if __name__ == '__main__':
    unittest.main()
