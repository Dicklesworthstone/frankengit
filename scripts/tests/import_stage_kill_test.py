"""Harness-only negative controls; these do not count as native import cases."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

helper = Path(__file__).resolve().parents[1] / 'e2e/helpers/import_stage_kill.py'
if len(sys.argv) > 1 and sys.argv[1].endswith('.py'):
    helper = Path(sys.argv.pop(1))
spec = importlib.util.spec_from_file_location('stage', helper)
stage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class HarnessControls(unittest.TestCase):
    def test_authority_witness_rejects_absent_or_disagreeing_head_and_sequence(self):
        # Captured real f04 `fg at ... latest` output. The summary uses colons;
        # the namespaced identity in the detail uses a slash before the digest.
        oid = '654e2d7a0afa37ea5c3aee48b319d9febc50641c1eb9732dc902a80454863198'
        raw = b'''snapshot at latest (head alg:2:654e2d7a0afa37ea5c3aee48b319d9febc50641c1eb9732dc902a80454863198, decision Some(1)): 1 refs, 0 pull requests; Forge Snapshot at latest
  Repository: 22222222222222222222222222222222
  Head: frankengit/authority-head/v1/v1.0/alg:2/654e2d7a0afa37ea5c3aee48b319d9febc50641c1eb9732dc902a80454863198 (gen 2)
  Decision Sequence: 1
  Policy Epoch: 1
  Refs: 1
  Pull Requests: 0 (legacy projection only)
  Replay Batches: 0 (capsule: genesis)
'''
        self.assertEqual(stage.cold_head(raw), {'head_id': 'alg:2:' + oid, 'decision_sequence': 1, 'generation': 2})
        for bad in [b'', raw.replace(b'Some(1)', b'Some(3)'), raw.replace(b'(gen 2)', b'(gen 0)'),
                    raw + b'  Decision Sequence: 1\n', raw + raw,
                    raw + ('  Head: frankengit/authority-head/v1/v1.0/alg:2/' + oid + ' (gen 2)\n').encode(),
                    raw.replace(('alg:2/' + oid + ' (gen').encode(), ('alg:2/' + 'b' * 64 + ' (gen').encode())]:
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                stage.cold_head(bad)

    def test_interleaved_trace_pairs_only_exact_pid_and_syscall(self):
        trace = ('10 fsync(16</owned/stage> <unfinished ...>\n'
                 '11 write(2</other>, "x", 1) = 1\n'
                 '10 <... fsync resumed>) = ?\n10 +++ killed by SIGKILL +++\n')
        lines = stage.syscall_lines(trace)
        self.assertIn('10 fsync(16</owned/stage>) = ?', lines)
        self.assertEqual(len(lines), 2)
        for bad in [trace.replace('10 <...', '12 <...'), trace.replace('fsync resumed', 'write resumed'),
                    trace + '10 <... fsync resumed>) = ?\n',
                    '10 fsync(16</owned/stage> <unfinished ...>\n',
                    trace.replace('11 write(', '10 write(')]:
            with self.subTest(bad=bad), self.assertRaises(AssertionError):
                stage.syscall_lines(bad)
        self.assertFalse(stage.exact_target('10 fsync(16</owned/stage-other>) = ?', '/owned/stage'))

    def test_exact_ref_mapping_and_bad_rows(self):
        oid = 'a' * 40
        valid = ('references at latest (1 total):\n  refs/heads/seed -> ' + oid + '\n').encode()
        self.assertEqual(stage.cold_refs(valid), {'refs/heads/seed': oid})
        for raw in [valid.replace(b'(1 total)', b'(2 total)'),
                    valid + b'  refs/heads/seed -> ' + oid.encode() + b'\n',
                    valid + b'unexpected row\n', b'', valid + b'  refs/heads/evil -> abc\n']:
            with self.subTest(raw=raw), self.assertRaises(AssertionError):
                stage.cold_refs(raw)

    def campaign(self, root):
        # Exercise command ownership itself, without pretending Python is fg.
        campaign = object.__new__(stage.Campaign)
        campaign.root, campaign.sequence = Path(root), 0
        campaign.fg, campaign.strace = sys.executable, shutil.which('strace')
        campaign.workload_deadline = time.monotonic() + 20
        campaign.calls = []
        return campaign

    def test_real_timeout_records_and_reaps_owned_process(self):
        with tempfile.TemporaryDirectory(prefix='fg-stage-harness-timeout-') as root:
            campaign = self.campaign(root)
            with self.assertRaises(subprocess.TimeoutExpired):
                campaign.invoke('real-timeout', ['-c', 'import time; time.sleep(60)'], timeout_seconds=0.05)
            row = json.loads((Path(root) / 'commands.json').read_text())[0]
            self.assertEqual(row['command'], [sys.executable, '-c', 'import time; time.sleep(60)'])
            self.assertGreater(row['pid'], 0)
            self.assertGreaterEqual(row['spawned_unix_ns'], row['started_unix_ns'])
            self.assertIn('TimeoutExpired', row['error'])
            self.assertTrue(row['cleanup_sent_sigkill'])
            self.assertTrue(row['owned_process_group_reaped'])
            self.assertFalse(row['owned_process_group_quiescent'])
            with self.assertRaises(ProcessLookupError):
                os.killpg(row['pid'], 0)
            self.assertEqual(row, json.loads((Path(root) / '001-real-timeout.command.json').read_text()))

    def test_real_overall_deadline_is_not_reset_by_command_timeout(self):
        with tempfile.TemporaryDirectory(prefix='fg-stage-harness-deadline-') as root:
            campaign = self.campaign(root)
            campaign.workload_deadline = time.monotonic() + 0.05
            with self.assertRaises(subprocess.TimeoutExpired):
                campaign.invoke('overall-deadline', ['-c', 'import time; time.sleep(60)'])
            row = json.loads((Path(root) / 'commands.json').read_text())[0]
            self.assertLess(row['elapsed'], 2)
            self.assertTrue(row['owned_process_group_reaped'])
            self.assertEqual(row['containment'], 'reaped')
            with self.assertRaises(ProcessLookupError):
                os.killpg(row['pid'], 0)

    def test_real_exit_mismatch_still_has_complete_command_record(self):
        with tempfile.TemporaryDirectory(prefix='fg-stage-harness-mismatch-') as root:
            campaign = self.campaign(root)
            with self.assertRaisesRegex(AssertionError, 'exit 3, expected 0'):
                campaign.invoke('real-mismatch', ['-c', 'raise SystemExit(3)'])
            row = json.loads((Path(root) / 'commands.json').read_text())[0]
            self.assertEqual(row['exit'], 3)
            self.assertTrue(row['owned_process_group_quiescent'])
            self.assertTrue(row['owned_process_group_reaped'])


if __name__ == '__main__':
    unittest.main()
