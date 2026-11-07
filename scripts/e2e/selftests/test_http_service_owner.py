#!/usr/bin/env python3
"""Actual prebuilt-fg process ownership tests; no schema peer or implicit build."""
from __future__ import annotations

import json
import os
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

E2E = Path(__file__).resolve().parents[1]
support = runpy.run_path(str(E2E / 'scoped_events_smoke.py'))
Campaign, HttpServer, TENANT, REPOSITORY = (support[name] for name in ('Campaign', 'HttpServer', 'TENANT', 'REPOSITORY'))


class HttpServiceOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fg = Path(os.environ['FG_BIN']).resolve(strict=True)
        if not cls.fg.is_file() or not os.access(cls.fg, os.X_OK) or os.name != 'posix':
            raise RuntimeError('prebuilt executable FG_BIN and POSIX process signals are required')
        os.umask(0o077)
        cls.artifacts = Path(os.environ.get('FGE_HTTP_OWNER_WORKDIR') or tempfile.mkdtemp(prefix='fg-http-owner-'))
        cls.artifacts.mkdir(mode=0o700, parents=True, exist_ok=True)
        print(f'native HTTP owner artifacts: {cls.artifacts}', file=sys.stderr)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix=self._testMethodName + '-', dir=self.artifacts))
        self.campaign = Campaign(self.fg, self.work)
        self.root = self.work / 'repository'
        self.campaign.run('init', self.root, TENANT, REPOSITORY, 'sha1')
        self.credentials, _ = self.campaign.credentials(self.root, self.work)
        self.server = HttpServer(self.campaign, self.root, self.credentials, 'owned-http')
        self.child = None

    def tearDown(self):
        # Retain the original Popen capability even when testing the old broken
        # owner. Cleanup never selects another session's process by a PID scan.
        if self.child is not None and self.child.poll() is None:
            self.child.send_signal(signal.SIGCONT)
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)

    def start(self, stopped=False):
        self.server.__enter__()
        self.child = self.server.process
        if stopped:
            self.child.send_signal(signal.SIGSTOP)
            until = time.monotonic() + 2
            while time.monotonic() < until:
                pid, status = os.waitpid(self.child.pid, os.WUNTRACED | os.WNOHANG)
                if pid:
                    if os.WIFSTOPPED(status):
                        return
                    self.child.returncode = os.waitstatus_to_exitcode(status)
                    self.fail('owned native child exited before the stop checkpoint')
                time.sleep(0.005)
            self.fail('owned native child did not acknowledge SIGSTOP')

    def stop_record(self):
        rows = [json.loads(line) for line in self.campaign.journal.read_text().splitlines()]
        starts = [r for r in rows if r['kind'] == 'service_start']
        stops = [r for r in rows if r['kind'] == 'service_stop']
        self.assertEqual(len(starts), 1)
        self.assertEqual(len(stops), 1)
        self.assertEqual(starts[0]['pid'], stops[0]['pid'])
        self.assertIsNotNone(self.child.poll(), 'owner returned with its native child still alive')
        self.assertIsNone(self.server.process)
        return stops[0]

    def test_permitted_stop_drains_real_native_service(self):
        self.start()
        self.server.close()
        row = self.stop_record()
        self.assertEqual(row['exit'], 0)
        self.assertFalse(row['forced'])
        self.assertNotIn('close_error', row)
        self.server.close()
        self.stop_record()

    def test_stop_file_failure_reaps_owned_native_child(self):
        self.start(stopped=True)
        self.server.stop.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.server.close()
        row = self.stop_record()
        self.assertTrue(row['forced'])
        self.assertEqual(row['close_error'], 'FileExistsError')

    def interrupted_stop(self, number, error_type):
        self.start(stopped=True)
        closing = threading.Event()
        calls, sent, faults = [], [], []

        def stop(_number, _frame):
            calls.append(_number)
            if closing.is_set():
                raise error_type('native owner cancellation requested')

        def interrupt():
            until = time.monotonic() + 2
            while not self.server.stop.exists() and time.monotonic() < until:
                time.sleep(0.005)
            if not self.server.stop.exists():
                faults.append('close did not request graceful stop')
                return
            for index in range(3):
                if closing.is_set():
                    sent.append(number)
                    os.kill(os.getpid(), number)
                # Popen.wait gives KeyboardInterrupt its own short grace
                # before propagating it. Repeat during our final drain, not
                # during that earlier stdlib-owned cancellation phase.
                time.sleep(1 if index == 0 else 0.03)

        previous = signal.signal(number, stop)
        worker = threading.Thread(target=interrupt)
        try:
            closing.set()
            worker.start()
            with self.assertRaises(error_type):
                self.server.close()
        finally:
            closing.clear()
            worker.join(timeout=3)
            signal.signal(number, previous)
        self.assertFalse(worker.is_alive())
        self.assertFalse(faults, faults)
        self.assertEqual(sent, [number] * 3)
        self.assertEqual(calls, [number], 'repeated cancellation interrupted the final drain')
        row = self.stop_record()
        self.assertTrue(row['forced'])
        self.assertEqual(row['close_error'], error_type.__name__)

    def test_sigterm_drain_reaps_child_despite_repeated_signals(self):
        self.interrupted_stop(signal.SIGTERM, InterruptedError)

    def test_sigint_drain_reaps_child_despite_repeated_signals(self):
        self.interrupted_stop(signal.SIGINT, KeyboardInterrupt)


if __name__ == '__main__':
    unittest.main()
