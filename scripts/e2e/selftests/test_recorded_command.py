#!/usr/bin/env python3
"""Real child processes test capture, not native forge functionality."""
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'helpers'))
from recorded_command import run


class RecordedCommandTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix='fg-recorded-command-')
        self.addCleanup(directory.cleanup)
        self.prefix = Path(directory.name) / '001-command'
        self.echo = io.TextIOWrapper(io.BytesIO())
        self.addCleanup(self.echo.close)

    def invoke(self, script, data=None, timeout=5):
        with contextlib.redirect_stderr(self.echo):
            return run(self.prefix, [sys.executable, '-c', script], data, timeout=timeout)

    def artifact(self, suffix):
        return self.prefix.with_suffix(suffix).read_bytes()

    def test_success_retains_exact_binary_streams_and_request(self):
        request = b'original request\x00\xff\n'
        output = self.invoke(
            "import os, sys; data=sys.stdin.buffer.read(); "
            "os.write(1, data); os.write(2, b'diagnostic\\x00\\xff\\n')", request)
        self.assertEqual(output, request)
        self.assertEqual(self.artifact('.out'), request)
        self.assertEqual(self.artifact('.err'), b'diagnostic\x00\xff\n')
        self.assertEqual(self.artifact('.requests.ndjson'), request)
        self.assertEqual(self.echo.buffer.getvalue(), self.artifact('.err'))

    def test_nonzero_exit_retains_streams_and_is_not_success(self):
        with self.assertRaises(AssertionError) as error:
            self.invoke("import os; os.write(1,b'partial'); os.write(2,b'refused'); raise SystemExit(7)", b'original')
        self.assertEqual(error.exception.args[0][1], 7)
        self.assertEqual(self.artifact('.out'), b'partial')
        self.assertEqual(self.artifact('.err'), b'refused')
        self.assertEqual(self.artifact('.requests.ndjson'), b'original')

    def test_timeout_retains_streams_request_and_reaps_direct_child(self):
        pidfile = self.prefix.parent / 'child.pid'
        script = (
            "import os, pathlib, sys, time; "
            f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid())); "
            "data=sys.stdin.buffer.read(); os.write(1,data); os.write(2,b'timeout diagnostic'); "
            "time.sleep(15)"
        )
        with self.assertRaises(subprocess.TimeoutExpired):
            self.invoke(script, b'original timeout request\x00\xff', timeout=1)
        self.assertEqual(self.artifact('.requests.ndjson'), b'original timeout request\x00\xff')
        self.assertEqual(self.artifact('.out'), b'original timeout request\x00\xff')
        self.assertEqual(self.artifact('.err'), b'timeout diagnostic')
        self.assertEqual(self.echo.buffer.getvalue(), b'timeout diagnostic')
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pidfile.read_text()), 0)

    def test_spawn_failure_preserves_request_and_original_error(self):
        with self.assertRaises(FileNotFoundError), contextlib.redirect_stderr(self.echo):
            run(self.prefix, [self.prefix.parent / 'absent-executable'], b'original request')
        self.assertEqual(self.artifact('.requests.ndjson'), b'original request')
        self.assertEqual(self.artifact('.out'), b'')
        self.assertEqual(self.artifact('.err'), b'')

    def test_child_can_observe_request_and_streams_before_exit(self):
        script = (
            "import os, pathlib; "
            f"prefix=pathlib.Path({str(self.prefix)!r}); "
            "assert prefix.with_suffix('.requests.ndjson').read_bytes()==b'original'; "
            "assert prefix.with_suffix('.out').exists(); assert prefix.with_suffix('.err').exists(); "
            "os.write(1,b'live'); os.write(2,b'diagnostic'); "
            "assert prefix.with_suffix('.out').read_bytes()==b'live'; "
            "assert prefix.with_suffix('.err').read_bytes()==b'diagnostic'"
        )
        self.assertEqual(self.invoke(script, b'original'), b'live')

    def test_command_without_input_does_not_create_request_artifact(self):
        self.assertEqual(self.invoke("print('ok')"), b'ok\n')
        self.assertFalse(self.prefix.with_suffix('.requests.ndjson').exists())


if __name__ == '__main__':
    unittest.main()
