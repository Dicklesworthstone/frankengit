#!/usr/bin/env python3
"""Actual process tests for the operator campaign's request/drain boundary.

The worker is a synthetic cooperative executable, not a native forge oracle.
The owner uses the shipped native-process-owner; no subprocess is mocked.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

E2E = Path(__file__).resolve().parents[1]
ROOT = E2E.parents[1]
sys.path.insert(0, str(E2E))
from operator_issue_smoke import OperatorCampaign


class OperatorCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = Path(os.environ["FGE_NODE"]).resolve(strict=True)
        identity = subprocess.run([str(cls.node), str(ROOT / "scripts/verify_js.mjs"), "runtime"],
                                  capture_output=True, check=False, timeout=10)
        if identity.returncode:
            raise RuntimeError(identity.stderr.decode(errors="replace"))

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="fg-operator-owner-"))
        self.campaign = OperatorCampaign(Path("/unused-native"), self.node, self.work)

    def records(self):
        return [json.loads(line) for line in self.campaign.journal.read_text().splitlines()]

    def test_ndjson_retains_every_record_without_changing_single_json_contract(self):
        script = "console.log(JSON.stringify({page:1})); console.log(JSON.stringify({complete:true}));"
        with self.assertRaises(json.JSONDecodeError):
            self.campaign.node_command(Path("-e"), [script])
        value = self.campaign.node_command(Path("-e"), [script], json_lines=True)
        self.assertEqual(value, [{"page": 1}, {"complete": True}])

    def test_ndjson_rejects_empty_mixed_and_nonobject_protocols(self):
        for script in ["", "console.log('{}'); console.log('not JSON');",
                       "console.log('{}'); console.log('');", "console.log('[]');"]:
            with self.subTest(script=script), self.assertRaises((ValueError, AssertionError)):
                self.campaign.node_command(Path("-e"), [script], json_lines=True)

    def test_success_retains_both_streams(self):
        value = self.campaign.node_command(Path("-e"), [
            "console.error('retained diagnostic'); console.log(JSON.stringify({ok:true}));"])
        self.assertEqual(value, {"ok": True})
        self.assertEqual(self.records()[0]["exit"], 0)
        self.assertEqual((self.work / "operator-001.stderr").read_text(), "retained diagnostic\n")

    def test_expected_refusal_stays_exact(self):
        value = self.campaign.node_command(Path("-e"), [
            "console.error(JSON.stringify({code:'permitted-refusal'})); process.exitCode=2;"],
            expected=2, error_reply=True)
        self.assertEqual(value, {"code": "permitted-refusal"})
        self.assertEqual(self.records()[0]["exit"], 2)

    def test_unexpected_exit_retains_journal(self):
        with self.assertRaisesRegex(AssertionError, "operator exit 7"):
            self.campaign.node_command(Path("-e"), ["console.error('original exit'); process.exitCode=7;"])
        self.assertEqual(self.records()[0]["exit"], 7)
        self.assertEqual((self.work / "operator-001.stderr").read_text(), "original exit\n")

    def test_invalid_json_retains_artifacts(self):
        with self.assertRaises(json.JSONDecodeError):
            self.campaign.node_command(Path("-e"), ["console.log('not JSON')"])
        self.assertEqual(self.records()[0]["exit"], 0)
        self.assertEqual((self.work / "operator-001.stdout").read_text(), "not JSON\n")

    def driver(self, owner, *arguments, timeout=None, workflow=False):
        driver = self.work / "driver.py"
        driver.write_text("""import signal, sys
from pathlib import Path
sys.path.insert(0, """ + repr(str(E2E)) + """)
from operator_issue_smoke import OperatorCampaign
def stop(number, frame): raise InterruptedError('original interrupt ' + str(number))
signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
campaign = OperatorCampaign(Path('/unused-native'), Path(sys.argv[1]), Path(sys.argv[2]))
""" + ("from operator_workflow_smoke import node_rows\n" if workflow else "") +
            ("node_rows(campaign, Path(sys.argv[3]), sys.argv[4:])\n" if workflow else
             "campaign.node_command(Path(sys.argv[3]), sys.argv[4:], " +
             ("timeout=" + repr(timeout) if timeout is not None else "") + ")\n"))
        with (self.work / "driver.stdout").open("wb") as out, (self.work / "driver.stderr").open("wb") as err:
            process = subprocess.Popen([sys.executable, str(driver), str(self.node), str(self.work),
                                        str(owner), *map(str, arguments)], stdout=out, stderr=err)
        def stop_driver():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        self.addCleanup(stop_driver)
        return process

    def wait_file(self, path, process):
        until = time.monotonic() + 8
        while time.monotonic() < until:
            if path.exists():
                return
            if process.poll() is not None:
                self.fail(f"driver exited before {path.name}; artifacts: {self.work}")
            time.sleep(.01)
        self.fail(f"readiness timed out; artifacts: {self.work}")

    def cooperative(self, *, interruption=None, repeated=False, timeout=None, workflow=False):
        pidfile, stopping, drained = [self.work / name for name in ("worker.pid", "stopping", "drained")]
        worker = self.work / "worker.mjs"
        worker.write_text("""import {writeFileSync} from 'node:fs';
process.on('SIGTERM', () => {
  writeFileSync(process.argv[3], 'requested');
  setTimeout(() => {writeFileSync(process.argv[4], 'drained'); process.exit(0);}, 300);
});
writeFileSync(process.argv[2], String(process.pid));
setTimeout(() => process.exit(8), 15000);
""")
        owner = self.work / "owner.mjs"
        owner.write_text("""import {runNativeProcess} from """ +
            json.dumps((ROOT / "scripts/lib/native-process-owner.mjs").as_uri()) + """;
const abort = new AbortController();
process.on('SIGTERM', () => abort.abort());
try {await runNativeProcess(process.execPath, process.argv.slice(2), {timeoutMs:10000, signal:abort.signal});}
catch(error) {console.error(JSON.stringify({code:error.code})); process.exitCode=2;}
""")
        process = self.driver(owner, worker, pidfile, stopping, drained, timeout=timeout, workflow=workflow)
        self.wait_file(pidfile, process)
        pid = int(pidfile.read_text())
        owned = [True]
        def stop_worker():
            # This exact PID was published by our private fixture. Its own
            # 15-second watchdog also bounds failure; no unrelated PID is used.
            if not owned[0]:
                return
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        self.addCleanup(stop_worker)
        if interruption is not None:
            process.send_signal(interruption)
        if repeated:
            self.wait_file(stopping, process)
            process.send_signal(signal.SIGTERM)
            process.send_signal(signal.SIGINT)
        self.assertNotEqual(process.wait(timeout=8), 0)
        self.assertTrue(drained.exists(), f"cooperative child was abandoned; artifacts: {self.work}")
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        owned[0] = False
        record = self.records()[-1]
        self.assertEqual(record["shutdown"], "owner_reaped_after_term")
        self.assertEqual(record["exit"], 2)
        self.assertEqual(record["native_effect"], "unknown")
        self.assertEqual(record["interruption"], "TimeoutExpired" if timeout else "InterruptedError")
        diagnostic = (self.work / "operator-001.stderr").read_text()
        self.assertIn("native_process_cancelled", diagnostic)
        return (self.work / "driver.stderr").read_text()

    def test_sigterm_drains_detached_native_child(self):
        self.assertIn("original interrupt 15", self.cooperative(interruption=signal.SIGTERM))

    def test_workflow_ndjson_adapter_drains_detached_native_child(self):
        self.assertIn("original interrupt 15", self.cooperative(interruption=signal.SIGTERM, workflow=True))

    def test_workflow_ndjson_adapter_preserves_stream_and_exact_refusal(self):
        from operator_workflow_smoke import node_rows
        rows = node_rows(self.campaign, Path("-e"), ["console.log('{}'); console.log('{\"complete\":true}');"])
        self.assertEqual(rows, [{}, {"complete": True}])
        self.assertEqual(node_rows(self.campaign, Path("-e"), [
            "console.error('{\"code\":\"refusal\"}'); process.exitCode=2;"], 2, error_reply=True), [{"code": "refusal"}])
        self.assertEqual(self.records()[-1]["exit"], 2)

    def test_workflow_ndjson_adapter_rejects_empty_and_nonobject_records(self):
        from operator_workflow_smoke import node_rows
        for script in ["", "console.log('[]');", "console.log('{}'); console.log('null');"]:
            with self.subTest(script=script), self.assertRaises((ValueError, AssertionError)):
                node_rows(self.campaign, Path("-e"), [script])

    def test_repeated_interrupts_do_not_preempt_drain(self):
        self.assertIn("original interrupt 2", self.cooperative(interruption=signal.SIGINT, repeated=True))

    def test_timeout_drains_detached_native_child(self):
        self.assertIn("TimeoutExpired", self.cooperative(timeout=3))

    def test_uncooperative_owner_reports_containment_failure(self):
        owner = self.work / "stubborn.mjs"
        ready = self.work / "ready"
        owner.write_text("import {writeFileSync} from 'node:fs';\n"
                         "process.on('SIGTERM', () => {});\n"
                         "writeFileSync(process.argv[2], 'ready');\n"
                         "setTimeout(() => process.exit(8), 15000);\n")
        process = self.driver(owner, ready)
        self.wait_file(ready, process)
        process.send_signal(signal.SIGTERM)
        self.assertNotEqual(process.wait(timeout=8), 0)
        record = self.records()[-1]
        self.assertEqual(record["shutdown"], "forced_owner_termination")
        self.assertEqual(record["native_effect"], "unknown")
        self.assertEqual(record["exit"], -signal.SIGKILL)
        self.assertIn("operator_owner_containment_failed", (self.work / "driver.stderr").read_text())

    def test_spawn_error_is_journaled(self):
        self.campaign.node = self.work / "missing-node"
        with self.assertRaises(FileNotFoundError):
            self.campaign.node_command(Path("-e"), ["console.log('{}')"])
        self.assertEqual(self.records()[-1]["spawn_error"], "FileNotFoundError")


if __name__ == "__main__":
    unittest.main()
