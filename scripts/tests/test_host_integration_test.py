#!/usr/bin/env python3
"""Explicit fake-tool command/receipt tests; not native product evidence."""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
HOST = "x86_64-unknown-linux-gnu"
TARGET = "differential_pinned_oracle"
FAKE_TOOL = r'''
import json, os, sys
from pathlib import Path
root = Path(os.environ["TEST_ROOT"])
target = Path(os.environ["CARGO_TARGET_DIR"])
case = os.environ.get("TEST_CASE", "")
log = Path(os.environ["TEST_LOG"])
if Path(sys.argv[0]).name == "rustc":
    print("host: " + os.environ.get("TEST_HOST", "x86_64-unknown-linux-gnu"))
    sys.exit(0)
args = sys.argv[1:]
with log.open("a") as out:
    out.write(json.dumps({"kind": "cargo", "args": args, "cwd": os.getcwd(),
                          "bypass": os.environ.get("RCH_CARGO_WRAPPER_BYPASS"),
                          "json_stdout": os.environ.get("RCH_CARGO_JSON_STDOUT")}) + "\n")
source = root / "crates/diff/tests/differential_pinned_oracle.rs"
manifest = root / "crates/diff/Cargo.toml"
if args[0] == "metadata":
    print(json.dumps({"target_directory": str(target), "workspace_members": ["local-package"],
          "packages": [{"id": "local-package", "name": "fgit-diff", "manifest_path": str(manifest),
                        "targets": [{"name": "differential_pinned_oracle", "kind": ["test"],
                                     "src_path": str(source)}]}]}))
    sys.exit(0)
if args[0] != "test" or "--no-run" not in args:
    sys.exit(91)
if case == "build_failure":
    sys.exit(103)
if case == "build_sleep":
    import signal, time
    def cancelled(signum, frame):
        with log.open("a") as out:
            out.write(json.dumps({"kind": "build_drained", "signal": signum}) + "\n")
        sys.exit(0)
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    with log.open("a") as out:
        out.write(json.dumps({"kind": "build_waiting"}) + "\n")
    time.sleep(20)
directory = target / "x86_64-unknown-linux-gnu/debug/deps"
if case.startswith("wrapped"):
    directory = target / "x86_64-unknown-linux-gnu/debug/build/fgit-diff/0123456789abcdef/out"
if case == "foreign":
    directory = target / "wasm32-unknown-unknown/debug/deps"
if case == "outside":
    directory = root / "unrelated-output"
if case == "parent_symlink":
    elsewhere = root / "elsewhere"
    elsewhere.mkdir()
    directory.parent.mkdir(parents=True)
    directory.symlink_to(elsewhere, target_is_directory=True)
else:
    directory.mkdir(parents=True, exist_ok=True)
executable = directory / "differential_pinned_oracle-a1b2"
if case.startswith("wrapped"):
    executable = directory / "differential_pinned_oracle-0123456789abcdef"
executable.write_text("#!" + sys.executable + "\n" +
    "import json, os, sys\n" +
    "with open(os.environ['TEST_LOG'], 'a') as out:\n" +
    " out.write(json.dumps({'kind':'native','args':sys.argv[1:],'cwd':os.getcwd(),"
    "'corpus':os.environ.get('FGIT_DIFF_DIFFERENTIAL_CORPUS')}) + '\\n')\n" +
    "sys.exit(int(os.environ.get('TEST_NATIVE_EXIT','0')))\n")
executable.chmod(0o700)
if case == "symlink":
    real = executable.with_suffix(".real")
    executable.rename(real)
    executable.symlink_to(real)
if case == "missing":
    executable.unlink()
if case == "not_executable":
    executable.chmod(0o600)
artifact = {"reason": "compiler-artifact", "package_id": "worker-path-package",
            "manifest_path": str(manifest), "target": {"kind": ["test"],
            "name": "differential_pinned_oracle", "src_path": str(source)},
            "profile": {"test": case != "wrong_mode"}, "executable": str(executable),
            "filenames": [str(executable)]}
if case.startswith("wrapped") and case != "wrapped_no_binding":
    artifact["rch"] = {"receipt": {"wrapper_id": "explicit-fake-contract"},
                       "worker_record": {"target": artifact["target"]},
                       "executable_blake3": "a" * 64}
    if case == "wrapped_bad_fingerprint":
        artifact["rch"]["executable_blake3"] = "not-a-fingerprint"
    if case == "wrapped_wrong_target":
        artifact["rch"]["worker_record"] = {"target": {"name": "unrelated", "kind": ["test"]}}
if case in ("wrong_manifest", "wrong_source"):
    other = root / "other"
    other.write_text("not selected")
    if case == "wrong_manifest":
        artifact["manifest_path"] = str(other)
    else:
        artifact["target"]["src_path"] = str(other)
if case == "missing_filename":
    artifact["filenames"] = []
if case == "malformed":
    print("not Cargo JSON")
if case != "no_artifact":
    print(json.dumps(artifact))
if case == "duplicate":
    print(json.dumps(artifact))
if case != "unfinished":
    print(json.dumps({"reason": "build-finished", "success": case != "failed_receipt"}))
if case == "partial_failure":
    sys.exit(101)
'''


class HostTestContract(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fgit host test contract ")
        self.base = Path(self.temporary.name)
        self.root = self.base / 'checkout with spaces "quotes"'
        self.bin = self.base / "fake tools"
        self.bin.mkdir()
        self.target = self.base / "private target λ"
        self.log = self.base / "commands.jsonl"
        helper = self.root / "scripts/run_host_integration_test.py"
        helper.parent.mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/run_host_integration_test.py", helper)
        self.helper = helper
        for relative in ("crates/diff/Cargo.toml", f"crates/diff/tests/{TARGET}.rs"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("explicit command-contract fixture")
        for name in ("cargo", "rustc"):
            path = self.bin / name
            path.write_text("#!" + sys.executable + "\n" + FAKE_TOOL)
            path.chmod(0o700)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "CARGO_TARGET_DIR": str(self.target), "CARGO_BUILD_TARGET": "wasm32-unknown-unknown",
                    "TEST_ROOT": str(self.root), "TEST_LOG": str(self.log),
                    "FGIT_DIFF_DIFFERENTIAL_CORPUS": "caller corpus with spaces"}
        for key in ("RCH_CARGO_WRAPPER_BYPASS", "RCH_CARGO_JSON_STDOUT", "CARGO_BUILD_JOBS"):
            self.env.pop(key, None)

    def tearDown(self):
        self.temporary.cleanup()

    def invoke(self, case="", expected=0, changes=None, args=None):
        env = {**self.env, "TEST_CASE": case, **(changes or {})}
        command = [sys.executable, str(self.helper)]
        command += args if args is not None else ["fgit-diff", TARGET, "--", "--ignored", "case with spaces"]
        result = subprocess.run(command, cwd=self.base, env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        rows = [json.loads(l) for l in self.log.read_text().splitlines()] if self.log.exists() else []
        if expected in (2, 101, 103):
            self.assertFalse(any(r["kind"] == "native" for r in rows), rows)
        return rows

    def test_wrapped_output_requires_exact_delivered_rch_binding(self):
        self.invoke("wrapped")
        for case in ("wrapped_no_binding", "wrapped_bad_fingerprint", "wrapped_wrong_target"):
            with self.subTest(case=case):
                # Each fake build needs a fresh output tree, as in separate invocations.
                if self.target.exists():
                    shutil.rmtree(self.target)
                self.log.unlink()
                self.invoke(case, expected=2)

    def test_real_selected_receipt_preserves_host_arguments_context_and_job_limit(self):
        rows = self.invoke(changes={"CARGO_BUILD_JOBS": "2"})
        build = next(r for r in rows if r["kind"] == "cargo" and r["args"][0] == "test")
        self.assertEqual(build["args"], ["test", "--locked", "--target", HOST, "--no-run", "-p",
                                        "fgit-diff", "--test", TARGET, "--message-format=json", "--jobs", "2"])
        self.assertIsNone(build["bypass"])
        self.assertEqual(build["json_stdout"], "1")
        native = next(r for r in rows if r["kind"] == "native")
        self.assertEqual(native["args"], ["--ignored", "case with spaces"])
        self.assertEqual(native["corpus"], "caller corpus with spaces")
        self.assertTrue(all(r["cwd"] == str(self.root) for r in rows))

    def test_native_nonzero_exit_is_preserved(self):
        self.invoke(expected=37, changes={"TEST_NATIVE_EXIT": "37"})

    def test_remote_refusal_is_preserved_without_local_execution(self):
        self.invoke("build_failure", expected=103)

    def test_nonzero_build_cannot_execute_a_partial_returned_artifact(self):
        self.invoke("partial_failure", expected=101)

    def test_receipt_and_output_boundary_refusals(self):
        for case in ("foreign", "outside", "parent_symlink", "symlink", "missing",
                     "not_executable", "wrong_mode", "wrong_manifest", "wrong_source",
                     "missing_filename", "malformed", "duplicate", "unfinished", "failed_receipt",
                     "no_artifact"):
            with self.subTest(case=case):
                self.log.unlink(missing_ok=True)
                # Each case owns a distinct output tree.
                self.env["CARGO_TARGET_DIR"] = str(self.base / ("target-" + case))
                self.invoke(case, expected=2)

    def test_rejects_forced_local_bypass_before_cargo(self):
        self.assertEqual(self.invoke(expected=2, changes={"RCH_CARGO_WRAPPER_BYPASS": "1"}), [])

    def test_rejects_malformed_host_before_cargo(self):
        self.assertEqual(self.invoke(expected=2, changes={"TEST_HOST": "bad host"}), [])

    def test_rejects_unknown_test_before_build(self):
        rows = self.invoke(expected=2, args=["fgit-diff", "unknown"])
        self.assertEqual([r["args"][0] for r in rows], ["metadata"])

    def test_rejects_unsafe_names_unseparated_arguments_and_invalid_jobs(self):
        for args in (["--workspace", TARGET], ["fgit-diff", TARGET, "--ignored"]):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(expected=2, args=args), [])
        self.assertEqual(self.invoke(expected=2, changes={"CARGO_BUILD_JOBS": "0"}), [])

    def test_cancellation_waits_for_build_child_and_never_executes_test(self):
        temporary = self.base / "owned temporary files"
        temporary.mkdir()
        env = {**self.env, "TEST_CASE": "build_sleep", "TMPDIR": str(temporary)}
        with (self.base / "output").open("w") as out, (self.base / "errors").open("w") as err:
            process = subprocess.Popen([sys.executable, str(self.helper), "fgit-diff", TARGET],
                                       env=env, stdout=out, stderr=err)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if self.log.exists() and '"build_waiting"' in self.log.read_text():
                        break
                    time.sleep(0.01)
                else:
                    self.fail("build child did not enter its controlled wait")
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=10), 128 + signal.SIGTERM)
                rows = [json.loads(l) for l in self.log.read_text().splitlines()]
                self.assertTrue(any(r["kind"] == "build_drained" for r in rows))
                self.assertEqual(next(r["signal"] for r in rows if r["kind"] == "build_drained"),
                                 signal.SIGINT)
                self.assertFalse(any(r["kind"] == "native" for r in rows))
                self.assertEqual(list(temporary.iterdir()), [])
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    unittest.main()
