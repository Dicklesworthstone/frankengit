#!/usr/bin/env bash
# Command-contract tests with explicit fake Cargo/compiler/tools. These do not
# establish a Rust checker pass, remote execution, or a product capability.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
"${PYTHON_BIN:-python3}" - "$ROOT" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(sys.argv.pop())
HOST = "x86_64-unknown-linux-gnu"

class NativeVerificationTools(unittest.TestCase):
    def setUp(self):
        # Retain fixtures and logs for inspection; never remove caller files.
        self.base = Path(tempfile.mkdtemp(prefix="fgit verify contract ")).resolve()
        self.root = self.base / "caller checkout"
        self.bin = self.base / "fake commands"
        self.bin.mkdir()
        self.target = self.base / 'target with spaces "quotes" and \\ unicode-λ'
        self.log = self.base / "commands.jsonl"
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                    "PYTHON_BIN": sys.executable, "TEST_LOG": str(self.log),
                    "TEST_TARGET": str(self.target), "CARGO_TARGET_DIR": str(self.target),
                    "CARGO_BUILD_TARGET": "wasm32-unknown-unknown",
                    "CARGO_MANIFEST_DIR": str(self.base / "remote checkout/tools/registry-check")}
        self.env.pop("RCH_CARGO_WRAPPER_BYPASS", None)
        self.env.pop("CARGO_BUILD_JOBS", None)
        for name in ["scripts/verify.sh", "scripts/check_toolchain_bootstrap_links.sh",
                     "rust-toolchain.toml", "tooling-rust-bootstrap-links.md"]:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        self.command("rustc", 'print("host: " + os.environ.get("TEST_HOST", "' + HOST + '"))')
        self.command("cargo", '''
record = {"kind": "cargo", "args": sys.argv[1:], "cwd": os.getcwd(),
          "bypass": os.environ.get("RCH_CARGO_WRAPPER_BYPASS"),
          "build_target": os.environ.get("CARGO_BUILD_TARGET")}
with open(os.environ["TEST_LOG"], "a") as f: f.write(json.dumps(record) + "\\n")
args = sys.argv[1:]
if args[0] == "metadata":
    if os.environ.get("TEST_METADATA_EXIT"): sys.exit(int(os.environ["TEST_METADATA_EXIT"]))
    print(os.environ.get("TEST_METADATA", json.dumps({"target_directory": os.environ["TEST_TARGET"]})))
elif args[0] == "build":
    if os.environ.get("TEST_BUILD_EXIT"): sys.exit(int(os.environ["TEST_BUILD_EXIT"]))
    if os.environ.get("TEST_MISSING_BINARY"): sys.exit(0)
    directory = Path(os.environ["TEST_TARGET"]) / args[args.index("--target") + 1] / "debug"
    directory.mkdir(parents=True, exist_ok=True)
    for i, arg in enumerate(args):
        if arg != "--bin": continue
        binary = directory / args[i + 1]
        binary.write_text("#!" + sys.executable + "\\n" + os.environ["TEST_NATIVE_BODY"])
        binary.chmod(0o700)
elif args[0] not in ["fmt", "check", "test", "clippy"]:
    print("unexpected Cargo command", args, file=sys.stderr); sys.exit(91)
''')
        self.env["TEST_NATIVE_BODY"] = '''
import json, os, sys
from pathlib import Path
record = {"kind": "native", "binary": Path(sys.argv[0]).name, "args": sys.argv[1:],
          "cwd": os.getcwd(), "build_target": os.environ.get("CARGO_BUILD_TARGET")}
with open(os.environ["TEST_LOG"], "a") as f: f.write(json.dumps(record) + "\\n")
print("caller tool executed")
sys.exit(int(os.environ.get("TEST_NATIVE_EXIT", "0")))
'''
        self.shell("scripts/tests/verify_test.sh", "exit 0\n")
        self.shell("scripts/license_gate.sh", 'exit "${TEST_LICENSE_EXIT:-0}"\n')
        self.shell("scripts/e2e/suites/example.sh", "# fge_kind js-unit\nfge_kind js-unit\n")
        self.shell("scripts/e2e/run_all.sh", '''
test "$FG_BIN" = "$TEST_TARGET/''' + HOST + '''/debug/fg"
test "$FG_MCP_BIN" = "$TEST_TARGET/''' + HOST + '''/debug/fg-mcp"
test -x "$FG_BIN" && test -x "$FG_MCP_BIN"
''')

    def shell(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + body)
        path.chmod(0o700)

    def command(self, name, body):
        path = self.bin / name
        path.write_text("#!" + sys.executable + "\nimport json, os, sys\nfrom pathlib import Path\n" + body + "\n")
        path.chmod(0o700)

    def invoke(self, lane="docs", expected=0, changes=None, unset=()):
        env = {**self.env, **(changes or {})}
        for key in unset: env.pop(key, None)
        result = subprocess.run(["bash", str(self.root / "scripts/verify.sh"), "--no-artifact", lane],
                                cwd=self.base, env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        records = [json.loads(row) for row in self.log.read_text().splitlines()] if self.log.exists() else []
        self.assertTrue(all(row["cwd"] == str(self.root) for row in records))
        self.assertFalse(any(row["args"][0] == "run" for row in records if row["kind"] == "cargo"))
        return result, records

    def test_docs_builds_native_but_reads_caller_even_with_remote_manifest_environment(self):
        _, rows = self.invoke()
        build = next(r for r in rows if r["kind"] == "cargo" and r["args"][0] == "build")
        self.assertIsNone(build["bypass"])
        self.assertEqual(build["args"], ["build", "--locked", "--target", HOST,
                                         "-p", "fgit-registry-check", "--bin", "fgit-registry-check"])
        native = [r for r in rows if r["kind"] == "native"]
        self.assertEqual(native[0]["args"], ["docs", "--root", str(self.root)])

    def test_constitution_keeps_configured_target_for_linkage_checks(self):
        _, rows = self.invoke("constitution")
        native = next(r for r in rows if r["kind"] == "native")
        self.assertEqual(native["args"], ["constitution", "--root", str(self.root)])
        self.assertEqual(native["build_target"], "wasm32-unknown-unknown")

    def test_fast_checks_caller_schema_paths_and_keeps_workspace_test_denominator(self):
        _, rows = self.invoke("fast")
        schema = next(r for r in rows if r.get("binary") == "fgit-schema-gen")
        self.assertEqual(schema["args"], ["check", str(self.root / "crates/fgit-schema/generated"),
                                           "--workspace-root", str(self.root)])
        tests = next(r for r in rows if r["kind"] == "cargo" and r["args"][0] == "test")
        self.assertEqual(tests["args"], ["test", "--workspace", "--all-targets", "--locked", "--no-fail-fast"])

    def test_fast_forwards_requested_jobs_to_every_compiler_without_losing_gate_arguments(self):
        for jobs in ["1", "3"]:
            with self.subTest(jobs=jobs):
                self.log = self.base / ("commands-jobs-" + jobs + ".jsonl")
                _, rows = self.invoke("fast", changes={"CARGO_BUILD_JOBS": jobs,
                                                       "TEST_LOG": str(self.log)})
                work = [r for r in rows if r["kind"] == "cargo"
                        and r["args"][0] in ["check", "test", "clippy"]]
                self.assertEqual([r["args"] for r in work], [
                    ["check", "--jobs", jobs, "--workspace", "--all-targets", "--locked"],
                    ["test", "--jobs", jobs, "--workspace", "--all-targets", "--locked", "--no-fail-fast"],
                    ["clippy", "--jobs", jobs, "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
                ])
                builds = [r for r in rows if r["kind"] == "cargo" and r["args"][0] == "build"]
                self.assertEqual(len(builds), 3)
                self.assertTrue(all(r["args"][1:6] == ["--locked", "--target", HOST, "--jobs", jobs]
                                    for r in builds))
                self.assertTrue(all(r["bypass"] is None for r in work + builds))

    def test_e2e_builds_both_returned_native_binaries_once(self):
        _, rows = self.invoke("e2e")
        builds = [r for r in rows if r["kind"] == "cargo" and r["args"][0] == "build"]
        self.assertEqual(len(builds), 1)
        self.assertEqual(builds[0]["args"], ["build", "--locked", "--target", HOST,
                                            "-p", "fgit-cli", "--bin", "fg", "--bin", "fg-mcp"])

    def test_native_build_job_cap_is_explicit_for_remote_compiler_and_scheduler(self):
        for lane in ["docs", "e2e"]:
            with self.subTest(lane=lane):
                _, rows = self.invoke(lane, changes={"CARGO_BUILD_JOBS": "1"})
                build = [r for r in rows if r["kind"] == "cargo" and r["args"][0] == "build"][-1]
                self.assertEqual(build["args"][1:6], ["--locked", "--target", HOST, "--jobs", "1"])

    def test_release_runs_probe_and_stays_dormant(self):
        _, rows = self.invoke("release", 3)
        native = next(r for r in rows if r["kind"] == "native")
        self.assertEqual(native["binary"], "fgit-release-attempt")
        self.assertEqual(native["args"], ["--release-gate-probe"])

    def test_license_refusal_precedes_any_cargo(self):
        _, rows = self.invoke("release", 3, {"TEST_LICENSE_EXIT": "3"})
        self.assertEqual(rows, [])

    def test_full_refusal_needs_no_cargo_or_target_directory(self):
        _, rows = self.invoke("full", 3, unset=("CARGO_TARGET_DIR",))
        self.assertEqual(rows, [])

    def test_missing_private_target_is_actionable_and_does_not_build(self):
        result, rows = self.invoke(expected=2, unset=("CARGO_TARGET_DIR",))
        self.assertIn("CARGO_TARGET_DIR", result.stderr)
        self.assertFalse(any(r["args"][0] == "build" for r in rows))

    def test_failed_build_never_runs_stale_returned_tool(self):
        self.invoke()  # near-identical permitted twin leaves an old executable
        self.log.write_text("")
        _, rows = self.invoke(expected=42, changes={"TEST_BUILD_EXIT": "42"})
        self.assertFalse(any(r["kind"] == "native" for r in rows))

    def test_missing_returned_executable_refuses(self):
        result, rows = self.invoke(expected=1, changes={"TEST_MISSING_BINARY": "1"})
        self.assertIn("no returned native executable", result.stderr)
        self.assertFalse(any(r["kind"] == "native" for r in rows))

    def test_checker_refusal_is_not_replaced_by_build_success(self):
        _, rows = self.invoke(expected=17, changes={"TEST_NATIVE_EXIT": "17"})
        self.assertEqual(len([r for r in rows if r["kind"] == "native"]), 1)

    def test_metadata_failure_preserves_exit(self):
        self.invoke(expected=61, changes={"TEST_METADATA_EXIT": "61"})

    def test_invalid_metadata_and_host_fail_before_build(self):
        for changes in [{"TEST_METADATA": "not JSON"}, {"TEST_METADATA": "{}"},
                        {"TEST_METADATA": '{"target_directory":"relative"}'},
                        {"TEST_HOST": ""}, {"TEST_HOST": "bad target"}]:
            with self.subTest(changes=changes):
                result, rows = self.invoke(expected=2, changes=changes)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(any(r["args"][0] == "build" for r in rows))

    def test_explicit_operator_environment_is_preserved(self):
        _, rows = self.invoke(changes={"RCH_CARGO_WRAPPER_BYPASS": "operator-selected"})
        self.assertTrue(all(r["bypass"] == "operator-selected" for r in rows if r["kind"] == "cargo"))

unittest.main()
PY
"${PYTHON_BIN:-python3}" "${ROOT}/scripts/tests/test_host_integration_test.py"
