#!/usr/bin/env bash
# Command-contract tests with explicit fake Cargo/compiler/tools. These do not
# establish a Rust checker pass, remote execution, or a product capability.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
"${PYTHON_BIN:-python3}" - "$ROOT" <<'PY'
import hashlib
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
        for name in ["scripts/verify.sh", "scripts/prepare_operator_native.py", "scripts/check_toolchain_bootstrap_links.sh",
                     "rust-toolchain.toml", "tooling-rust-bootstrap-links.md"]:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / name, destination)
        self.original_source = self.base / "original verify.sh"
        shutil.copy2(ROOT / "scripts/verify.sh", self.original_source)
        self.env["TEST_ORIGINAL_SOURCE"] = str(self.original_source)
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
    profile = "release" if "--release" in args else "debug"
    directory = Path(os.environ["TEST_TARGET"]) / args[args.index("--target") + 1] / profile
    directory.mkdir(parents=True, exist_ok=True)
    for i, arg in enumerate(args):
        if arg != "--bin": continue
        binary = directory / args[i + 1]
        binary.write_text("#!" + sys.executable + "\\n" + os.environ["TEST_NATIVE_BODY"])
        binary.chmod(int(os.environ.get("TEST_BINARY_MODE", "700"), 8))
        if os.environ.get("TEST_BINARY_SYMLINK"):
            actual = binary.with_suffix(".returned")
            binary.rename(actual)
            binary.symlink_to(actual)
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

    def invoke(self, lane="docs", expected=0, changes=None, unset=(), artifact=False):
        env = {**self.env, **(changes or {})}
        for key in unset: env.pop(key, None)
        switches = [] if artifact else ["--no-artifact"]
        result = subprocess.run(["bash", str(self.root / "scripts/verify.sh"), *switches, lane],
                                cwd=self.base, env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        records = [json.loads(row) for row in self.log.read_text().splitlines()] if self.log.exists() else []
        self.assertTrue(all(row["cwd"] == str(self.root) for row in records))
        self.assertFalse(any(row["args"][0] == "run" for row in records if row["kind"] == "cargo"))
        return result, records

    def test_replay_retains_both_streams_with_matching_digests(self):
        directory = self.base / "replay artifacts"
        result, _ = self.invoke(changes={"VERIFY_ARTIFACT_DIR":str(directory)}, artifact=True)
        receipts = list(directory.glob("*.json"))
        self.assertEqual(len(receipts), 1)
        receipt = json.loads(receipts[0].read_bytes())
        captured = (directory / receipt["captured_output_file"]).read_bytes()
        self.assertEqual(hashlib.sha256(captured).hexdigest(), receipt["captured_output_sha256"])
        self.assertTrue(captured.startswith(b"stdout\0"))
        stdout, stderr = captured[len(b"stdout\0"):].split(b"\0stderr\0", 1)
        self.assertEqual(stdout, result.stdout.encode())
        self.assertTrue(stdout.endswith(b"caller tool executed\n"))
        for name, stream in [("stdout", stdout), ("stderr", stderr)]:
            self.assertEqual(hashlib.sha256(stream).hexdigest(), receipt[name + "_sha256"])
        self.assertEqual(receipt["exit_code"], 0)

    def test_replay_preserves_quoted_unicode_command_arguments(self):
        original = self.root
        self.root = self.base / 'caller "quoted" \\ unicode-λ checkout'
        original.rename(self.root)
        directory = self.base / "quoted command replay"
        self.invoke(changes={"VERIFY_ARTIFACT_DIR":str(directory)}, artifact=True)
        receipt = json.loads(next(directory.glob("*.json")).read_bytes())
        self.assertEqual(receipt["command_argv"], [str(self.root / "scripts/verify.sh"), "docs"])

    def test_failed_checksum_process_publishes_no_replay(self):
        body = '''
import hashlib
data = sys.stdin.buffer.read()
counter = Path(os.environ["TEST_LOG"] + ".hash-count")
count = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(count))
failed = count == int(os.environ["TEST_HASH_AT"])
# Declared fault: emit a partial-input digest, then report failure.
print(hashlib.sha256(data[:len(data) // 2] if failed else data).hexdigest() + "  -")
sys.exit(74 if failed else 0)
'''
        self.command("sha256sum", body)
        self.command("shasum", body)
        shim = self.base / "controlled checksum selection.bash"
        shim.write_text('''command() {
  if [[ "$TEST_HASH_TOOL" == shasum && "${1-}" == -v && "${2-}" == sha256sum ]]; then
    return 1
  fi
  builtin command "$@"
}
''')
        for tool in ["sha256sum", "shasum"]:
            for at in [3, 4, 5]:  # Captured stdout, stderr, and framed output.
                for code in [0, 31]:
                    with self.subTest(tool=tool, hash_at=at, lane_exit=code):
                        counter = Path(str(self.log) + ".hash-count")
                        counter.unlink(missing_ok=True)
                        directory = self.base / f"failed {tool} hash {at} {code}"
                        result, _ = self.invoke(expected=code, artifact=True,
                            changes={"VERIFY_ARTIFACT_DIR":str(directory), "BASH_ENV":str(shim),
                                     "TEST_HASH_TOOL":tool, "TEST_HASH_AT":str(at),
                                     "TEST_NATIVE_EXIT":str(code)})
                        self.assertGreaterEqual(int(counter.read_text()), at)
                        self.assertEqual(list(directory.glob("*")), [])
                        self.assertIn("cannot hash", result.stderr)
                        self.assertTrue(result.stdout.endswith("caller tool executed\n"))

    def test_failed_json_escaping_publishes_no_replay_and_keeps_lane_exit(self):
        shim = self.base / "controlled JSON escape failure.bash"
        shim.write_text('''printf() {
  if [[ "${FUNCNAME[1]-}" == json_escape && "${1-}" == '%s' && ! -e "${TEST_LOG}.escape-failed" ]]; then
    case "$TEST_ESCAPE_CONTEXT:${FUNCNAME[*]}" in
      argv:*json_array*|metadata:*write_replay_artifact*)
        : > "${TEST_LOG}.escape-failed"
        builtin printf '%s' 'partial-escape"'
        return 74 ;;
    esac
  fi
  builtin printf "$@"
}
''')
        for context in ["argv", "metadata"]:
            for code in [0, 31]:
                with self.subTest(context=context, lane_exit=code):
                    marker = Path(str(self.log) + ".escape-failed")
                    marker.unlink(missing_ok=True)
                    directory = self.base / f"failed JSON escape {context} {code}"
                    result, _ = self.invoke(expected=code, artifact=True,
                        changes={"VERIFY_ARTIFACT_DIR":str(directory), "BASH_ENV":str(shim),
                                 "TEST_ESCAPE_CONTEXT":context, "TEST_NATIVE_EXIT":str(code)})
                    self.assertTrue(marker.is_file())
                    self.assertEqual(list(directory.glob("*")), [])
                    self.assertIn("replay artifact unavailable", result.stderr)
                    self.assertTrue(result.stdout.endswith("caller tool executed\n"))

    def replay_copy_failure(self, stream):
        # A declared cat double writes a real partial file and returns failure
        # once. Later replay succeeds, so it cannot mask the failed retention.
        self.command("cat", '''
path = Path(sys.argv[-1])
marker = Path(os.environ["TEST_LOG"] + ".copy-failed")
data = path.read_bytes()
if path.name.startswith("frankengit-verify-" + os.environ["TEST_COPY_STREAM"] + ".") and not marker.exists():
    marker.touch()
    sys.stdout.buffer.write(data[:len(data) // 2])
    sys.exit(74)
sys.stdout.buffer.write(data)
''')
        for code in [0, 31]:
            with self.subTest(stream=stream, lane_exit=code):
                marker = Path(str(self.log) + ".copy-failed")
                marker.unlink(missing_ok=True)
                directory = self.base / f"failed {stream} copy {code}"
                result, _ = self.invoke(expected=code, artifact=True,
                    changes={"VERIFY_ARTIFACT_DIR":str(directory), "TEST_COPY_STREAM":stream,
                             "TEST_NATIVE_EXIT":str(code)})
                self.assertTrue(marker.is_file())
                self.assertEqual(list(directory.iterdir()), [])
                self.assertIn("cannot retain captured output", result.stderr)
                self.assertTrue(result.stdout.endswith("caller tool executed\n"))

    def test_failed_stdout_retention_publishes_no_partial_replay(self):
        self.replay_copy_failure("stdout")

    def test_failed_stderr_retention_publishes_no_partial_replay(self):
        self.replay_copy_failure("stderr")

    def test_failed_metadata_write_publishes_no_partial_replay(self):
        shim = self.base / "controlled metadata write failure.bash"
        shim.write_text('''printf() {
  if [[ "${1-}" == "$TEST_METADATA_FORMAT" && ! -e "${TEST_LOG}.metadata-failed" ]]; then
    : > "${TEST_LOG}.metadata-failed"
    builtin printf 'partial-metadata'
    return 74
  fi
  builtin printf "$@"
}
''')
        # Fail the opening, an intermediate field, and the final write. The
        # actual partial file must never become a published replay receipt.
        for at, form in enumerate(['{', '"exit_code":%s,', '"captured_output_sha256":"%s"}\\n']):
            for code in [0, 31]:
                with self.subTest(write=at, lane_exit=code):
                    marker = Path(str(self.log) + ".metadata-failed")
                    marker.unlink(missing_ok=True)
                    directory = self.base / f"failed metadata write {at} {code}"
                    result, _ = self.invoke(expected=code, artifact=True,
                        changes={"VERIFY_ARTIFACT_DIR":str(directory), "BASH_ENV":str(shim),
                                 "TEST_METADATA_FORMAT":form, "TEST_NATIVE_EXIT":str(code)})
                    self.assertTrue(marker.is_file())
                    self.assertEqual(list(directory.iterdir()), [])
                    self.assertIn("cannot write", result.stderr)
                    self.assertTrue(result.stdout.endswith("caller tool executed\n"))

    def operator_fixture(self):
        # Dispatch-only doubles; the real shared runtime verifier owns the pin,
        # and no result from these tools is native/operator acceptance evidence.
        self.env["FGE_NODE"] = str(self.bin / "node")
        self.command("node", '''
record = {"kind": "node", "args": sys.argv[1:], "cwd": os.getcwd()}
with open(os.environ["TEST_LOG"], "a") as out: out.write(json.dumps(record) + "\\n")
if os.environ.get("TEST_NODE_EXIT"):
    print(json.dumps({"type":"controlled_runtime_refusal", "corpus_started":False}), file=sys.stderr)
    sys.exit(int(os.environ["TEST_NODE_EXIT"]))
''')
        self.command("git", '''
args = sys.argv[1:]
rows = [json.loads(line) for line in Path(os.environ["TEST_LOG"]).read_text().splitlines()]
count = sum(r["kind"] == "git" and r["args"] == args for r in rows)
with open(os.environ["TEST_LOG"], "a") as out:
    out.write(json.dumps({"kind":"git", "args":args, "cwd":os.getcwd()}) + "\\n")
if args == ["rev-parse", "--verify", "HEAD"]:
    moved = Path(os.environ["TEST_LOG"]).with_suffix(".moved").exists()
    print(("b" if moved or count and os.environ.get("TEST_SOURCE_MOVED") else "a") * 40)
elif args == ["status", "--porcelain=v1", "--untracked-files=all"]:
    if Path(os.environ["TEST_LOG"]).with_suffix(".unreadable").exists(): sys.exit(88)
    changed = Path("scripts/verify.sh").read_bytes() != Path(os.environ["TEST_ORIGINAL_SOURCE"]).read_bytes()
    if changed or os.environ.get("TEST_DIRTY_SOURCE") or (count and os.environ.get("TEST_SOURCE_DIRTY_AFTER")):
        print(" M tracked source")
else: sys.exit(92)
''')
        for name in ["operator/a.sh", "operator/nested/z.sh", "recovery/native_signed_bundle.sh"]:
            self.shell("scripts/e2e/suites/" + name, "# Explicit dispatch fixture; never executed.\n")
        self.shell("scripts/e2e/run_all.sh", '''
exec "$PYTHON_BIN" - "$@" <<'OPERATOR_DISPATCH'
import json, os, sys
from pathlib import Path
original = Path(os.environ["TEST_TARGET"]) / "''' + HOST + '''/release/fg"
selected = Path(os.environ["FG_BIN"])
assert selected != original and selected.resolve() == selected
assert selected.name == "fg" and selected.parent.name.startswith(".operator-native-")
assert selected.parent.parent == Path(os.environ["TEST_TARGET"]).resolve()
assert selected.parent.stat().st_mode & 0o777 == 0o700
assert selected.stat().st_mode & 0o777 == 0o500
assert selected.read_bytes() == original.read_bytes() and os.access(selected, os.X_OK)
row = {"kind":"suite", "args":sys.argv[1:], "cwd":os.getcwd(),
       "fg":os.environ["FG_BIN"], "node":os.environ.get("FGE_NODE"),
       "profile":os.environ.get("FGE_PROFILE"),
       "source_cut":os.environ.get("FG_SIGNED_BUNDLE_SOURCE_CUT")}
with open(os.environ["TEST_LOG"], "a") as out: out.write(json.dumps(row) + "\\n")
if os.environ.get("TEST_SOURCE_DIRTY_IN_SUITE"):
    with Path("scripts/verify.sh").open("a") as out: out.write("\\n# controlled campaign source mutation\\n")
if os.environ.get("TEST_SOURCE_MOVED_IN_SUITE"):
    Path(os.environ["TEST_LOG"]).with_suffix(".moved").touch()
if os.environ.get("TEST_SOURCE_UNREADABLE_IN_SUITE"):
    Path(os.environ["TEST_LOG"]).with_suffix(".unreadable").touch()
sys.exit(int(os.environ.get("TEST_SUITE_EXIT", "0")))
OPERATOR_DISPATCH
''')

    def test_operator_builds_once_and_runs_recursive_suites_with_signed_native_case(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", changes={"CARGO_BUILD_JOBS":"3", "FGE_E2E_TIMEOUT":"37",
                                                   "FG_BIN":"/stale-supplied-fg",
                                                   "FGE_PROFILE":"stale-supplied-profile",
                                                   "FG_SIGNED_BUNDLE_SOURCE_CUT":"c" * 40})
        self.assertEqual(rows[0]["kind"], "node")
        self.assertEqual(rows[0]["args"], [str(self.root / "scripts/verify_js.mjs"), "runtime"])
        builds = [r for r in rows if r["kind"] == "cargo" and r["args"][0] == "build"]
        self.assertEqual([r["args"] for r in builds], [["build", "--locked", "--target", HOST,
                         "--jobs", "3", "-p", "fgit-cli", "--bin", "fg", "--release"]])
        suite = next(r for r in rows if r["kind"] == "suite")
        self.assertEqual(suite["node"], self.env["FGE_NODE"])
        self.assertEqual(suite["profile"], "release")
        self.assertEqual(suite["source_cut"], "a" * 40)
        self.assertEqual(suite["args"], ["--timeout", "37", *[str(self.root / "scripts/e2e/suites" / p)
                         for p in ["operator/a.sh", "operator/nested/z.sh", "recovery/native_signed_bundle.sh"]]])

    def test_operator_installs_group_writable_build_output_without_modifying_it(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", changes={"TEST_BINARY_MODE": "775"})
        selected = Path(next(r for r in rows if r["kind"] == "suite")["fg"])
        original = self.target / HOST / "release/fg"
        self.assertEqual(original.stat().st_mode & 0o777, 0o775)
        self.assertEqual(selected.stat().st_mode & 0o777, 0o500)
        self.assertEqual(selected.read_bytes(), original.read_bytes())

    def test_operator_runtime_refusal_precedes_any_cargo(self):
        self.operator_fixture()
        result, rows = self.invoke("operator", 3, {"TEST_NODE_EXIT":"3"})
        self.assertEqual([r["kind"] for r in rows], ["node"])
        self.assertEqual(json.loads(result.stderr)["type"], "controlled_runtime_refusal")

    def test_operator_invalid_install_cannot_select_an_old_snapshot(self):
        self.operator_fixture()
        self.invoke("operator")
        self.log.write_text("")
        _, rows = self.invoke("operator", 2, {"TEST_BINARY_SYMLINK": "1"})
        self.assertFalse(any(r["kind"] == "suite" for r in rows))

    def test_operator_missing_node_is_typed_and_never_builds(self):
        self.operator_fixture()
        for path in [self.base / "missing-node", self.base]:
            with self.subTest(path=path):
                result, rows = self.invoke("operator", 3, {"FGE_NODE":str(path)})
                self.assertEqual(rows, [])
                self.assertEqual(json.loads(result.stderr)["code"], "js_runtime_unavailable")

    def test_operator_requires_a_private_target_after_runtime_check(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", 2, unset=("CARGO_TARGET_DIR",))
        self.assertEqual([r["kind"] for r in rows], ["node"])

    def test_operator_failed_build_cannot_run_a_stale_binary(self):
        self.operator_fixture()
        self.invoke("operator")
        self.log.write_text("")
        _, rows = self.invoke("operator", 42, {"TEST_BUILD_EXIT":"42"})
        self.assertFalse(any(r["kind"] == "suite" for r in rows))

    def test_operator_missing_returned_binary_never_runs_suites(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", 1, {"TEST_MISSING_BINARY":"1"})
        self.assertFalse(any(r["kind"] == "suite" for r in rows))

    def test_operator_missing_signed_native_suite_cannot_be_omitted(self):
        self.operator_fixture()
        (self.root / "scripts/e2e/suites/recovery/native_signed_bundle.sh").unlink()
        _, rows = self.invoke("operator", 1)
        self.assertEqual([r["kind"] for r in rows], ["node"])

    def test_operator_empty_discovery_never_runs_only_the_signed_case(self):
        self.operator_fixture()
        for name in ["a.sh", "nested/z.sh"]:
            (self.root / "scripts/e2e/suites/operator" / name).unlink()
        result, rows = self.invoke("operator", 1)
        self.assertIn("no operator suites discovered", result.stderr)
        self.assertEqual([r["kind"] for r in rows], ["node"])

    def test_operator_nonexecutable_suite_is_a_refusal_not_a_filter(self):
        self.operator_fixture()
        (self.root / "scripts/e2e/suites/operator/a.sh").chmod(0o600)
        _, rows = self.invoke("operator", 1)
        self.assertEqual([r["kind"] for r in rows], ["node"])

    def test_operator_suite_failure_preserves_exit(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", 31, {"TEST_SUITE_EXIT":"31"})
        self.assertEqual(len([r for r in rows if r["kind"] == "suite"]), 1)

    def test_operator_dirty_source_never_builds(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", 1, {"TEST_DIRTY_SOURCE":"1"})
        self.assertFalse(any(r["kind"] == "cargo" and r["args"][0] == "build" for r in rows))
        self.assertFalse(any(r["kind"] == "suite" for r in rows))

    def test_operator_source_revision_change_during_build_never_runs_suites(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", 1, {"TEST_SOURCE_MOVED":"1"})
        self.assertFalse(any(r["kind"] == "suite" for r in rows))

    def test_operator_source_dirtied_during_build_never_runs_suites(self):
        self.operator_fixture()
        _, rows = self.invoke("operator", 1, {"TEST_SOURCE_DIRTY_AFTER":"1"})
        self.assertFalse(any(r["kind"] == "suite" for r in rows))

    def test_operator_source_dirtied_during_campaigns_cannot_pass(self):
        self.operator_fixture()
        result, rows = self.invoke("operator", 1, {"TEST_SOURCE_DIRTY_IN_SUITE":"1"})
        self.assertEqual(len([r for r in rows if r["kind"] == "suite"]), 1)
        self.assertNotEqual((self.root / "scripts/verify.sh").read_bytes(), self.original_source.read_bytes())
        self.assertIn("source changed during operator campaigns", result.stderr)

    def test_operator_revision_moved_during_campaigns_cannot_pass(self):
        self.operator_fixture()
        result, rows = self.invoke("operator", 1, {"TEST_SOURCE_MOVED_IN_SUITE":"1"})
        self.assertEqual(len([r for r in rows if r["kind"] == "suite"]), 1)
        self.assertIn("source changed during operator campaigns", result.stderr)

    def test_operator_unreadable_source_after_campaigns_cannot_pass(self):
        self.operator_fixture()
        result, rows = self.invoke("operator", 1, {"TEST_SOURCE_UNREADABLE_IN_SUITE":"1"})
        self.assertEqual(len([r for r in rows if r["kind"] == "suite"]), 1)
        self.assertIn("cannot inspect source after operator campaigns", result.stderr)

    def test_operator_source_change_preserves_the_campaign_failure(self):
        self.operator_fixture()
        result, rows = self.invoke("operator", 31, {"TEST_SOURCE_DIRTY_IN_SUITE":"1", "TEST_SUITE_EXIT":"31"})
        self.assertEqual(len([r for r in rows if r["kind"] == "suite"]), 1)
        self.assertIn("source changed during operator campaigns", result.stderr)

    def test_operator_diagnostic_failure_cannot_replace_campaign_failure(self):
        self.operator_fixture()
        shim = self.base / "controlled printf failure.bash"
        shim.write_text('''printf() {
  case "${1-}" in
    'verify: source changed during operator campaigns'*)
      : > "${TEST_LOG}.printf-failed"
      return 1 ;;
  esac
  builtin printf "$@"
}
''')
        _, rows = self.invoke("operator", 31, {"TEST_SOURCE_DIRTY_IN_SUITE":"1",
                             "TEST_SUITE_EXIT":"31", "BASH_ENV":str(shim)})
        self.assertEqual(len([r for r in rows if r["kind"] == "suite"]), 1)
        self.assertTrue(Path(str(self.log) + ".printf-failed").is_file())

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
"${PYTHON_BIN:-python3}" "${ROOT}/scripts/tests/test_prepare_operator_native.py"
