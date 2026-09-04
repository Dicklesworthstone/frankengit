#!/usr/bin/env bash
# Hermetic command-contract tests, not Rust conformance or distribution proof.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
exec "${PYTHON_BIN:-python3}" - "$ROOT" <<'PY'
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(sys.argv.pop())
SUBJECT = ROOT / "scripts/check_toolchain_bootstrap_links.sh"
PIN = "nightly-2026-08-31"
ARCHIVE = "https://static.rust-lang.org/dist/2026-08-31/rust-nightly-x86_64-unknown-linux-gnu.tar.xz"
NOTE = f"# Bootstrap\n\nPinned `{PIN}`.\n\n- [Archive]({ARCHIVE})\n- [Checksum]({ARCHIVE}.sha256)\n"
MANIFEST = f'[toolchain]\nchannel = "{PIN}"\nprofile = "minimal"\ncomponents = ["rustfmt", "clippy"]\n'

class BootstrapLinks(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fgit bootstrap test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name) / "repository with spaces"
        self.root.mkdir()
        self.cwd = pathlib.Path(self.temporary.name) / "unrelated cwd"
        self.cwd.mkdir()
        self.env = {**os.environ, "PYTHON_BIN": sys.executable}
        self.write("rust-toolchain.toml", MANIFEST)
        self.write("tooling-rust-bootstrap-links.md", NOTE)

    def write(self, name, content):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))

    def snapshot(self):
        return {str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.root.rglob("*") if p.is_file()}

    def invoke(self, expected=0, diagnostic=None, args=None, env=None):
        before = self.snapshot()
        result = subprocess.run([str(SUBJECT), *(args if args is not None else ["--root", str(self.root)])],
                                cwd=self.cwd, env=env or self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(self.snapshot(), before, "preflight must never rewrite its inputs")
        if diagnostic:
            self.assertIn(diagnostic, result.stderr)
        if expected:
            self.assertEqual(result.stdout, "")
            self.assertNotIn("Traceback", result.stderr)
        return result

    def test_consistent_pin_from_unrelated_cwd_and_spaced_path(self):
        result = self.invoke()
        self.assertIn(PIN, result.stdout)
        self.assertEqual(result.stderr, "")

    def test_real_toml_single_quotes_comments_and_crlf(self):
        self.write("rust-toolchain.toml", f"# pin\r\n[toolchain]\r\n  channel = '{PIN}' # exact\r\n")
        self.write("tooling-rust-bootstrap-links.md", NOTE.replace("\n", "\r\n"))
        self.invoke()

    def test_valid_leap_day(self):
        self.write("rust-toolchain.toml", MANIFEST.replace("2026-08-31", "2024-02-29"))
        self.write("tooling-rust-bootstrap-links.md", NOTE.replace("2026-08-31", "2024-02-29"))
        self.invoke()

    def test_invalid_manifest_contracts(self):
        cases = {
            "floating nightly": '[toolchain]\nchannel="nightly"\n',
            "stable": '[toolchain]\nchannel="stable"\n',
            "beta": '[toolchain]\nchannel="beta"\n',
            "missing table": f'channel="{PIN}"\n',
            "missing channel": '[toolchain]\nprofile="minimal"\n',
            "wrong table type": 'toolchain="nightly"\n',
            "nonstring channel": '[toolchain]\nchannel=123\n',
            "array channel": f'[toolchain]\nchannel=["{PIN}"]\n',
            "malformed date": '[toolchain]\nchannel="nightly-2026-8-31"\n',
            "target suffix": f'[toolchain]\nchannel="{PIN}-x86_64-unknown-linux-gnu"\n',
            "invalid date": '[toolchain]\nchannel="nightly-2026-02-29"\n',
            "duplicate channel": MANIFEST + f'channel="{PIN}"\n',
            "duplicate table": MANIFEST + '[toolchain]\n',
            "malformed TOML": '[toolchain\nchannel="nightly"\n',
        }
        for name, manifest in cases.items():
            with self.subTest(name=name):
                self.write("rust-toolchain.toml", manifest)
                self.invoke(3, "toolchain-bootstrap: refused:")

    def test_declared_pin_is_unique_and_current(self):
        for note in [NOTE.replace(PIN, "nightly-2026-08-30"), NOTE.replace(f"`{PIN}`", "nightly"),
                     NOTE + f"\n`{PIN}`\n", NOTE + "\n`nightly`\n"]:
            with self.subTest(note=note):
                self.write("tooling-rust-bootstrap-links.md", note)
                self.invoke(3, "must declare exactly")

    def test_exact_archive_and_checksum_pair(self):
        cases = {
            "both stale": NOTE.replace("dist/2026-08-31/", "dist/2026-08-30/"),
            "mixed dates": NOTE.replace(ARCHIVE + ".sha256", ARCHIVE.replace("08-31", "08-30") + ".sha256"),
            "rolling archive": NOTE.replace("dist/2026-08-31/", "dist/"),
            "wrong target": NOTE.replace("x86_64", "aarch64"),
            "missing checksum": NOTE.replace(f"- [Checksum]({ARCHIVE}.sha256)\n", ""),
            "missing archive": NOTE.replace(f"- [Archive]({ARCHIVE})\n", ""),
            "duplicate archive": NOTE + f"\n[Duplicate]({ARCHIVE})\n",
            "insecure scheme": NOTE.replace("https://", "http://"),
            "unapproved mirror": NOTE.replace("static.rust-lang.org", "mirror.example.invalid"),
            "query": NOTE.replace(ARCHIVE + ")", ARCHIVE + "?source=latest)"),
            "fragment": NOTE.replace(ARCHIVE + ")", ARCHIVE + "#latest)"),
            "extra download": NOTE + "\n[Other](https://example.invalid/archive)\n",
        }
        for name, note in cases.items():
            with self.subTest(name=name):
                self.write("tooling-rust-bootstrap-links.md", note)
                self.invoke(3, "bootstrap URLs do not match")

    def test_missing_unreadable_and_oversized_inputs(self):
        for name, normal in [("rust-toolchain.toml", MANIFEST), ("tooling-rust-bootstrap-links.md", NOTE)]:
            for content in [None, b"\xff", b"x" * (1024 * 1024 + 1)]:
                with self.subTest(name=name, content="missing" if content is None else len(content)):
                    if content is None:
                        (self.root / name).unlink()
                    else:
                        self.write(name, content)
                    self.invoke(3, name)
                    self.write(name, normal)

    def test_missing_root_refuses(self):
        self.invoke(3, "rust-toolchain.toml", ["--root", str(self.root / "absent")])

    def test_usage(self):
        for args in [["--root"], ["--root", ""], ["--unknown"], ["--root", str(self.root), "extra"]]:
            with self.subTest(args=args):
                self.invoke(2, "usage:", args)
        result = self.invoke(args=["--help"])
        self.assertIn("usage:", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_missing_python_is_unavailable_not_consistency(self):
        self.invoke(2, "Python 3.11+ is required", env={**self.env, "PYTHON_BIN": str(self.root / "absent-python")})

    def test_docs_lane_checks_metadata_before_cargo(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        shutil.copy2(SUBJECT, scripts / SUBJECT.name)
        shutil.copy2(ROOT / "scripts/verify.sh", scripts / "verify.sh")
        binary_dir = self.root / "bin"
        binary_dir.mkdir()
        cargo = binary_dir / "cargo"
        cargo.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"$CARGO_CALLS\"\nexit 37\n", encoding="utf-8")
        cargo.chmod(0o755)
        calls = self.cwd / "cargo-calls"
        env = {**self.env, "PATH": str(binary_dir) + os.pathsep + os.environ["PATH"], "CARGO_CALLS": str(calls)}
        for note, expected in [(NOTE, 37), (NOTE.replace("dist/2026-08-31/", "dist/2026-08-30/"), 3)]:
            with self.subTest(note=note):
                calls.unlink(missing_ok=True)
                self.write("tooling-rust-bootstrap-links.md", note)
                before = self.snapshot()
                result = subprocess.run([str(scripts / "verify.sh"), "--no-artifact", "docs"],
                                        cwd=self.cwd, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertEqual(self.snapshot(), before)
                if expected == 37:
                    self.assertEqual(calls.read_text(), "run --locked -p fgit-registry-check -- docs\n")
                else:
                    self.assertFalse(calls.exists(), "metadata refusal must prevent the Cargo call")
                    self.assertIn("bootstrap URLs do not match", result.stderr)

    def test_default_root_is_script_relative(self):
        target = self.root / "scripts/check_toolchain_bootstrap_links.sh"
        target.parent.mkdir()
        shutil.copy2(SUBJECT, target)
        before = self.snapshot()
        result = subprocess.run([str(target)], cwd=self.cwd, env=self.env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.snapshot(), before)

unittest.main(verbosity=2)
PY
