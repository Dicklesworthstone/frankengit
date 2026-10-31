#!/usr/bin/env python3
"""Build one integration test through caller Cargo/RCH, then execute it here.

The merge differential consumes a local pinned-oracle corpus. Remote test
execution cannot read that corpus, and forcing local compilation violates the
repository contract. Select the returned executable from this build's Cargo
receipt; never discover a possibly stale executable by globbing the target.
"""

import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
MAX_JSON_BYTES = 64 * 1024 * 1024
ACTIVE_CHILD = None
STOP_SIGNAL = None


class Cancelled(Exception):
    pass


def request_stop(signum, _frame):
    global STOP_SIGNAL
    if STOP_SIGNAL is None:
        STOP_SIGNAL = signum
    if ACTIVE_CHILD is not None:
        try:
            ACTIVE_CHILD.send_signal(signum)
        except ProcessLookupError:
            pass


def require(condition, message):
    if not condition:
        raise ValueError(message)


def absolute_path(value):
    require(isinstance(value, str) and value and not any(c in value for c in "\0\r\n"),
            "expected a path without control separators")
    path = Path(value)
    require(path.is_absolute(), "expected an absolute path")
    return path


def read_text(path):
    require(path.stat().st_size <= MAX_JSON_BYTES, "Cargo output exceeds the 64 MiB receipt limit")
    return path.read_text(encoding="utf-8")


def capture(argv, output, env=None):
    global ACTIVE_CHILD
    if STOP_SIGNAL is not None:
        raise Cancelled(STOP_SIGNAL)
    with output.open("wb") as stream:
        child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=stream)
        ACTIVE_CHILD = child
        try:
            if STOP_SIGNAL is not None:
                request_stop(STOP_SIGNAL, None)
            status = child.wait()
        finally:
            ACTIVE_CHILD = None
    if STOP_SIGNAL is not None:
        raise Cancelled(STOP_SIGNAL)
    if status:
        raise subprocess.CalledProcessError(status, argv)


def select_executable(metadata, records, package, target, host, private_target):
    target_root = absolute_path(metadata["target_directory"]).resolve()
    require(target_root == private_target.resolve(), "Cargo changed the private target directory")
    members = metadata["workspace_members"]
    packages = [p for p in metadata["packages"] if p["name"] == package and p["id"] in members]
    require(len(packages) == 1, "expected one selected workspace package")
    selected = packages[0]
    manifest = absolute_path(selected["manifest_path"]).resolve(strict=True)
    require(manifest.is_file() and manifest.is_relative_to(ROOT), "package manifest escapes this checkout")
    targets = [t for t in selected["targets"] if t["name"] == target and t["kind"] == ["test"]]
    require(len(targets) == 1, "expected one named integration test")
    source = absolute_path(targets[0]["src_path"]).resolve(strict=True)
    require(source.is_file() and source.is_relative_to(ROOT), "test source escapes this checkout")
    finished = [r for r in records if r.get("reason") == "build-finished"]
    require(len(finished) == 1 and finished[0].get("success") is True,
            "Cargo did not report one successful completed build")
    artifacts = [r for r in records if r.get("reason") == "compiler-artifact"
                 and r.get("target", {}).get("name") == target
                 and r.get("target", {}).get("kind") == ["test"]]
    require(len(artifacts) == 1, "expected one unambiguous test executable receipt")
    artifact = artifacts[0]
    require(artifact.get("profile", {}).get("test") is True, "artifact is not a test executable")
    # RCH projects these paths back to the caller. Its package_id may retain
    # the worker's path, so bind the actual manifest and test source instead.
    require(absolute_path(artifact["manifest_path"]).resolve(strict=True) == manifest,
            "artifact belongs to another package")
    require(absolute_path(artifact["target"]["src_path"]).resolve(strict=True) == source,
            "artifact belongs to another test source")
    executable = absolute_path(artifact["executable"])
    require(str(executable) in artifact["filenames"], "executable is absent from Cargo filenames")
    require(not executable.is_symlink(), "test executable is a symlink")
    executable = executable.resolve(strict=True)
    require(executable.parent == target_root / host / "debug" / "deps",
            "test executable is outside the private native host output")
    require(stat.S_ISREG(executable.stat().st_mode) and os.access(executable, os.X_OK),
            "returned test executable is missing or not executable")
    return executable


def main(argv):
    require(len(argv) >= 2, "usage: run_host_integration_test.py PACKAGE TEST [-- TEST-ARGS...]")
    package, target, *rest = argv
    require(all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_-]*", value) for value in (package, target)),
            "package and test must be literal Cargo names")
    require(not rest or rest[0] == "--", "test arguments must follow --")
    test_args = rest[1:] if rest else []
    require(os.environ.get("RCH_CARGO_WRAPPER_BYPASS", "").lower() in ("", "0", "false", "no", "off"),
            "forced local Cargo bypass is not permitted")
    private_target = absolute_path(os.environ.get("CARGO_TARGET_DIR"))
    require(private_target.resolve() != (ROOT / "target").resolve(), "set a pane-private target directory")
    jobs = os.environ.get("CARGO_BUILD_JOBS")
    require(jobs is None or re.fullmatch(r"[1-9][0-9]*", jobs), "invalid compiler job limit")
    with tempfile.TemporaryDirectory(prefix="fgit-host-test-") as temporary:
        temporary = Path(temporary)
        version = temporary / "rustc.txt"
        capture(["rustc", "-vV"], version)
        hosts = [line.removeprefix("host: ") for line in read_text(version).splitlines()
                 if line.startswith("host: ")]
        require(len(hosts) == 1 and re.fullmatch(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+)+", hosts[0]),
                "cannot determine one native caller host")
        host = hosts[0]
        metadata_path = temporary / "metadata.json"
        capture(["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], metadata_path)
        metadata = json.loads(read_text(metadata_path))
        # Validate the requested package/test before starting a remote build.
        packages = [p for p in metadata["packages"] if p["name"] == package
                    and p["id"] in metadata["workspace_members"]]
        require(len(packages) == 1 and any(t["name"] == target and t["kind"] == ["test"]
                                          for t in packages[0]["targets"]),
                "named integration test is not in this workspace")
        require(absolute_path(metadata["target_directory"]).resolve() == private_target.resolve(),
                "Cargo changed the private target directory")
        output = temporary / "artifacts.jsonl"
        command = ["cargo", "test", "--locked", "--target", host, "--no-run", "-p", package,
                   "--test", target, "--message-format=json"]
        if jobs is not None:
            command += ["--jobs", jobs]
        capture(command, output, {**os.environ, "RCH_CARGO_JSON_STDOUT": "1"})
        records = [json.loads(line) for line in read_text(output).splitlines() if line.strip()]
        require(all(isinstance(r, dict) for r in records), "Cargo emitted a non-object receipt")
        executable = select_executable(metadata, records, package, target, host, private_target)
    # No receipt files or remote build obligations survive into local test
    # execution. Replace this process so the existing E2E owner reaps the test.
    # Once cleanup has finished, signals must terminate this process or its
    # replacement rather than get consumed in the small interval before exec.
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    if STOP_SIGNAL is not None:
        raise Cancelled(STOP_SIGNAL)
    os.chdir(ROOT)
    print(f"host-test: executing returned native test {executable}", file=sys.stderr)
    os.execv(str(executable), [str(executable), *test_args])


if __name__ == "__main__":
    try:
        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        main(sys.argv[1:])
    except Cancelled as error:
        sys.exit(128 + error.args[0])
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode if error.returncode >= 0 else 128 - error.returncode)
    except (ValueError, KeyError, TypeError, AttributeError, OSError) as error:
        print(f"host-test: refused: {error}", file=sys.stderr)
        sys.exit(2)
