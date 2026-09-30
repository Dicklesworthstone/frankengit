#!/usr/bin/env python3
"""Drive a built fg binary; fixture-only mode never claims native execution.

Fixture construction uses Python's independent hashlib/zlib. Git runs only in
this explicit test fixture preflight, never in the product implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import zlib


def oid(kind: str, body: bytes, algorithm: str) -> str:
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def record(kind: int, body: bytes, level: int) -> bytes:
    size = len(body)
    byte = (kind << 4) | (size & 15)
    size >>= 4
    header = bytearray()
    while size:
        header.append(byte | 128)
        byte, size = size & 127, size >> 7
    header.append(byte)
    return bytes(header) + zlib.compress(body, level)


def fixture(algorithm: str, *, level: int = 6, omit_blob: bool = False) -> tuple[bytes, dict[str, str]]:
    blob = b"binary\0data\xff\r\n"
    blob_id = oid("blob", blob, algorithm)
    tree = b"100644 file\0" + bytes.fromhex(blob_id)
    tree_id = oid("tree", tree, algorithm)
    commit = (f"tree {tree_id}\nauthor A <a@example.invalid> 1700000000 +0000\n"
              "committer A <a@example.invalid> 1700000000 +0000\n\nsource backup\n").encode()
    commit_id = oid("commit", commit, algorithm)
    tag = (f"object {commit_id}\ntype commit\ntag release\n"
           "tagger A <a@example.invalid> 1700000000 +0000\n\nrelease\n").encode()
    tag_id = oid("tag", tag, algorithm)
    refs = {b"refs/heads/main".hex(): commit_id, b"refs/tags/release".hex(): tag_id,
            b"refs/tags/\xff".hex(): commit_id}
    header = b"# v2 git bundle\n" if algorithm == "sha1" else b"# v3 git bundle\n@object-format=sha256\n"
    header += b"".join(value.encode() + b" " + bytes.fromhex(name) + b"\n" for name, value in refs.items())
    header += commit_id.encode() + b" HEAD\n\n"
    objects = [(3, blob), (2, tree), (1, commit), (4, tag)]
    if omit_blob:
        objects = objects[1:]
    pack = b"PACK" + struct.pack(">II", 2, len(objects)) + b"".join(record(kind, body, level) for kind, body in objects)
    return header + pack + hashlib.new(algorithm, pack).digest(), refs


def git_preflight(root: Path, data: bytes, algorithm: str) -> dict[str, object]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("fixture preflight requires an explicitly installed Git test oracle")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    home = root / "home"
    home.mkdir()
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, LC_ALL="C")
    target = root / "oracle.git"
    bundle = root / "fixture.bundle"
    bundle.write_bytes(data)

    def run(*args: str) -> str:
        process = subprocess.run([git, *args], env=env, capture_output=True, timeout=30)
        if process.returncode:
            raise RuntimeError(process.stderr.decode("utf-8", "replace"))
        return process.stdout.decode("utf-8", "replace").strip()

    run("init", "--bare", f"--object-format={algorithm}", str(target))
    run("-C", str(target), "bundle", "verify", str(bundle))
    run("-C", str(target), "fetch", "--no-tags", str(bundle), "+refs/*:refs/*")
    run("-C", str(target), "fsck", "--strict", "--full")
    assert hashlib.sha256(bundle.read_bytes()).digest() == hashlib.sha256(data).digest()
    return {"format": algorithm, "fixture_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "oracle": run("--version"), "bundle_verify_fetch_fsck": True}


def exercise(fg: Path, root: Path, algorithm: str) -> int:
    data, refs = fixture(algorithm)
    path = root / "input.bundle"
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    first = next(iter(refs))
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PATH"] = str(root / "no-tools")
    cases = 0

    def run(arguments: list[str], error: str | None = None) -> dict[str, object] | None:
        nonlocal cases
        result = subprocess.run([str(fg), "bundle", "verify", *arguments], env=env,
                                capture_output=True, text=True, timeout=45)
        cases += 1
        if error is not None:
            assert result.returncode == 2 and result.stdout == "", (arguments, result.returncode, result.stdout, result.stderr)
            if error:
                assert error in result.stderr, (error, result.stderr)
            return None
        assert result.returncode == 0 and result.stderr == "", (arguments, result.stdout, result.stderr)
        report = json.loads(result.stdout)
        assert report["object_graph_verified"] is True
        for key in ("origin_authenticated", "signatures_verified", "repository_opened", "repository_changed"):
            assert report[key] is False
        return report

    plain = run([str(path)])
    assert plain is not None and "caller_expectations_matched" not in plain
    basic = [str(path), "--expect-format", algorithm, "--expect-ref", f"refs/heads/main={algorithm}:{refs[first]}"]
    report = run(basic)
    assert report is not None and report["expectations"]["ref_set"] == "contains"
    exact = [str(path), "--expect-format", algorithm, "--exact-refs"]
    for name, target in refs.items():
        exact += ["--expect-ref-hex", f"{name}={target}"]
    report = run([*exact, "--expect-sha256", digest])
    assert report is not None and report["caller_expectations_matched"] is True
    assert report["expectations"]["ref_set"] == "exact"
    assert report["reference_count"] == 3
    run([str(path), "--expect-sha256", digest])
    run([str(path), "--expect-sha256", "0" * 64], "expected_bundle_artifact_mismatch")
    run([*basic, "--exact-refs"], "expected_reference_set_mismatch")
    wrong = "f" * (40 if algorithm == "sha1" else 64)
    run([str(path), "--expect-format", algorithm, "--expect-ref", f"refs/heads/main={wrong}"], "expected_reference_mismatch")
    run([str(path), "--expect-format", algorithm, "--expect-ref", f"refs/heads/missing={refs[first]}"], "expected_reference_missing")
    other = "sha256" if algorithm == "sha1" else "sha1"
    run([str(path), "--expect-format", other, "--expect-sha256", digest], "expected_bundle_format_mismatch")
    for arguments in (["--expect-format", algorithm], ["--expect-ref", f"refs/heads/main={refs[first]}"],
                      ["--expect-format", algorithm, "--expect-ref", "HEAD=" + refs[first]],
                      ["--expect-sha256", "bad"], ["--exact-refs"]):
        run([str(root / "does-not-exist"), *arguments], "")
    repacked, _ = fixture(algorithm, level=0)
    assert repacked != data
    path.write_bytes(repacked)
    run(exact)
    run([*exact, "--expect-sha256", digest], "expected_bundle_artifact_mismatch")
    missing, _ = fixture(algorithm, omit_blob=True)
    path.write_bytes(missing)
    run([*exact, "--expect-sha256", hashlib.sha256(missing).hexdigest()], "bundle_graph:")
    corrupted = data[:-1] + bytes([data[-1] ^ 1])
    path.write_bytes(corrupted)
    run([str(path), "--expect-sha256", "0" * 64], "expected_bundle_artifact_mismatch")
    run([*exact, "--expect-sha256", hashlib.sha256(corrupted).hexdigest()], "bundle_pack:")
    assert path.read_bytes() == corrupted
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fg", type=Path, help="explicit path to a built native fg binary")
    mode.add_argument("--fixtures-only", action="store_true", help="validate test data only; does not run new Rust code")
    args = parser.parse_args()
    fg = args.fg.resolve(strict=True) if args.fg else None
    with tempfile.TemporaryDirectory(prefix="fg-native-pins-smoke-") as temporary:
        output: dict[str, object] = {"native_fg_executed": fg is not None, "native_cases": 0, "fixture_checks": []}
        for algorithm in ("sha1", "sha256"):
            root = Path(temporary) / algorithm
            root.mkdir()
            data, _ = fixture(algorithm)
            output["fixture_checks"].append(git_preflight(root, data, algorithm))
            if fg is not None:
                output["native_cases"] += exercise(fg, root, algorithm)
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
