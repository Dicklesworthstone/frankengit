#!/usr/bin/env python3
"""Pinned, NON-PRODUCTION Git input-corpus check; not native Rust execution.

Generates ordinary Git --binary patches in disposable repositories, applies them
through actual Git, and checks exact trees/modes/blobs. No candidate node, native
admission or production decoder is simulated. Run native tests separately.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(git, root, args, data=None):
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root),
           "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_TERMINAL_PROMPT": "0"}
    result = subprocess.run([str(git), *args], cwd=root, env=env, input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
    if result.returncode:
        raise RuntimeError(f"Git {args[0]} failed ({result.returncode}): {result.stderr.decode(errors='replace')}")
    return result.stdout


def populate(root, files):
    for name, (body, mode) in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(mode)


def check(git, algorithm, name, before, after, require_binary=True):
    with tempfile.TemporaryDirectory(prefix="fg-compressed-corpus-") as directory:
        root = Path(directory)
        run(git, root, ["init", "-q", f"--object-format={algorithm}"])
        run(git, root, ["config", "core.fileMode", "true"])
        populate(root, before)
        run(git, root, ["add", "--all"])
        old_tree = run(git, root, ["write-tree"]).strip()
        for path in before:
            (root / path).unlink()
        populate(root, after)
        run(git, root, ["add", "--all"])
        new_tree = run(git, root, ["write-tree"]).strip()
        patch = run(git, root, ["diff", "--binary", "--full-index", "--no-ext-diff", "--no-textconv",
                               "--find-renames=50%", old_tree.decode(), new_tree.decode()])
        if require_binary and b"GIT binary patch\n" not in patch:
            raise AssertionError(f"{name}: missing binary input")
        run(git, root, ["read-tree", old_tree.decode()])
        run(git, root, ["apply", "--cached", "--whitespace=nowarn", "-"], patch)
        assert run(git, root, ["write-tree"]).strip() == new_tree, name
        rows = run(git, root, ["ls-files", "--stage", "-z"]).split(b"\0")
        entries = {}
        for row in filter(None, rows):
            meta, raw_path = row.split(b"\t", 1)
            mode, oid, stage = meta.split()
            assert stage == b"0"
            entries[os.fsdecode(raw_path)] = (mode, oid)
        assert set(entries) == set(after), name
        for path, (body, mode) in after.items():
            observed_mode, oid = entries[path]
            expected_id = hashlib.new(algorithm, f"blob {len(body)}\0".encode() + body).hexdigest().encode()
            assert oid == expected_id and observed_mode == (b"100755" if mode == 0o755 else b"100644"), name
            assert run(git, root, ["cat-file", "blob", oid.decode()]) == body, name
        return {"case": name, "object_format": algorithm, "patch_sha256": hashlib.sha256(patch).hexdigest(),
                "patch_bytes": len(patch), "before_tree": old_tree.decode(), "after_tree": new_tree.decode(),
                "binary_files": patch.count(b"GIT binary patch\n"),
                "literal_members": sum(line.startswith(b"literal ") for line in patch.splitlines()),
                "delta_members": sum(line.startswith(b"delta ") for line in patch.splitlines())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("git", type=Path)
    parser.add_argument("version")
    parser.add_argument("sha256")
    args = parser.parse_args()
    git = args.git.resolve(strict=True)
    digest = hashlib.sha256(git.read_bytes()).hexdigest()
    if digest != args.sha256:
        raise SystemExit("Pinned Git executable hash mismatch; nothing executed.")
    with tempfile.TemporaryDirectory(prefix="fg-git-version-") as directory:
        version = run(git, Path(directory), ["--version"]).decode().strip()
    if version != args.version:
        raise SystemExit("Pinned Git version mismatch.")
    old = b"\0old\xff\n"
    new = b"\0new\xfe\r\n"
    delta = bytes(range(256)) * 8
    delta_new = delta[:333] + b"changed\0\xff" + delta[341:]
    keep = {"keep.bin": (b"untouched\0sibling\n", 0o644)}
    cases = [
        ("literal", {"asset.bin": (old, 0o644)}, {"asset.bin": (new, 0o644)}),
        ("creation", {}, {"asset.bin": (new, 0o644)}),
        ("deletion", {"asset.bin": (old, 0o644)}, {}),
        ("empty-present", {"asset.bin": (old, 0o644)}, {"asset.bin": (b"", 0o644)}),
        ("delta", {"asset.bin": (delta, 0o644)}, {"asset.bin": (delta_new, 0o644)}),
        ("mode-and-content", {"asset.bin": (old, 0o644)}, {"asset.bin": (new, 0o755)}),
        ("quoted-path", {"nested/a b\t.bin": (old, 0o644)}, {"nested/a b\t.bin": (new, 0o644)}),
        ("mixed-text-rename-binary", {"asset.bin": (old, 0o644), "rename.txt": (b"unchanged text\n", 0o644)},
         {"asset.bin": (new, 0o644), "renamed.txt": (b"unchanged text\n", 0o644), "note.txt": (b"new note\n", 0o755)}),
    ]
    reports = [check(git, algorithm, name, {**keep, **before}, {**keep, **after})
               for algorithm in ("sha1", "sha256") for name, before, after in cases]
    assert any(report["delta_members"] for report in reports)
    print(json.dumps({"profile": "git-compressed-patch-input-corpus-v1", "git_version": version,
                      "git_sha256": digest, "cases": reports, "passed": len(reports),
                      "native_rust_executed": False, "native_authority_tested": False}, indent=2))


if __name__ == "__main__":
    main()
