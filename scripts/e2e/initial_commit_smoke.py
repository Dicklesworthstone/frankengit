#!/usr/bin/env python3
"""Fresh fg init -> exact root patch -> reviewed publish -> verified bytes; no Git subprocess."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


def oid(fmt, kind, body):
    return hashlib.new(fmt, kind + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def unpack(bundle, fmt, reference, expected):
    header, pack = bundle.split(b"\n\n", 1)
    assert header.startswith(b"# v2 git bundle\n" if fmt == "sha1" else b"# v3 git bundle\n@object-format=sha256\n")
    advertised = [line for line in header.splitlines() if not line.startswith((b"#", b"@"))]
    assert advertised == [expected.encode() + b" " + reference]
    width = hashlib.new(fmt).digest_size
    assert hashlib.new(fmt, pack[:-width]).digest() == pack[-width:]
    assert pack[:8] == b"PACK\0\0\0\2"
    count = struct.unpack(">I", pack[8:12])[0]
    at, objects = 12, {}
    for _ in range(count):
        byte = pack[at]
        at += 1
        kind, size, shift = (byte >> 4) & 7, byte & 15, 4
        while byte & 128:
            byte = pack[at]
            at += 1
            size |= (byte & 127) << shift
            shift += 7
            assert shift <= 67
        assert kind in (1, 2, 3), "initial candidate unexpectedly used delta/tag objects"
        decoder = zlib.decompressobj()
        remaining = pack[at:-width]
        body = decoder.decompress(remaining)
        assert decoder.eof and len(body) == size
        at += len(remaining) - len(decoder.unused_data)
        label = {1: b"commit", 2: b"tree", 3: b"blob"}[kind]
        identity = oid(fmt, label, body)
        assert identity not in objects
        objects[identity] = (label, body)
    assert at == len(pack) - width
    assert sum(kind == b"commit" for kind, _ in objects.values()) == 1
    kind, commit = objects[expected]
    assert kind == b"commit" and not any(line.startswith(b"parent ") for line in commit.split(b"\n\n", 1)[0].splitlines())
    tree = commit.splitlines()[0].removeprefix(b"tree ").decode()
    visited, files = {expected}, {}
    def walk(identity, prefix=b""):
        visited.add(identity)
        kind, body = objects[identity]
        assert kind == b"tree"
        at, order = 0, []
        while at < len(body):
            end = body.index(b"\0", at)
            mode, name = body[at:end].split(b" ", 1)
            target = body[end+1:end+1+width].hex()
            at = end + 1 + width
            order.append(name + (b"/" if mode == b"40000" else b"\0"))
            if mode == b"40000":
                walk(target, prefix + name + b"/")
            else:
                assert mode in (b"100644", b"100755")
                visited.add(target)
                assert objects[target][0] == b"blob"
                files[prefix + name] = (mode, objects[target][1])
        assert at == len(body) and order == sorted(order) and len(order) == len(set(order))
    walk(tree)
    assert visited == objects.keys(), "bundle contains unexplained objects"
    return tree, files, count


def campaign(binary, fmt):
    with tempfile.TemporaryDirectory(prefix="fg-initial-cli-") as tmp:
        root = Path(tmp)
        node, patch, bundle = root / "node", root / "creation.patch", root / "first.bundle"
        tenant, repository, principal = "e1" * 16, "e2" * 16, "e3" * 16
        reference = "refs/heads/main"
        patch_bytes = (b"diff --git a/src/main.rs b/src/main.rs\nnew file mode 100755\n--- /dev/null\n+++ b/src/main.rs\n@@ -0,0 +1 @@\n+fn main() {}\n"
            b"diff --git a/empty b/empty\nnew file mode 100644\n--- /dev/null\n+++ b/empty\n"
            b"diff --git a/crlf b/crlf\nnew file mode 100644\n--- /dev/null\n+++ b/crlf\n@@ -0,0 +1,2 @@\n+hello\r\n+without-final\n\\ No newline at end of file\n")
        patch.write_bytes(patch_bytes)
        def run(args, code=0, receipt=True, data=None):
            result = subprocess.run([str(binary), *map(str,args)], input=data, capture_output=True, timeout=120)
            assert result.returncode == code, (args, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
            if receipt:
                rows = [row for row in result.stdout.splitlines() if row.strip()]
                assert len(rows) == 1, result.stdout
                return json.loads(rows[0])
            return result
        run(["init", node, tenant, repository, fmt], receipt=False)
        empty = run(["refs", node, tenant, repository, "--trusted-local", "--object-format", fmt])
        assert empty["references"] == []
        prepare = ["patch", "prepare-initial", node, tenant, repository, reference, patch, bundle,
            "--trusted-local", "--profile", "exact-v1", "--object-format", fmt,
            "--author", "Author <a@example.invalid>", "--timestamp", "1", "--message", "Initial\n"]
        prepared = run(prepare)
        assert prepared["parent_count"] == 0 and prepared["published_to_repository"] is False
        assert prepared["patch_sha256"] == hashlib.sha256(patch_bytes).hexdigest()
        saved = bundle.read_bytes()
        assert prepared["bundle_sha256"] == hashlib.sha256(saved).hexdigest()
        tree, files, count = unpack(saved, fmt, reference.encode(), prepared["candidate_commit"])
        assert prepared["root_tree"] == tree and prepared["pack_objects"] == count
        assert files == {b"src/main.rs":(b"100755",b"fn main() {}\n"),b"empty":(b"100644",b""),b"crlf":(b"100644",b"hello\r\nwithout-final")}
        assert run(["refs", node, tenant, repository, "--trusted-local", "--object-format", fmt]) == empty
        run(prepare, code=2, receipt=False)
        assert bundle.read_bytes() == saved
        apply = ["patch", "apply-initial", node, tenant, repository, reference, bundle,
            "--trusted-local", "--principal", principal, "--key-stdin", "--expected-commit", prepared["candidate_commit"]]
        wrong = apply.copy()
        wrong[-1] = tree
        run(wrong, code=2, receipt=False, data=b"wrong")
        assert run(["refs", node, tenant, repository, "--trusted-local", "--object-format", fmt]) == empty
        result = run(apply, data=b"first\n")
        assert result["outcome"] == "committed" and result["expected_absent"] is True
        assert run(apply, data=b"first\n") == result
        collision = run(apply, code=3, data=b"different-key")
        assert collision["outcome"] == "refused" and collision["published_to_repository"] is False
        assert run(apply, code=3, data=b"different-key") == collision
        inventory = run(["refs", node, tenant, repository, "--trusted-local", "--object-format", fmt])
        assert inventory["references"] == [{"reference_hex":reference.encode().hex(), "tip":prepared["candidate_commit"]}]
        for name, (mode, contents) in files.items():
            shown = run(["show", node, tenant, repository, "--trusted-local", "--object-format", fmt,
                "--ref", reference, "--path-hex", name.hex(), "--expected-commit", prepared["candidate_commit"]])
            assert bytes.fromhex(shown["bytes_hex"]) == contents
            assert shown["source_commit"] == prepared["candidate_commit"]
        # Existing ordinary patch editing must work immediately on the new root.
        update, next_bundle = root / "change.patch", root / "next.bundle"
        update.write_bytes(b"diff --git a/src/main.rs b/src/main.rs\n--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-fn main() {}\n+fn main() { println!(\"ready\"); }\n")
        next_plan = run(["patch", "prepare", node, tenant, repository, reference, update, next_bundle,
            "--trusted-local", "--profile", "exact-v1", "--workspace-id", "44"*16, "--expected-base", prepared["candidate_commit"],
            "--author", "Author <a@example.invalid>", "--timestamp", "2", "--message", "Next\n"])
        advanced = run(["patch", "apply", node, tenant, repository, reference, next_bundle,
            "--trusted-local", "--principal", principal, "--idempotency-key", "second", "--expected-base", prepared["candidate_commit"],
            "--expected-commit", next_plan["candidate_commit"]])
        assert advanced["outcome"] == "committed"
        assert run(apply, data=b"first\n") == result
        shown = run(["show", node, tenant, repository, "--trusted-local", "--object-format", fmt, "--ref", reference, "--path", "src/main.rs"])
        assert shown["source_commit"] == next_plan["candidate_commit"]
        assert bytes.fromhex(shown["bytes_hex"]) == b'fn main() { println!("ready"); }\n'
        print(f"INITIAL_COMMIT_CLI format={fmt} files={len(files)} parent_count=0 exact_replay=true collision_refused=true next_commit=true")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True, type=Path)
    binary = parser.parse_args().fg.resolve(strict=True)
    for fmt in ("sha1", "sha256"):
        campaign(binary, fmt)


if __name__ == "__main__":
    main()
