#!/usr/bin/env python3
"""Real fg processes: native tags, exact retries, and complete bundle transfer."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zlib


def oid(fmt, kind, body):
    return hashlib.new(fmt, kind.encode() + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def loose(root, fmt, kind, body):
    identity = oid(fmt, kind, body)
    path = root / "objects" / identity[:2] / identity[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(kind.encode() + b" " + str(len(body)).encode() + b"\0" + body))
    return identity


def campaign(binary, fmt):
    with tempfile.TemporaryDirectory(prefix="fg-native-tag-cli-") as tmp:
        root = Path(tmp)
        source, storage = root / "source", root / "node"
        (source / "refs/heads").mkdir(parents=True)
        (source / "HEAD").write_bytes(b"ref: refs/heads/main\n")
        (source / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat = sha256\n"))
        blob = loose(source, fmt, "blob", b"release data\n")
        tree = loose(source, fmt, "tree", b"100644 file\0" + bytes.fromhex(blob))
        commit = loose(source, fmt, "commit", f"tree {tree}\nauthor T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\ninitial\n".encode())
        (source / "refs/heads/main").write_text(commit + "\n")
        tenant, repo, principal = "b1" * 16, "b2" * 16, "b3" * 16
        secret = b"byte-exact-tag-key\n"
        def run(args, code=0, receipt=True, key=None):
            result = subprocess.run([str(binary), *map(str, args)], input=key, capture_output=True, timeout=120)
            assert result.returncode == code, (args, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
            assert secret.strip() not in result.stdout + result.stderr, "key leaked to output"
            if receipt:
                lines = [v for v in result.stdout.splitlines() if v.strip()]
                assert len(lines) == 1, result.stdout
                return json.loads(lines[0])
            if code == 2:
                assert not result.stdout, "unacknowledged operation emitted a complete receipt"
            return result
        run(["init", storage, tenant, repo, fmt], receipt=False)
        run(["import", storage, tenant, repo, principal, "fixture", source], receipt=False)
        common = [storage, tenant, repo, "--trusted-local", "--object-format", fmt]
        def mutate(action, ref, extra, key):
            return run(["tag", action, *common, "--ref", ref, "--principal", principal, "--key-stdin", *extra], key=key)
        def show(ref):
            return run(["tag", "show", *common, "--ref", ref])
        empty = run(["tag", "list", *common])
        assert empty["tags"] == [] and empty["has_more"] is False
        message = b"release\xff\r\nwithout-final"
        path = root / "message"
        path.write_bytes(message)
        expected_tags = {}
        metadata = ["--tagger", "Release <release@example.invalid>", "--timestamp", "7", "--message-file", path]
        for kind, target in [("commit", commit), ("tree", tree), ("blob", blob)]:
            ref = "refs/tags/" + kind
            result = mutate("annotate", ref, ["--target", target, "--target-kind", kind, *metadata], kind.encode())
            assert result["outcome"] == "committed" and result["node_closed"] is True
            body = f"object {target}\ntype {kind}\ntag {kind}\ntagger Release <release@example.invalid> 7 +0000\n\n".encode() + message
            expected = oid(fmt, "tag", body)
            read = show(ref)
            assert read["tip"] == expected and read["peeled"] == target and read["peeled_kind"] == kind
            assert bytes.fromhex(read["annotations"][0]["body_hex"]) == body
            assert read["annotations"][0]["signature_state"] == "absent"
            assert read["signature_verification"] == "not_performed"
            expected_tags[ref] = expected
        inner = expected_tags["refs/tags/commit"]
        nested = mutate("annotate", "refs/tags/outer", ["--target", inner, "--target-kind", "tag", *metadata], secret)
        outer = show("refs/tags/outer")
        assert len(outer["annotations"]) == 2 and outer["peeled"] == commit
        assert mutate("annotate", "refs/tags/outer", ["--target", inner, "--target-kind", "tag", *metadata], secret) == nested
        alias = run(["tag", "create", *common, "--ref-hex", b"refs/tags/raw/\xff".hex(), "--target", outer["tip"], "--principal", principal, "--idempotency-key", "alias"])
        assert alias["outcome"] == "committed"
        first = run(["tag", "list", *common, "--limit", "2"])
        token, page, names = first["snapshot_token"], first, []
        while True:
            assert page["snapshot_token"] == token
            names.extend(bytes.fromhex(row["reference_hex"]) for row in page["tags"])
            if not page["has_more"]:
                break
            page = run(["tag", "list", *common, "--limit", "2", "--after-hex", page["next_after_hex"], "--expected-head", token])
        assert names == [b"refs/tags/blob", b"refs/tags/commit", b"refs/tags/outer", b"refs/tags/raw/\xff", b"refs/tags/tree"]
        current = run(["tag", "show", *common, "--ref", "refs/tags/outer", "--expected-head", token])
        for field in ("tip", "peeled", "peeled_kind", "annotations"):
            assert current[field] == outer[field]
        collision = run(["tag", "create", *common, "--ref", "refs/tags/outer", "--target", commit, "--principal", principal, "--idempotency-key", "collision"], code=3)
        assert collision["outcome"] == "refused" and collision["command_committed"] is False
        run(["tag", "list", *common, "--after-hex", first["next_after_hex"], "--expected-head", token], code=2, receipt=False)
        before = run(["tag", "list", *common])
        run(["tag", "annotate", *common, "--ref", "refs/tags/wrong-kind", "--target", blob, "--target-kind", "commit", *metadata, "--principal", principal, "--idempotency-key", "wrong-kind"], code=2, receipt=False)
        assert run(["tag", "list", *common]) == before
        # Transfer through the existing native full-bundle path into a fresh node.
        bundle, destination = root / "tags.bundle", root / "destination"
        run(["bundle", "export", storage, tenant, repo, bundle, "--trusted-local", "--object-format", fmt])
        run(["init", destination, tenant, repo, fmt], receipt=False)
        imported = run(["bundle", "import", destination, tenant, repo, bundle, "--trusted-local", "--object-format", fmt, "--principal", principal, "--idempotency-key", "bundle-import"])
        assert imported["outcome"] == "committed"
        copied = run(["tag", "show", destination, tenant, repo, "--trusted-local", "--object-format", fmt, "--ref", "refs/tags/outer"])
        for field in ("tip", "peeled", "peeled_kind", "annotations"):
            assert copied[field] == outer[field]
        deleted = mutate("delete", "refs/tags/outer", ["--expected-tip", outer["tip"]], b"delete")
        assert deleted["outcome"] == "committed"
        settled = run(["tag", "list", *common])
        assert mutate("annotate", "refs/tags/outer", ["--target", inner, "--target-kind", "tag", *metadata], secret) == nested
        assert mutate("delete", "refs/tags/outer", ["--expected-tip", outer["tip"]], b"delete") == deleted
        assert run(["tag", "list", *common]) == settled
        # An empty message is a valid annotation, not a missing artifact.
        path.write_bytes(b"")
        blank = mutate("annotate", "refs/tags/empty", ["--target", commit, "--target-kind", "commit", *metadata], b"empty")
        assert blank["outcome"] == "committed" and bytes.fromhex(show("refs/tags/empty")["annotations"][0]["body_hex"]).endswith(b"\n\n")
        print(f"NATIVE_TAG_CLI format={fmt} nested_tags=true exact_retry=true bundle_transfer=true empty_message=true")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", type=Path, required=True)
    binary = parser.parse_args().fg.resolve(strict=True)
    for algorithm in ("sha1", "sha256"):
        campaign(binary, algorithm)
