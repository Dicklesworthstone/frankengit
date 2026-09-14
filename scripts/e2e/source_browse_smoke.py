#!/usr/bin/env python3
"""Fresh-process exact source browsing and read-to-patch integration. No Git subprocess."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zlib


def object_id(fmt, kind, body):
    return hashlib.new(fmt, kind.encode() + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def loose(root, fmt, kind, body):
    name = object_id(fmt, kind, body)
    path = root / "objects" / name[:2] / name[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(kind.encode() + b" " + str(len(body)).encode() + b"\0" + body))
    return name


def tree(entries):
    return b"".join(mode + b" " + name + b"\0" + bytes.fromhex(identity)
                    for name, mode, identity in sorted(entries, key=lambda row: row[0] + (b"/" if row[1] == b"40000" else b"\0")))


def campaign(binary, fmt):
    with tempfile.TemporaryDirectory(prefix="fg-source-browse-cli-") as tmp:
        root = Path(tmp)
        source, node = root / "source", root / "node"
        (source / "refs/heads").mkdir(parents=True)
        (source / "HEAD").write_bytes(b"ref: refs/heads/main\n")
        (source / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat = sha256\n"))
        text, binary_bytes = b"before\r\nwithout-final", b"\0\xff\r\nbinary"
        old = loose(source, fmt, "blob", text)
        blob = loose(source, fmt, "blob", binary_bytes)
        blank = loose(source, fmt, "blob", b"")
        symlink = loose(source, fmt, "blob", b"/etc/passwd")
        nested = loose(source, fmt, "tree", tree([(b"file", b"100644", old)]))
        root_tree = loose(source, fmt, "tree", tree([(b"bin", b"100755", blob), (b"dir", b"40000", nested),
            (b"dir.c", b"100644", old), (b"empty", b"100644", blank), (b"link", b"120000", symlink), (b"\xff", b"100644", blob)]))
        base = loose(source, fmt, "commit", f"tree {root_tree}\nauthor T <t@example.invalid> 1 +0000\ncommitter T <t@example.invalid> 1 +0000\n\nbase\n".encode())
        (source / "refs/heads/main").write_text(base + "\n")
        tenant, repo, principal = "a7" * 16, "a8" * 16, "a9" * 16
        def run(args, code=0, receipt=False):
            result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=120)
            assert result.returncode == code, (args, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
            if receipt:
                lines = [line for line in result.stdout.splitlines() if line.strip()]
                assert len(lines) == 1, result.stdout
                return json.loads(lines[0])
            if code != 0:
                assert not result.stdout, "failed read emitted a partial page"
            return result
        run(["init", node, tenant, repo, fmt])
        run(["import", node, tenant, repo, principal, "source", source])
        common = [node, tenant, repo, "--trusted-local", "--ref", "refs/heads/main", "--object-format", fmt]
        first = run(["tree", *common, "--limit", "2"], receipt=True)
        assert first["source_commit"] == base and first["root_tree"] == root_tree
        assert first["repository_changed"] is False and first["node_closed"] is True
        assert [bytes.fromhex(e["name_hex"]) for e in first["entries"]] == [b"bin", b"dir"]
        token, rows, page = first["snapshot_token"], [], first
        while True:
            assert page["snapshot_token"] == token
            rows.extend(bytes.fromhex(e["name_hex"]) for e in page["entries"])
            if not page["has_more"]:
                break
            page = run(["tree", *common, "--limit", "2", "--after-hex", page["next_after_hex"], "--expected-head", token], receipt=True)
        assert rows == [b"bin", b"dir", b"dir.c", b"empty", b"link", b"\xff"]
        nested_page = run(["tree", *common, "--path", "dir", "--expected-head", token], receipt=True)
        assert nested_page["object_id"] == nested and nested_page["entries"][0]["object_id"] == old
        page = run(["show", *common, "--path-hex", "ff", "--max-bytes", "2"], receipt=True)
        assert page["text_utf8"] is None and page["object_id"] == blob
        body = bytearray()
        while True:
            body.extend(bytes.fromhex(page["bytes_hex"]))
            assert page["total_bytes"] == len(binary_bytes)
            if not page["has_more"]:
                break
            page = run(["show", *common, "--path-hex", "ff", "--max-bytes", "2", "--offset", page["next_offset"], "--expected-head", token], receipt=True)
        assert body == binary_bytes
        file = run(["show", *common, "--path", "dir/file", "--expected-commit", base], receipt=True)
        assert bytes.fromhex(file["bytes_hex"]) == text and file["text_utf8"] == text.decode()
        link = run(["show", *common, "--path", "link"], receipt=True)
        assert link["kind"] == "symlink" and bytes.fromhex(link["bytes_hex"]) == b"/etc/passwd"
        empty = run(["show", *common, "--path", "empty"], receipt=True)
        assert empty["bytes_hex"] == "" and empty["total_bytes"] == 0 and empty["next_offset"] is None
        eof = run(["show", *common, "--path", "bin", "--offset", len(binary_bytes), "--expected-head", token], receipt=True)
        assert eof["bytes_hex"] == "" and eof["has_more"] is False
        for extra, mode in [(["--path", "link/outside"], "show"), (["--path", "dir"], "show"),
            (["--path", "bin"], "tree"), (["--path", "../outside"], "show"),
            (["--after-hex", "62696e"], "tree"), (["--path", "bin", "--offset", "1"], "show"),
            (["--path", "bin", "--offset", str(2**64 - 1), "--expected-head", token], "show")]:
            run([mode, *common, *extra], code=2)
        assert run(["tree", *common, "--limit", "2"], receipt=True) == first
        # Use the observed exact bytes and native source identity to prepare a patch.
        patch = root / "change.patch"
        patch.write_bytes(b"diff --git a/dir/file b/dir/file\n--- a/dir/file\n+++ b/dir/file\n@@ -1,2 +1,2 @@\n-before\r\n+after\r\n without-final\n\\ No newline at end of file\n")
        bundle = root / "candidate.bundle"
        prepared = run(["patch", "prepare", node, tenant, repo, "refs/heads/main", patch, bundle,
            "--trusted-local", "--profile", "exact-v1", "--workspace-id", "aa" * 16,
            "--expected-base", file["source_commit"], "--author", "T <t@example.invalid>",
            "--timestamp", "2", "--message", "change\n"], receipt=True)
        assert prepared["published_to_repository"] is False
        applied = run(["patch", "apply", node, tenant, repo, "refs/heads/main", bundle, "--trusted-local",
            "--principal", principal, "--idempotency-key", "browse-patch", "--expected-base", base,
            "--expected-commit", prepared["candidate_commit"]], receipt=True)
        assert applied["outcome"] == "committed"
        run(["tree", *common, "--limit", "2", "--after-hex", first["next_after_hex"], "--expected-head", token], code=2)
        run(["show", *common, "--path", "dir/file", "--expected-commit", base], code=2)
        changed = run(["show", *common, "--path", "dir/file"], receipt=True)
        assert changed["source_commit"] == prepared["candidate_commit"]
        assert bytes.fromhex(changed["bytes_hex"]) == b"after\r\nwithout-final"
        print(f"SOURCE_BROWSE_CLI format={fmt} directory_entries={len(rows)} binary_exact=true read_patch_apply=true stale_snapshot_refused=true")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True, type=Path)
    args = parser.parse_args()
    binary = args.fg.resolve(strict=True)
    for fmt in ("sha1", "sha256"):
        campaign(binary, fmt)


if __name__ == "__main__":
    main()
