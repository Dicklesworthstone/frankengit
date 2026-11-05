#!/usr/bin/env python3
"""Real fresh-process fg patch campaign. No Git or substitute node is invoked."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib


def oid(fmt, kind, body):
    return hashlib.new(fmt, kind.encode() + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def loose(root, fmt, kind, body):
    name = oid(fmt, kind, body)
    path = root / "objects" / name[:2] / name[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(kind.encode() + b" " + str(len(body)).encode() + b"\0" + body))
    return name


def tree(entries):
    return b"".join(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(identity)
                    for name, mode, identity in sorted(entries))


def bundle_objects(data, fmt, base, candidate):
    header, pack = data.split(b"\n\n", 1)
    expected = (b"# v2 git bundle\n" if fmt == "sha1" else b"# v3 git bundle\n@object-format=sha256\n")
    assert header == expected + f"-{base} patch base\n{candidate} refs/heads/main".encode()
    width = hashlib.new(fmt).digest_size
    assert pack[:8] == b"PACK\0\0\0\2"
    assert hashlib.new(fmt, pack[:-width]).digest() == pack[-width:]
    count = struct.unpack(">I", pack[8:12])[0]
    at, result = 12, {}
    for _ in range(count):
        first = pack[at]
        at += 1
        kind = {1: "commit", 2: "tree", 3: "blob"}[(first >> 4) & 7]
        size, shift, byte = first & 15, 4, first
        while byte & 128:
            byte = pack[at]
            at += 1
            size |= (byte & 127) << shift
            shift += 7
            assert shift < 64
        decoder = zlib.decompressobj()
        tail = pack[at:]
        body = decoder.decompress(tail, 64 * 1024 * 1024 + 1)
        assert decoder.eof and not decoder.unconsumed_tail and len(body) == size
        at += len(tail) - len(decoder.unused_data)
        name = oid(fmt, kind, body)
        assert name not in result
        result[name] = (kind, body)
    assert at == len(pack) - width
    return result


def campaign(binary, fmt):
    with tempfile.TemporaryDirectory(prefix="fg-patch-cli-") as tmp:
        root = Path(tmp)
        source, node = root / "source", root / "node"
        (source / "refs/heads").mkdir(parents=True)
        (source / "HEAD").write_bytes(b"ref: refs/heads/main\n")
        config = "[core]\nbare = true\nrepositoryformatversion = " + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat = sha256\n")
        (source / "config").write_text(config)
        old = loose(source, fmt, "blob", b"before\n")
        keep = loose(source, fmt, "blob", b"preserve\0me\n")
        old_tree = loose(source, fmt, "tree", tree([("edit.txt", "100644", old), ("keep.txt", "100644", keep)]))
        base = loose(source, fmt, "commit", f"tree {old_tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nbase\n".encode())
        (source / "refs/heads/main").write_text(base + "\n")
        tenant, repo, principal = "d1" * 16, "d2" * 16, "d3" * 16

        def run(args, code=0, stdin=None, receipt=False):
            result = subprocess.run([str(binary), *map(str, args)], input=stdin, capture_output=True, timeout=120)
            assert result.returncode == code, (args, result.returncode, result.stdout.decode(errors="replace"), result.stderr.decode(errors="replace"))
            if receipt:
                lines = [line for line in result.stdout.splitlines() if line.strip()]
                assert len(lines) == 1, result.stdout
                return json.loads(lines[0])
            return result

        run(["init", node, tenant, repo, fmt])
        run(["import", node, tenant, repo, principal, "source", source])
        new = oid(fmt, "blob", b"after\r\n")
        patch = root / "input.patch"
        patch.write_bytes(f"diff --git a/edit.txt b/edit.txt\nold mode 100644\nnew mode 100755\nindex {old}..{new}\n--- a/edit.txt\n+++ b/edit.txt\n@@ -1 +1 @@\n-before\n+after\r\n".encode())
        output, second = root / "candidate.bundle", root / "same.bundle"
        prepare = ["patch", "prepare", node, tenant, repo, "refs/heads/main", patch, output,
                   "--trusted-local", "--profile", "exact-v1", "--workspace-id", "d4" * 16,
                   "--expected-base", base, "--author", "Test <test@example.invalid>", "--timestamp", "2", "--message", "patch\n"]
        prepared = run(prepare, receipt=True)
        assert prepared["published_to_repository"] is False and prepared["node_closed"] is True
        assert prepared["patch_sha256"] == hashlib.sha256(patch.read_bytes()).hexdigest()
        new_tree = oid(fmt, "tree", tree([("edit.txt", "100755", new), ("keep.txt", "100644", keep)]))
        commit_bytes = f"tree {new_tree}\nparent {base}\nauthor Test <test@example.invalid> 2 +0000\ncommitter Test <test@example.invalid> 2 +0000\n\npatch\n".encode()
        candidate = oid(fmt, "commit", commit_bytes)
        assert prepared["candidate_commit"] == candidate and prepared["root_tree"] == new_tree
        packed = bundle_objects(output.read_bytes(), fmt, base, candidate)
        assert packed[candidate] == ("commit", commit_bytes)
        assert packed[new] == ("blob", b"after\r\n")
        assert packed[new_tree] == ("tree", tree([("edit.txt", "100755", new), ("keep.txt", "100644", keep)]))
        same = prepare.copy()
        same[7] = second
        assert run(same, receipt=True) == prepared
        assert second.read_bytes() == output.read_bytes()
        run(prepare, code=2)
        assert second.read_bytes() == output.read_bytes(), "existing artifact was overwritten"
        broken = root / "broken.patch"
        broken.write_bytes(patch.read_bytes() + b"diff --git a/keep.txt b/keep.txt\n--- a/keep.txt\n+++ b/keep.txt\n@@ -1 +1 @@\n-wrong\n+wrong\n")
        refused = prepare.copy()
        refused[6], refused[7] = broken, root / "refused.bundle"
        run(refused, code=2)
        assert not refused[7].exists(), "late file failure created a partial bundle"
        apply = ["patch", "apply", node, tenant, repo, "refs/heads/main", output,
                 "--trusted-local", "--principal", principal, "--key-stdin", "--expected-base", base,
                 "--expected-commit", candidate]
        wrong = apply.copy()
        wrong[-1] = keep
        run(wrong, code=2, stdin=b"wrong-review\n")
        terminal = run(apply, stdin=b"private-review-key\n", receipt=True)
        assert terminal["outcome"] == "committed" and terminal["published_to_repository"] is True
        assert terminal["candidate_commit"] == candidate and terminal["node_closed"] is True
        assert "private-review-key" not in json.dumps(terminal)
        assert run(apply, stdin=b"private-review-key\n", receipt=True) == terminal
        stale = prepare.copy()
        stale[7] = root / "stale.bundle"
        run(stale, code=2)
        assert not stale[7].exists()
        print(f"PATCH_CLI format={fmt} candidate={candidate} objects={len(packed)} committed=true replay_identical=true")

        symlink_patch, symlink_bundle = root / "symlink.patch", root / "symlink.bundle"
        target = b"../../outside"
        symlink_patch.write_bytes(b"diff --git a/link b/link\nnew file mode 120000\n--- /dev/null\n+++ b/link\n@@ -0,0 +1 @@\n+" + target + b"\n\\ No newline at end of file\n")
        symlink_prepare = prepare.copy()
        symlink_prepare[6], symlink_prepare[7] = symlink_patch, symlink_bundle
        symlink_prepare[symlink_prepare.index("--expected-base") + 1] = candidate
        profile_at = symlink_prepare.index("--profile") + 1
        for legacy in ("exact-v1", "exact-binary-v1", "exact-tree-v1", "exact-tree-binary-v1"):
            denied = symlink_prepare.copy()
            denied[profile_at], denied[7] = legacy, root / f"{legacy}-symlink-refused.bundle"
            run(denied, code=2)
            assert not denied[7].exists()
        symlink_prepare[profile_at] = "exact-symlink-v1"
        limited = symlink_prepare.copy()
        limited[7] = root / "symlink-over-budget.bundle"
        limited.extend(["--max-output-bytes", "4"])
        run(limited, code=2)
        assert not limited[7].exists(), "bounded refusal exposed a partial candidate"
        linked = run(symlink_prepare, receipt=True)
        assert linked["profile"] == "exact-symlink-v1" and linked["published_to_repository"] is False
        link_blob = oid(fmt, "blob", target)
        link_tree_body = tree([("edit.txt", "100755", new), ("keep.txt", "100644", keep), ("link", "120000", link_blob)])
        link_tree = oid(fmt, "tree", link_tree_body)
        assert linked["root_tree"] == link_tree
        link_objects = bundle_objects(symlink_bundle.read_bytes(), fmt, candidate, linked["candidate_commit"])
        assert link_objects[link_blob] == ("blob", target)
        assert link_objects[link_tree] == ("tree", link_tree_body)
        link_apply = apply.copy()
        link_apply[6] = symlink_bundle
        link_apply[link_apply.index("--expected-base") + 1] = candidate
        link_apply[-1] = linked["candidate_commit"]
        link_terminal = run(link_apply, stdin=b"reviewed-symlink-key\n", receipt=True)
        assert link_terminal["outcome"] == "committed"
        assert run(link_apply, stdin=b"reviewed-symlink-key\n", receipt=True) == link_terminal
        print(f"PATCH_SYMLINK_CLI format={fmt} candidate={linked['candidate_commit']} mode=120000 inert_bytes=true old_profiles_refuse=true")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True, type=Path)
    args = parser.parse_args()
    binary = args.fg.resolve(strict=True)
    for fmt in ("sha1", "sha256"):
        campaign(binary, fmt)


if __name__ == "__main__":
    main()
