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


def bundle_objects(data, fmt, base, candidate, reference='refs/heads/main'):
    header, pack = data.split(b"\n\n", 1)
    expected = (b"# v2 git bundle\n" if fmt == "sha1" else b"# v3 git bundle\n@object-format=sha256\n")
    assert header == expected + f"-{base} patch base\n{candidate} {reference}".encode()
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

        # A gitlink names a foreign commit, not a blob in this repository. These
        # identities are deliberately never written to the source object store.
        first_pointer = oid(fmt, "commit", b"foreign submodule first\n")
        second_pointer = oid(fmt, "commit", b"foreign submodule second\n")
        absent = "0" * len(first_pointer)
        current = linked["candidate_commit"]
        previous_config = b""
        for phase, before, after, config_body in [
            ("create", absent, first_pointer, b'[submodule "module"]\n\tpath = module\n\turl = https://example.invalid/first\n'),
            ("update", first_pointer, second_pointer, b'[submodule "module"]\n\tpath = module\n\turl = https://example.invalid/second\n'),
            ("delete", second_pointer, absent, b""),
        ]:
            prefix = "diff --git a/module b/module\n"
            if phase == "create":
                pointer_diff = f"{prefix}new file mode 160000\nindex {before}..{after}\n--- /dev/null\n+++ b/module\n@@ -0,0 +1 @@\n+Subproject commit {after}\n"
                config_headers = "new file mode 100644\n--- /dev/null\n+++ b/.gitmodules\n@@ -0,0 +1,3 @@\n"
            elif phase == "update":
                pointer_diff = f"{prefix}index {before}..{after} 160000\n--- a/module\n+++ b/module\n@@ -1 +1 @@\n-Subproject commit {before}\n+Subproject commit {after}\n"
                config_headers = "--- a/.gitmodules\n+++ b/.gitmodules\n@@ -1,3 +1,3 @@\n"
            else:
                pointer_diff = f"{prefix}deleted file mode 160000\nindex {before}..{after}\n--- a/module\n+++ /dev/null\n@@ -1 +0,0 @@\n-Subproject commit {before}\n"
                config_headers = "deleted file mode 100644\n--- a/.gitmodules\n+++ /dev/null\n@@ -1,3 +0,0 @@\n"
            config_diff = b"diff --git a/.gitmodules b/.gitmodules\n" + config_headers.encode()
            config_diff += b"".join(b"-" + line for line in previous_config.splitlines(keepends=True))
            config_diff += b"".join(b"+" + line for line in config_body.splitlines(keepends=True))
            pointer_patch = root / f"gitlink-{phase}.patch"
            pointer_patch.write_bytes(pointer_diff.encode() + config_diff)
            pointer_bundle = root / f"gitlink-{phase}.bundle"
            pointer_prepare = prepare.copy()
            pointer_prepare[6], pointer_prepare[7] = pointer_patch, pointer_bundle
            pointer_prepare[profile_at] = "exact-gitlink-v1"
            pointer_prepare[pointer_prepare.index("--expected-base") + 1] = current
            if phase == "create":
                for legacy in ("exact-v1", "exact-binary-v1", "exact-tree-v1", "exact-tree-binary-v1", "exact-symlink-v1"):
                    denied = pointer_prepare.copy()
                    denied[profile_at], denied[7] = legacy, root / f"{legacy}-gitlink-refused.bundle"
                    run(denied, code=2)
                    assert not denied[7].exists()
            prepared_pointer = run(pointer_prepare, receipt=True)
            assert prepared_pointer["profile"] == "exact-gitlink-v1"
            assert prepared_pointer["published_to_repository"] is False and prepared_pointer["node_closed"] is True
            entries = [("edit.txt", "100755", new), ("keep.txt", "100644", keep), ("link", "120000", link_blob)]
            if phase != "delete":
                entries += [(".gitmodules", "100644", oid(fmt, "blob", config_body)), ("module", "160000", after)]
            expected_tree_body = tree(entries)
            expected_tree = oid(fmt, "tree", expected_tree_body)
            assert prepared_pointer["root_tree"] == expected_tree
            pointer_candidate = prepared_pointer["candidate_commit"]
            objects = bundle_objects(pointer_bundle.read_bytes(), fmt, current, pointer_candidate)
            # Deletion restores an unchanged ancestor tree: the exporter may
            # reuse that verified object rather than redundantly packing it.
            if expected_tree in objects:
                assert objects[expected_tree] == ("tree", expected_tree_body)
            assert first_pointer not in objects and second_pointer not in objects
            for pointer in (first_pointer, second_pointer):
                assert oid(fmt, "blob", f"Subproject commit {pointer}\n".encode()) not in objects
            if config_body:
                assert objects[oid(fmt, "blob", config_body)] == ("blob", config_body)
            receipts = {bytes.fromhex(item["path_hex"]): item for item in prepared_pointer["paths"]}
            assert set(receipts) == {b".gitmodules", b"module"}
            assert all("old_blob" not in item and "new_blob" not in item for item in receipts.values())
            pointer_receipt = receipts[b"module"]
            assert pointer_receipt["old_object"] == (None if phase == "create" else before)
            assert pointer_receipt["new_object"] == (None if phase == "delete" else after)
            assert pointer_receipt["new_mode"] == (None if phase == "delete" else "160000")
            pointer_apply = apply.copy()
            pointer_apply[6] = pointer_bundle
            pointer_apply[pointer_apply.index("--expected-base") + 1] = current
            pointer_apply[-1] = pointer_candidate
            key = f"reviewed-gitlink-{phase}\n".encode()
            pointer_terminal = run(pointer_apply, stdin=key, receipt=True)
            assert pointer_terminal["outcome"] == "committed" and pointer_terminal["published_to_repository"] is True
            assert run(pointer_apply, stdin=key, receipt=True) == pointer_terminal
            current, previous_config = pointer_candidate, config_body
            print(f"PATCH_GITLINK_CLI format={fmt} operation={phase} candidate={current} mode=160000 opaque_target=true replay_identical=true")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True, type=Path)
    args = parser.parse_args()
    binary = args.fg.resolve(strict=True)
    for fmt in ("sha1", "sha256"):
        campaign(binary, fmt)


if __name__ == "__main__":
    main()
