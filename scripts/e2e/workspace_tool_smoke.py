#!/usr/bin/env python3
"""Exercise the actual fg binary and independently inspect its candidate bundles.

No Git engine is invoked. Fixtures use standard-library hash/zlib encoders;
the actual candidate bytes must come from fg workspace run. This is functional
CLI evidence when executed, not a pinned-upstream differential campaign.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zlib

TENANT = "91" * 16
REPOSITORY = "92" * 16
PRINCIPAL = "93" * 16
AUTHOR = "Workspace Test <test@example.invalid>"
REF = "refs/heads/main"
MAX_BUNDLE_BYTES = 128 * 1024 * 1024 + 4096


def require(condition, detail):
    if not condition:
        raise AssertionError(detail)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, kind.encode() + b" " + str(len(body)).encode() + b"\0" + body).hexdigest()


def write_object(directory, algorithm, kind, body):
    oid = identity(algorithm, kind, body)
    target = directory / "objects" / oid[:2] / oid[2:]
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(zlib.compress(kind.encode() + b" " + str(len(body)).encode() + b"\0" + body))
    return oid


def tree(entries):
    return b"".join(mode + b" " + name + b"\0" + bytes.fromhex(oid) for mode, name, oid in entries)


def commit(tree_id, parent, timestamp, message):
    parent_line = f"parent {parent}\n" if parent else ""
    return (f"tree {tree_id}\n{parent_line}author {AUTHOR} {timestamp} +0000\n"
            f"committer {AUTHOR} {timestamp} +0000\n\n").encode() + message


def inspect_bundle(data, algorithm, expected_parent, expected_commit):
    require(len(data) <= MAX_BUNDLE_BYTES, "bundle exceeds test input bound")
    header, separator, pack = data.partition(b"\n\n")
    require(separator, "bundle header is incomplete")
    expected_header = (f"# v3 git bundle\n@object-format={algorithm}\n"
                       f"-{expected_parent} TreeFS source prerequisite\n{expected_commit} {REF}").encode()
    require(header == expected_header, "bundle must bind native format, source prerequisite and candidate ref")
    width = hashlib.new(algorithm).digest_size
    require(len(pack) >= 12 + width and pack[:4] == b"PACK", "missing finalized Git pack")
    version, count = struct.unpack(">II", pack[4:12])
    require(version == 2 and count <= 100_002, "unsupported pack version or excessive object count")
    require(hashlib.new(algorithm, pack[:-width]).digest() == pack[-width:], "pack checksum mismatch")
    labels = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
    objects, cursor = {}, 12
    for _ in range(count):
        require(cursor < len(pack) - width, "truncated entry header")
        byte = pack[cursor]
        cursor += 1
        code, length, shift = (byte >> 4) & 7, byte & 15, 4
        while byte & 128:
            require(cursor < len(pack) - width and shift < 64, "invalid entry length")
            byte = pack[cursor]
            cursor += 1
            length |= (byte & 127) << shift
            shift += 7
        require(code in labels and length <= 64 * 1024 * 1024, "profile must emit bounded non-delta entries")
        decoder = zlib.decompressobj()
        tail = pack[cursor:-width]
        body = decoder.decompress(tail, length + 1)
        require(decoder.eof and len(body) == length, "entry zlib or native body length mismatch")
        cursor += len(tail) - len(decoder.unused_data)
        oid = identity(algorithm, labels[code], body)
        require(oid not in objects, "duplicate candidate object")
        objects[oid] = (labels[code], body)
    require(cursor == len(pack) - width, "trailing data or incomplete entry consumption")
    return objects


def invoke(binary, arguments, environment, success=True):
    result = subprocess.run([str(binary), *map(str, arguments)], env=environment,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=90, check=False)
    if success and result.returncode != 0:
        raise AssertionError(f"fg {arguments[0]} failed ({result.returncode}):\n"
                             + result.stderr.decode(errors="replace"))
    if not success:
        require(result.returncode != 0, "expected a real CLI refusal")
    return result


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix=f"fg-workspace-{algorithm}-") as temporary:
        root = Path(temporary)
        source, node, parent = root / "source", root / "node", root / "private"
        parent.mkdir(mode=0o700)
        (source / "refs/heads").mkdir(parents=True)
        (source / "HEAD").write_text(f"ref: {REF}\n")
        config = "[core]\nrepositoryformatversion = 0\nbare = true\n"
        if algorithm == "sha256":
            config = "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        (source / "config").write_text(config)
        before = write_object(source, algorithm, "blob", b"before\n")
        keep = write_object(source, algorithm, "blob", b"preserved\n")
        base_tree = write_object(source, algorithm, "tree", tree([
            (b"100644", b"edit.txt", before), (b"100644", b"keep.txt", keep)]))
        base = write_object(source, algorithm, "commit", commit(base_tree, None, 0, b"base\n"))
        (source / REF).write_text(base + "\n")
        environment = dict(os.environ, FG_WORKSPACE_SECRET="must-not-reach-tool")
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm], environment)
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "workspace-source", source], environment)
        inspect = ["at", node, TENANT, REPOSITORY, "latest", "refs"]
        old_refs = invoke(binary, inspect, environment).stdout
        require(base.encode() in old_refs, "source import did not publish the fixture ref")
        tool = ("from pathlib import Path; import os; "
                "assert not Path('keep.txt').exists(); "
                "assert os.environ.get('FG_WORKSPACE_SECRET') is None; "
                "print('trusted tool diagnostic'); "
                "Path('edit.txt').write_bytes(b'after\\n'); "
                "Path('new.txt').write_bytes(b'new\\n'); Path('new.txt').chmod(0o755)")

        def command(slot, destination, script, reads=("edit.txt", "new.txt"), writes=("edit.txt", "new.txt")):
            arguments = ["workspace", "run", node, TENANT, REPOSITORY, REF, parent, slot, destination, "--trusted-local"]
            for path in reads:
                arguments.extend(["--read", path])
            for path in writes:
                arguments.extend(["--write", path])
            return arguments + ["--author", AUTHOR, "--timestamp", "1", "--message", "candidate\n",
                                "--timeout-secs", "30", "--", sys.executable, "-c", script]

        first = command("94" * 16, "candidate.bundle", tool)
        result = invoke(binary, first, environment)
        receipt = json.loads(result.stdout)
        require(b"trusted tool diagnostic" in result.stderr, "tool stdout must route to diagnostics")
        require(receipt["type"] == "workspace_candidate" and receipt["published_to_repository"] is False,
                "preparation must not claim repository publication")
        require(receipt["source_commit"] == base and receipt["object_format"] == algorithm, "source/format binding")
        require(receipt["changed_paths_hex"] == [b"edit.txt".hex(), b"new.txt".hex()], "exact declared output receipt")
        after = identity(algorithm, "blob", b"after\n")
        new = identity(algorithm, "blob", b"new\n")
        candidate_tree_body = tree([(b"100644", b"edit.txt", after), (b"100644", b"keep.txt", keep),
                                    (b"100755", b"new.txt", new)])
        candidate_tree = identity(algorithm, "tree", candidate_tree_body)
        candidate_body = commit(candidate_tree, base, 1, b"candidate\n")
        candidate = identity(algorithm, "commit", candidate_body)
        require(receipt["root_tree"] == candidate_tree and receipt["candidate_commit"] == candidate, "exact native candidate identities")
        data = (parent / "candidate.bundle").read_bytes()
        objects = inspect_bundle(data, algorithm, base, candidate)
        require(objects == {after: ("blob", b"after\n"), new: ("blob", b"new\n"),
                            candidate_tree: ("tree", candidate_tree_body), candidate: ("commit", candidate_body)},
                "candidate pack must contain exact changes while preserving unselected base identities")
        require(receipt["objects"] == len(objects), "object-count receipt must match pack")
        require(sorted(p.name for p in parent.iterdir()) == ["candidate.bundle"], "workspace/staging cleanup")
        require(invoke(binary, inspect, environment).stdout == old_refs, "candidate construction changed canonical refs")
        repeat = invoke(binary, command("95" * 16, "repeat.bundle", tool), environment)
        require(json.loads(repeat.stdout)["candidate_commit"] == candidate, "candidate identity must not depend on workspace ID")
        require((parent / "repeat.bundle").read_bytes() == data, "deterministic candidate bundle bytes")

        marker = root / "tool-was-run"
        marker_script = f"from pathlib import Path; Path({str(marker)!r}).touch()"
        no_trust = command("96" * 16, "untrusted.bundle", marker_script)
        no_trust.remove("--trusted-local")
        invoke(binary, no_trust, environment, success=False)
        require(not marker.exists() and not (parent / "untrusted.bundle").exists(), "untrusted invocation had effects")
        invoke(binary, command("97" * 16, "candidate.bundle", marker_script), environment, success=False)
        require(not marker.exists() and (parent / "candidate.bundle").read_bytes() == data, "existing output was overwritten or tool ran")
        invoke(binary, command("98" * 16, "forbidden.bundle",
                               "from pathlib import Path; Path('keep.txt').write_bytes(b'forbidden')",
                               ("edit.txt", "keep.txt"), ("edit.txt",)), environment, success=False)
        require(sorted(p.name for p in parent.iterdir()) == ["candidate.bundle", "repeat.bundle"], "refused import left output or live workspace")
        require(invoke(binary, inspect, environment).stdout == old_refs, "refusal changed canonical refs")
        return {"format": algorithm, "candidate": candidate, "objects": len(objects),
                "deterministic": True, "canonical_refs_unchanged": True, "refusal_cases": 3}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path, help="actual freshly built fg binary")
    parser.add_argument("--format", choices=("sha1", "sha256", "both"), default="both")
    options = parser.parse_args()
    binary = options.fg.resolve(strict=True)
    require(sys.platform.startswith("linux"), "workspace host profile is Linux-only")
    algorithms = ("sha1", "sha256") if options.format == "both" else (options.format,)
    results = [run_format(binary, algorithm) for algorithm in algorithms]
    print(json.dumps({"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": results}, sort_keys=True))


if __name__ == "__main__":
    main()
