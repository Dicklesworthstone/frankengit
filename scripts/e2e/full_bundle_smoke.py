#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import zlib
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, fixture, document, require, identity


def invoke(binary, args, code=0, data=None):
    result = subprocess.run([str(binary), *map(str, args)], input=data, capture_output=True, timeout=120)
    require(result.returncode == code, f"fg exit {result.returncode}, wanted {code}: {result.stderr!r}; {result.stdout!r}")
    return result


def decode_export(data, algorithm):
    header, pack = data.split(b"\n\n", 1)
    lines = header.split(b"\n")
    require(lines.pop(0) == (b"# v2 git bundle" if algorithm == "sha1" else b"# v3 git bundle"), "bundle version")
    if algorithm == "sha256":
        require(lines.pop(0) == b"@object-format=sha256", "explicit SHA-256 capability")
    refs = {}
    for line in lines:
        oid, name = line.split(b" ", 1)
        require(name not in refs, "duplicate bundle ref")
        refs[name] = oid.decode("ascii")
    width = hashlib.new(algorithm).digest_size
    require(hashlib.new(algorithm, pack[:-width]).digest() == pack[-width:], "native pack checksum")
    require(pack[:4] == b"PACK", "pack signature")
    version, count = struct.unpack(">II", pack[4:12])
    require(version == 2, "pack version")
    cursor, objects = 12, {}
    for _ in range(count):
        value = pack[cursor]
        cursor += 1
        kind, size, shift = (value >> 4) & 7, value & 15, 4
        while value & 128:
            value = pack[cursor]
            cursor += 1
            size |= (value & 127) << shift
            shift += 7
        require(kind in (1, 2, 3, 4), "export promises no delta objects")
        decoder = zlib.decompressobj()
        body = decoder.decompress(pack[cursor:-width])
        require(decoder.eof and len(body) == size, "complete exact-length zlib member")
        cursor = len(pack) - width - len(decoder.unused_data)
        label = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}[kind]
        oid = identity(algorithm, label, body)
        require(oid not in objects, "duplicate exported object")
        objects[oid] = (label, body)
    require(cursor == len(pack) - width, "extra/truncated pack bytes")
    return refs, objects


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-full-bundle-") as directory:
        root = Path(directory)
        source, original, destination = root / "source", root / "original", root / "destination"
        f = fixture(source, algorithm)
        invoke(binary, ["init", original, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", original, TENANT, REPOSITORY, PRINCIPAL, "fixture", source])
        def args(operation, node, path, *extra):
            return ["bundle", operation, node, TENANT, REPOSITORY, path, "--trusted-local", "--object-format", algorithm, *extra]
        def refs(node):
            return document(invoke(binary, ["branch", "list", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm]))
        before = refs(original)
        output = root / "complete.bundle"
        report = document(invoke(binary, args("export", original, output)))
        require(report["type"] == "git_bundle_export" and report["object_count"] == 5, "export object count")
        require(report["node_closed"] and not report["repository_changed"] and not report["includes_forge_metadata"], "export effect scope")
        raw = output.read_bytes()
        exported_refs, objects = decode_export(raw, algorithm)
        require({f[key] for key in ("blob", "tree", "base", "target", "source")} == set(objects), "exact original object closure")
        require(exported_refs[b"refs/heads/main"] == f["target"] and exported_refs[b"refs/heads/topic"] == f["source"], "advertised tips")
        require(refs(original) == before, "export changed authority")
        invoke(binary, args("export", original, output), code=2)
        require(output.read_bytes() == raw, "existing output overwritten")
        invoke(binary, ["init", destination, TENANT, REPOSITORY, algorithm])
        command = args("import", destination, output, "--principal", PRINCIPAL, "--key-stdin")
        key = b"exact-transfer-key\n"
        imported = document(invoke(binary, command, data=key))
        require(imported["type"] == "git_bundle_import" and imported["command_committed"] and imported["atomic"], "atomic publication")
        require(imported["reference_count"] == 2 and imported["principal_id"] == PRINCIPAL, "scoped publication")
        require(imported["node_closed"] and imported["cleanup_error"] is None and imported["refusal_record_id"] is None, "terminal receipt")
        require(key.strip().decode() not in str(imported), "retry key disclosed")
        settled = refs(destination)
        require(settled["branches"] == before["branches"], "round trip ref identity")
        require(document(invoke(binary, command, data=key)) == imported, "fresh-process exact replay")
        require(refs(destination) == settled, "replay advanced authority")
        second = root / "again.bundle"
        document(invoke(binary, args("export", destination, second)))
        second_refs, second_objects = decode_export(second.read_bytes(), algorithm)
        require({k: v for k, v in second_refs.items() if k != b"HEAD"} == {k: v for k, v in exported_refs.items() if k != b"HEAD"} and second_objects == objects, "round trip native bytes")
        collision = args("import", original, output, "--principal", PRINCIPAL, "--idempotency-key", "collision")
        refused = document(invoke(binary, collision, code=3))
        require(refused["outcome"] == "refused" and not refused["command_committed"] and refused["refusal_record_id"] is not None, "collision is a canonical refusal")
        require(refs(original)["branches"] == before["branches"], "collision overwrote a ref")
        require(document(invoke(binary, collision, code=3)) == refused, "refusal replay")
        bad = root / "bad.bundle"
        bad.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        fresh = root / "fresh"
        invoke(binary, ["init", fresh, TENANT, REPOSITORY, algorithm])
        empty = refs(fresh)
        invoke(binary, args("import", fresh, bad, "--principal", PRINCIPAL, "--idempotency-key", "corrupt"), code=2)
        require(refs(fresh) == empty, "corruption published a decision or refs")
        changed = root / "changed.bundle"
        changed.write_bytes(raw.replace(b"refs/heads/topic\n", b"refs/heads/other\n", 1))
        invoke(binary, args("import", destination, changed, "--principal", PRINCIPAL, "--key-stdin"), code=2, data=key)
        require(refs(destination) == settled, "key rebinding changed authority")
        deleted = document(invoke(binary, ["branch", "delete", original, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm,
                           "--principal", PRINCIPAL, "--idempotency-key", "delete-topic", "--ref", "refs/heads/topic", "--expected-tip", f["source"]]))
        require(deleted["command_committed"], "delete obsolete branch")
        reduced = root / "reduced.bundle"
        document(invoke(binary, args("export", original, reduced)))
        reduced_refs, reduced_objects = decode_export(reduced.read_bytes(), algorithm)
        require(b"refs/heads/topic" not in reduced_refs and f["source"] not in reduced_objects, "deleted-only history leaked")
        require(set(reduced_objects) == {f[key] for key in ("blob", "tree", "base", "target")}, "reduced closure lost shared history")
        print(f"FULL_BUNDLE_CLI format={algorithm} transfer_replay_collision_corruption_retained_history=passed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True, type=Path)
    options = parser.parse_args()
    for algorithm in ("sha1", "sha256"):
        run_format(options.fg.resolve(), algorithm)


if __name__ == "__main__":
    main()
