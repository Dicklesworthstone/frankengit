#!/usr/bin/env python3
"""Real fg rebase preparation with independent object identities and pack decoding."""
import argparse
import hashlib
from pathlib import Path
import struct
import tempfile
import zlib
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, fixture, identity, invoke, document, require


def native_commit(tree, parent, message, rewritten=False):
    committer = "Rebaser <rebaser@example.invalid> 100 +0000" if rewritten else "Test <test@example.invalid> 1 +0000"
    return (f"tree {tree}\nparent {parent}\nauthor Test <test@example.invalid> 1 +0000\ncommitter {committer}\n\n".encode() + message)


def tree_bytes(entries):
    return b"".join(b"100644 " + name + b"\0" + bytes.fromhex(oid) for name, oid in sorted(entries.items()))


def decode_bundle(data, algorithm, onto, candidate):
    width = hashlib.new(algorithm).digest_size
    header, separator, pack = data.partition(b"\n\n")
    signature = b"# v2 git bundle\n" if algorithm == "sha1" else b"# v3 git bundle\n@object-format=sha256\n"
    require(separator and header == signature + f"-{onto} onto\n{candidate} refs/heads/topic".encode(), "exact source ref and sole onto prerequisite")
    require(len(pack) >= 12 + width and pack[:8] == b"PACK\0\0\0\2", "native pack header")
    require(hashlib.new(algorithm, pack[:-width]).digest() == pack[-width:], "native pack checksum")
    count = struct.unpack(">I", pack[8:12])[0]
    offset, objects = 12, {}
    kinds = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
    for _ in range(count):
        require(offset < len(pack)-width, "missing object header")
        byte = pack[offset]
        offset += 1
        kind, size, shift = (byte >> 4) & 7, byte & 15, 4
        while byte & 128:
            require(offset < len(pack)-width and shift < 64, "invalid size framing")
            byte = pack[offset]
            offset += 1
            size |= (byte & 127) << shift
            shift += 7
        require(kind in kinds and size <= 32*1024*1024, "unexpected delta or oversized object")
        remaining = pack[offset:-width]
        inflater = zlib.decompressobj()
        body = inflater.decompress(remaining, size+1)
        require(inflater.eof and len(body) == size, "exact inflated object boundary")
        offset += len(remaining)-len(inflater.unused_data)
        oid = identity(algorithm, kinds[kind], body)
        require(oid not in objects, "duplicate packed identity")
        objects[oid] = (kinds[kind], body)
    require(offset == len(pack)-width, "unaccounted pack bytes")
    return objects


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-rebase-cli-") as temporary:
        root = Path(temporary)
        source, node = root/"source", root/"node"
        f = fixture(source, algorithm)
        originals = {}
        def store(kind, body):
            oid = identity(algorithm, kind, body)
            destination = source/"objects"/oid[:2]/oid[2:]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode()+body))
            originals[oid] = (kind, body)
            return oid
        changed = store("blob", b"source-only replacement\n")
        second_tree = store("tree", tree_bytes({b"preserved.txt": changed}))
        second_message = b"second\r\n\xff without final LF"
        second = store("commit", native_commit(second_tree, f["source"], second_message))
        added = store("blob", b"source-only addition\n")
        final_tree = store("tree", tree_bytes({b"added.txt": added, b"preserved.txt": changed}))
        third_message = b"third\n"
        tip = store("commit", native_commit(final_tree, second, third_message))
        (source/"refs/heads/topic").write_text(tip+"\n", encoding="ascii")
        (source/"refs/heads/already").write_text(tip+"\n", encoding="ascii")
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "rebase-import", source])
        def snapshot():
            return document(invoke(binary, ["pr", "list", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm]))
        before = snapshot()
        def prepare(name, onto=f["target"], onto_ref="refs/heads/main", upstream=f["base"], empty="stop", extra=(), code=0):
            path = root/name
            result = invoke(binary, ["rebase", "prepare", node, TENANT, REPOSITORY, "refs/heads/topic", path,
                "--trusted-local", "--profile", "path-v1", "--onto-ref", onto_ref,
                "--expected-source", tip, "--expected-onto", onto, "--upstream", upstream,
                "--committer", "Rebaser <rebaser@example.invalid>", "--timestamp", "100", "--empty", empty,
                "--expected-head", before["snapshot_token"], *extra], code)
            if code == 2:
                require(not result.stdout, "an error emitted a successful receipt")
                return None
            report = document(result)
            require(report["type"] == "rebase_preparation" and report["schema_version"] == 1, "receipt schema")
            require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "repository binding")
            require(report["expected_source"] == tip and report["expected_onto"] == onto and report["upstream"] == upstream, "input binding")
            require(report["snapshot_token"] == before["snapshot_token"] and report["object_format"] == algorithm, "exact authenticated basis/domain")
            require(report["node_closed"] is True and report["objects_staged"] is False and report["published_to_repository"] is False and report["approval_granted"] is False, "preparation effects")
            require(report["bundle_created"] is (code == 0) and path.exists() is (code == 0), "artifact disposition")
            if code == 0:
                payload = path.read_bytes()
                require(report["bundle_bytes"] == len(payload) and report["bundle_sha256"] == hashlib.sha256(payload).hexdigest(), "bundle digest/length")
                objects = decode_bundle(payload, algorithm, onto, report["candidate_commit"])
                require(len(objects) == report["pack_objects"], "packed count")
                return report, payload, objects
            return report
        report, bundle, objects = prepare("rebased.bundle")
        parent, expected = f["target"], {oid: originals[oid] for oid in [changed, second_tree, added, final_tree]}
        for step, old, tree, message, kind in zip(report["steps"], [f["source"], second, tip],
                [f["tree"], second_tree, final_tree], [b"source\n", second_message, third_message], ["preserved_empty", "replayed", "replayed"], strict=True):
            body = native_commit(tree, parent, message, rewritten=True)
            new = identity(algorithm, "commit", body)
            require(step == dict(original=old, rewritten=new, tree=tree, kind=kind), "independently computed step identity/metadata")
            expected[new] = ("commit", body)
            parent = new
        require(report["candidate_commit"] == parent and report["root_tree"] == final_tree, "final native result")
        require(objects == expected and report["generated_objects"] == 3 and report["borrowed_objects"] == 4, "complete onto-only dependency closure")
        require(prepare("deterministic.bundle")[1] == bundle, "fresh-process identity determinism")
        prepare("rebased.bundle", code=2)
        require((root/"rebased.bundle").read_bytes() == bundle, "existing bundle overwritten")
        prepare("bounded.bundle", extra=["--max-commits", "1"], code=2)
        require(not (root/"bounded.bundle").exists(), "bounded failure wrote artifact")
        stopped = prepare("stopped.bundle", onto=tip, onto_ref="refs/heads/already", code=3)
        require(stopped["outcome"] == "became_empty" and stopped["candidate_commit"] is None and stopped["stopped_commit"] == second, "newly-empty stop")
        dropped, _, _ = prepare("dropped.bundle", onto=tip, onto_ref="refs/heads/already", empty="drop")
        require([step["kind"] for step in dropped["steps"]] == ["preserved_empty", "dropped_empty", "dropped_empty"], "explicit empty policy")
        empty, _, empty_objects = prepare("empty.bundle", upstream=tip)
        require(empty["candidate_commit"] == f["target"] and empty["steps"] == [] and empty_objects == {}, "zero-object source-branch result")
        require(snapshot() == before, "preparation changed canonical state across processes")
        print(f"REBASE_CLI format={algorithm} native_series_metadata_borrowed_objects_empty_controls_snapshot=passed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    args = parser.parse_args()
    for algorithm in ["sha1", "sha256"]:
        run_format(args.fg.resolve(), algorithm)


if __name__ == "__main__":
    main()
