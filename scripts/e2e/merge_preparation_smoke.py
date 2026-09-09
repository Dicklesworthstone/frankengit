#!/usr/bin/env python3
"""Exercise the built fg prepare/review/apply path; never simulate authority.

Fixtures and the non-delta pack inspector are independent Python encoders.
The inspector deliberately rejects delta entries: path-v1 emits full objects.
--self-test checks only those helpers, not the Rust implementation or fg.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = "a1" * 16, "a2" * 16, "a3" * 16
TARGET, SOURCE = "refs/heads/main", "refs/heads/topic"
IDENTITY = "Test <test@example.invalid>"
KINDS = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def oid(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def tree(entries):
    ordered = sorted(entries, key=lambda row: row[0] + (b"/" if row[1] == 0o40000 else b"\0"))
    require(len({row[0] for row in ordered}) == len(ordered), "duplicate fixture tree name")
    return b"".join(f"{mode:o} ".encode() + name + b"\0" + bytes.fromhex(identity)
                    for name, mode, identity in ordered)


def commit(root, parents, message):
    headers = f"tree {root}\n" + "".join(f"parent {parent}\n" for parent in parents)
    return (headers + f"author {IDENTITY} 1 +0000\ncommitter {IDENTITY} 1 +0000\n\n").encode() + message


def fixture(path, algorithm, conflict=False):
    (path / "refs/heads").mkdir(parents=True)
    (path / "HEAD").write_text(f"ref: {TARGET}\n")
    (path / "config").write_text(
        "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        if algorithm == "sha256" else "[core]\nrepositoryformatversion = 0\nbare = true\n")
    objects = {}

    def store(kind, body):
        identity = oid(algorithm, kind, body)
        objects[identity] = (kind, body)
        target = path / "objects" / identity[:2] / identity[2:]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return identity

    b = store("blob", b"one\ntwo\nthree\nfour\nfive\n")
    o = store("blob", b"ONE\ntwo\nthree\nfour\nfive\n")
    t = store("blob", b"THEIRS\ntwo\nthree\nfour\nfive\n" if conflict else b"one\ntwo\nthree\nfour\nFIVE\n")
    kept = store("blob", b"unchanged sibling\n")
    bt = store("tree", tree([(b"text", 0o100644, b)]))
    ot = store("tree", tree([(b"text", 0o100755, o)]))
    tt = store("tree", tree([(b"text", 0o100644, t)]))
    roots = [store("tree", tree([(b"dir", 0o40000, sub), (b"keep", 0o100644, kept)]))
             for sub in (bt, ot, tt)]
    base = store("commit", commit(roots[0], [], b"base\n"))
    target = store("commit", commit(roots[1], [base], b"target\n"))
    source = store("commit", commit(roots[2], [base], b"source\n"))
    (path / TARGET).write_text(target + "\n")
    (path / SOURCE).write_text(source + "\n")
    return {"base": base, "target": target, "source": source, "kept": kept, "objects": objects}


def inspect_bundle(data, algorithm, target, source):
    require(len(data) <= 40 * 1024 * 1024, "unexpected artifact size")
    header, packed = data.split(b"\n\n", 1)
    lines = header.split(b"\n")
    prefix = [b"# v2 git bundle"] if algorithm == "sha1" else [b"# v3 git bundle", b"@object-format=sha256"]
    require(lines[:len(prefix)] == prefix, "wrong bundle format")
    lines = lines[len(prefix):]
    require(len(lines) == 3, "unexpected advertised refs/prerequisites")
    require(lines[:2] == [f"-{target} target".encode(), f"-{source} source".encode()], "missing parent frontier")
    candidate, reference = lines[2].split(b" ", 1)
    candidate = candidate.decode("ascii")
    require(reference == TARGET.encode(), "artifact advertises wrong target")
    width = hashlib.new(algorithm).digest_size
    require(len(packed) >= 12 + width, "truncated pack")
    body, trailer = packed[:-width], packed[-width:]
    require(hashlib.new(algorithm, body).digest() == trailer, "pack checksum mismatch")
    require(body[:8] == b"PACK\0\0\0\x02", "pack version")
    count = int.from_bytes(body[8:12], "big")
    require(0 < count <= 10000, "pack object count")
    objects, cursor, total = {}, 12, 0
    for _ in range(count):
        require(cursor < len(body), "missing object header")
        first = body[cursor]
        cursor += 1
        kind = KINDS.get((first >> 4) & 7)
        require(kind is not None, "path-v1 must not emit delta entries")
        size, shift, byte = first & 15, 4, first
        while byte & 128:
            require(cursor < len(body) and shift < 64, "invalid object size")
            byte = body[cursor]
            cursor += 1
            size |= (byte & 127) << shift
            shift += 7
        require(size <= 32 * 1024 * 1024, "object byte limit")
        decoder = zlib.decompressobj()
        payload = decoder.decompress(body[cursor:], size + 1)
        require(decoder.eof and len(payload) == size and not decoder.unconsumed_tail, "zlib member mismatch")
        consumed = len(body) - cursor - len(decoder.unused_data)
        require(consumed > 0, "zlib made no progress")
        cursor += consumed
        total += size
        require(total <= 32 * 1024 * 1024, "expanded pack limit")
        identity = oid(algorithm, kind, payload)
        require(identity not in objects, "duplicate generated object")
        objects[identity] = (kind, payload)
    require(cursor == len(body), "trailing pack bytes")
    require(candidate in objects and objects[candidate][0] == "commit", "missing candidate commit")
    require(len(candidate) == 2 * width, "candidate hash width")
    return candidate, objects


def synthetic_pack(algorithm, objects):
    packed = bytearray(b"PACK\0\0\0\x02" + len(objects).to_bytes(4, "big"))
    kinds = {name: number for number, name in KINDS.items()}
    for kind, body in objects:
        size = len(body)
        byte = (kinds[kind] << 4) | (size & 15)
        size >>= 4
        packed.append(byte | (128 if size else 0))
        while size:
            byte = size & 127
            size >>= 7
            packed.append(byte | (128 if size else 0))
        packed.extend(zlib.compress(body))
    packed.extend(hashlib.new(algorithm, packed).digest())
    return bytes(packed)


def invoke(binary, arguments, success=True):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, timeout=180)
    if result.stderr:
        print(result.stderr.decode(errors="replace"), end="", file=__import__("sys").stderr)
    require((result.returncode == 0) == success,
            f"unexpected fg exit {result.returncode}: {result.stdout!r}; {result.stderr!r}")
    return result


def current_state(binary, node):
    prefix = ["at", node, TENANT, REPOSITORY, "latest"]
    refs = invoke(binary, prefix + ["refs"]).stdout
    summary = invoke(binary, prefix).stdout
    generations = re.findall(rb"\(gen (\d+)\)", summary)
    require(len(generations) == 1, "missing authenticated generation")
    return refs, summary, int(generations[0])


def prep_args(node, path, message=b"prepared merge\n"):
    return ["merge", "prepare", node, TENANT, REPOSITORY, TARGET, path,
            "--trusted-local", "--profile", "path-v1", "--source-ref", SOURCE,
            "--author", IDENTITY, "--timestamp", "1", "--message", message.decode()]


def apply_args(node, path, receipt, key, number):
    return ["merge", "apply", node, TENANT, REPOSITORY, TARGET, path,
            "--trusted-local", "--principal", PRINCIPAL, "--idempotency-key", key,
            "--source-ref", SOURCE, "--expected-source", receipt["expected_source"],
            "--expected-target", receipt["expected_target"], "--merge-base", receipt["merge_base"],
            "--expected-commit", receipt["candidate_commit"], "--pull-request", str(number),
            "--expected-version", "0"]


def check_receipt(receipt, history, status):
    require(receipt["type"] == "merge_preparation" and receipt["profile"] == "path-v1", "profile binding")
    require(receipt["outcome"] == status and receipt["published_to_repository"] is False, "preparation claimed publication")
    require(receipt["repository_id"] == REPOSITORY and receipt["node_closed"] is True, "repository/lifecycle binding")
    require(receipt["source_head"], "missing pinned authority head")
    require(receipt["source_reference_hex"] == SOURCE.encode().hex(), "source reference")
    require(receipt["target_reference_hex"] == TARGET.encode().hex(), "target reference")
    if status != "already_up_to_date":
        require(receipt["merge_base"] == history["base"], "wrong selected merge base")
    if status == "prepared":
        require(receipt["bundle_created"] is True, "clean result missing artifact")
        require(receipt["expected_source"] == history["source"], "source-tip drift")
        require(receipt["expected_target"] == history["target"], "target-tip drift")
    else:
        require(receipt["bundle_created"] is False, "non-clean result created artifact")


def run_format(binary, algorithm, conflict=False):
    with tempfile.TemporaryDirectory(prefix=f"fg-prepare-{algorithm}-") as temporary:
        root = Path(temporary)
        node, source = root / "node", root / "source"
        history = fixture(source, algorithm, conflict)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "prepare-import", source])
        before = current_state(binary, node)
        first = root / "first.bundle"
        result = invoke(binary, prep_args(node, first), success=not conflict)
        receipt = json.loads(result.stdout)
        check_receipt(receipt, history, "conflicted" if conflict else "prepared")
        require(current_state(binary, node) == before, "preparation changed repository state")
        if conflict:
            require(not first.exists(), "conflicted preparation exposed an artifact")
            require(len(receipt["conflicts"]) == 1, "unexpected conflict count")
            item = receipt["conflicts"][0]
            require(item["path_hex"] == b"dir/text".hex() and item["kind"] == "Content", "wrong conflict evidence")
            print(json.dumps({"type": "merge_preparation_smoke", "format": algorithm, "case": "conflict", "result": "passed"}))
            return
        data = first.read_bytes()
        candidate, objects = inspect_bundle(data, algorithm, history["target"], history["source"])
        require(candidate == receipt["candidate_commit"], "receipt candidate is not the native pack identity")
        require(receipt["object_count"] == len(objects) and receipt["bundle_bytes"] == len(data), "artifact count mismatch")
        text = b"ONE\ntwo\nthree\nfour\nFIVE\n"
        blob = oid(algorithm, "blob", text)
        subtree_bytes = tree([(b"text", 0o100755, blob)])
        subtree = oid(algorithm, "tree", subtree_bytes)
        root_bytes = tree([(b"dir", 0o40000, subtree), (b"keep", 0o100644, history["kept"])])
        expected_root = oid(algorithm, "tree", root_bytes)
        commit_bytes = commit(expected_root, [history["target"], history["source"]], b"prepared merge\n")
        expected_candidate = oid(algorithm, "commit", commit_bytes)
        require(candidate == expected_candidate and receipt["root_tree"] == expected_root, "incorrect merged tree/parents/metadata")
        require(objects == {blob: ("blob", text), subtree: ("tree", subtree_bytes),
                            expected_root: ("tree", root_bytes), candidate: ("commit", commit_bytes)},
                "candidate objects differ from independent exact result")
        require(history["kept"] not in objects, "unchanged sibling was unnecessarily copied")
        repeat = root / "repeat.bundle"
        again = json.loads(invoke(binary, prep_args(node, repeat)).stdout)
        require(repeat.read_bytes() == data and again["candidate_commit"] == candidate, "nondeterministic candidate")
        invoke(binary, prep_args(node, first), success=False)
        require(first.read_bytes() == data, "existing artifact was replaced")
        competitor = root / "competitor.bundle"
        rival = json.loads(invoke(binary, prep_args(node, competitor, b"different reviewed merge\n")).stdout)
        require(rival["candidate_commit"] != candidate, "message not bound into candidate identity")
        args = apply_args(node, first, receipt, "prepared-review", 1)
        accepted = json.loads(invoke(binary, args).stdout)
        require(accepted["outcome"] == "committed" and accepted["published_to_repository"] is True, "merge did not commit")
        require(accepted["candidate_commit"] == candidate and accepted["node_closed"] is True, "publication binding")
        after = current_state(binary, node)
        require(after[2] == before[2] + 1 and candidate.encode() in after[0], "coupled publication generation/ref mismatch")
        require(json.loads(invoke(binary, args).stdout) == accepted, "retry changed terminal result")
        require(current_state(binary, node) == after, "retry advanced authority")
        stale = json.loads(invoke(binary, apply_args(node, competitor, rival, "prepared-rival", 2), success=False).stdout)
        require(stale["outcome"] == "refused" and stale["refusal_code"] == "TargetRefMoved", "stale candidate was not refused")
        refused = current_state(binary, node)
        require(refused[0] == after[0] and refused[2] == after[2] + 1, "stale refusal changed source state")
        noop_path = root / "noop.bundle"
        noop = json.loads(invoke(binary, prep_args(node, noop_path)).stdout)
        check_receipt(noop, history, "already_up_to_date")
        require(not noop_path.exists() and noop["expected_target"] == candidate, "no-op created another merge")
        require(current_state(binary, node) == refused, "no-op advanced authority")
        print(json.dumps({"type": "merge_preparation_smoke", "format": algorithm,
                          "case": "prepare_apply_retry", "result": "passed", "candidate": candidate}))


def self_test():
    for algorithm in ("sha1", "sha256"):
        with tempfile.TemporaryDirectory() as temporary:
            history = fixture(Path(temporary), algorithm)
            payload = commit(oid(algorithm, "tree", b""), [history["target"], history["source"]], b"inspector-only\n")
            candidate = oid(algorithm, "commit", payload)
            prefix = (b"# v2 git bundle\n" if algorithm == "sha1" else b"# v3 git bundle\n@object-format=sha256\n")
            header = prefix + f"-{history['target']} target\n-{history['source']} source\n{candidate} {TARGET}\n\n".encode()
            data = header + synthetic_pack(algorithm, [("commit", payload)])
            require(inspect_bundle(data, algorithm, history["target"], history["source"])[1] == {candidate: ("commit", payload)}, "helper roundtrip")
            for damaged in (data[:-1], data + b"junk", data[:-1] + bytes([data[-1] ^ 1]),
                            data.replace(TARGET.encode(), b"refs/heads/wrong", 1)):
                try:
                    inspect_bundle(damaged, algorithm, history["target"], history["source"])
                except (AssertionError, ValueError, zlib.error):
                    pass
                else:
                    raise AssertionError("damaged bundle accepted")
    print("fixture and inspector self-tests passed; Rust and fg were NOT executed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", type=Path, help="path to a real, already-built fg executable")
    parser.add_argument("--self-test", action="store_true", help="test only the independent Python helpers")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.fg is None:
        parser.error("--fg is required; missing runtime evidence is not a skipped success")
    binary = args.fg.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "fg must be an executable file")
    print(json.dumps({"type": "binary_under_test", "path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
    for algorithm in ("sha1", "sha256"):
        run_format(binary, algorithm)
        run_format(binary, algorithm, conflict=True)


if __name__ == "__main__":
    main()
