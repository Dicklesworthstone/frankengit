#!/usr/bin/env python3
"""Exercise fg merge apply against a built fg binary; never simulate authority.

Every command opens the real embedded node in a fresh process. Fixture Git
objects and bundles are encoded independently using only the Python stdlib.
A missing binary or any failed assertion is an error, not a skipped success.
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

TENANT = "91" * 16
REPOSITORY = "92" * 16
PRINCIPAL = "93" * 16
TARGET = "refs/heads/main"
SOURCE = "refs/heads/topic"
KINDS = {"commit": 1, "tree": 2, "blob": 3}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def write_object(root, algorithm, kind, body):
    oid = identity(algorithm, kind, body)
    path = root / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
    return oid


def tree(entries):
    return b"".join(b"100644 " + name.encode() + b"\0" + bytes.fromhex(oid)
                    for name, oid in sorted(entries))


def commit(tree_id, parents, label):
    prefix = f"tree {tree_id}\n" + "".join(f"parent {oid}\n" for oid in parents)
    return (prefix + "author Test <test@example.invalid> 1 +0000\n"
            "committer Test <test@example.invalid> 1 +0000\n\n" + label + "\n").encode()


def pack(algorithm, objects):
    data = bytearray(b"PACK\0\0\0\x02" + len(objects).to_bytes(4, "big"))
    for kind, body in objects:
        size = len(body)
        first = (KINDS[kind] << 4) | (size & 15)
        size >>= 4
        data.append(first | (128 if size else 0))
        while size:
            part = size & 127
            size >>= 7
            data.append(part | (128 if size else 0))
        data.extend(zlib.compress(body))
    data.extend(hashlib.new(algorithm, data).digest())
    return bytes(data)


def inspect_fixture_bundle(data, algorithm, old, candidate):
    """Check our full-object fixture encoding; this is not a general pack reader."""
    header, packed = data.split(b"\n\n", 1)
    expected = (f"# v3 git bundle\n@object-format={algorithm}\n-{old} target prerequisite\n"
                f"{candidate} {TARGET}").encode()
    require(header == expected, "fixture review envelope drift")
    width = hashlib.new(algorithm).digest_size
    require(hashlib.new(algorithm, packed[:-width]).digest() == packed[-width:], "fixture pack checksum")
    body = packed[:-width]
    require(body[:8] == b"PACK\0\0\0\x02", "fixture pack version")
    count = int.from_bytes(body[8:12], "big")
    require(count <= 16, "fixture object count is unexpectedly large")
    offset, objects = 12, {}
    kinds = {value: key for key, value in KINDS.items()}
    for _ in range(count):
        first = body[offset]
        offset += 1
        size, shift, byte = first & 15, 4, first
        while byte & 128:
            require(shift < 64, "fixture size overflow")
            byte = body[offset]
            offset += 1
            size |= (byte & 127) << shift
            shift += 7
        kind = kinds[(first >> 4) & 7]
        decoder = zlib.decompressobj()
        payload = decoder.decompress(body[offset:], 65537)
        require(decoder.eof and len(payload) == size and size <= 65536, "fixture zlib framing")
        offset = len(body) - len(decoder.unused_data)
        oid = identity(algorithm, kind, payload)
        require(oid not in objects, "duplicate fixture object")
        objects[oid] = (kind, payload)
    require(offset == len(body) and candidate in objects, "fixture pack boundary or candidate missing")
    return objects


def make_source(root, algorithm):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n")
    (root / "config").write_text(
        "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        if algorithm == "sha256" else "[core]\nrepositoryformatversion = 0\nbare = true\n")
    common = write_object(root, algorithm, "blob", b"common\n")
    ours = write_object(root, algorithm, "blob", b"ours\n")
    theirs = write_object(root, algorithm, "blob", b"theirs\n")
    base_tree = write_object(root, algorithm, "tree", tree([("common.txt", common)]))
    ours_tree = write_object(root, algorithm, "tree", tree([("common.txt", common), ("ours.txt", ours)]))
    theirs_tree = write_object(root, algorithm, "tree", tree([("common.txt", common), ("theirs.txt", theirs)]))
    base = write_object(root, algorithm, "commit", commit(base_tree, [], "base"))
    target = write_object(root, algorithm, "commit", commit(ours_tree, [base], "ours"))
    source = write_object(root, algorithm, "commit", commit(theirs_tree, [base], "theirs"))
    (root / TARGET).write_text(target + "\n")
    (root / SOURCE).write_text(source + "\n")
    return dict(base=base, target=target, source=source, common=common, ours=ours, theirs=theirs)


def make_candidate(path, algorithm, history, old, label, parents=None):
    blob = ("reviewed " + label + "\n").encode()
    changed = identity(algorithm, "blob", blob)
    tree_body = tree([("common.txt", history["common"]), ("ours.txt", history["ours"]),
                      ("reviewed.txt", changed), ("theirs.txt", history["theirs"])])
    root = identity(algorithm, "tree", tree_body)
    body = commit(root, [old, history["source"]] if parents is None else parents, label)
    candidate = identity(algorithm, "commit", body)
    packed = pack(algorithm, [("blob", blob), ("tree", tree_body), ("commit", body)])
    header = (f"# v3 git bundle\n@object-format={algorithm}\n-{old} target prerequisite\n"
              f"{candidate} {TARGET}\n\n").encode()
    data = header + packed
    require(inspect_fixture_bundle(data, algorithm, old, candidate) == {
        changed: ("blob", blob), root: ("tree", tree_body), candidate: ("commit", body)},
        "independent fixture inspection failed")
    path.write_bytes(data)
    return candidate


def arguments(node, path, history, old, candidate, key, number=1, version=0):
    return ["merge", "apply", node, TENANT, REPOSITORY, TARGET, path,
            "--trusted-local", "--principal", PRINCIPAL, "--idempotency-key", key,
            "--source-ref", SOURCE, "--expected-source", history["source"],
            "--expected-target", old, "--merge-base", history["base"],
            "--expected-commit", candidate, "--pull-request", str(number),
            "--expected-version", str(version)]


def invoke(binary, args, success=True):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=120)
    require((result.returncode == 0) is success,
            f"unexpected fg exit {result.returncode}: {result.stdout!r}; {result.stderr!r}")
    return result


def terminal(result, history, old, candidate, number=1, version=0, refusal=None):
    receipt = json.loads(result.stdout)
    committed = refusal is None
    require(receipt["type"] == "merge_publication", "missing merge receipt")
    require(receipt["outcome"] == ("committed" if committed else "refused"), "wrong canonical outcome")
    require(receipt["published_to_repository"] is committed, "wrong merge publication claim")
    require(receipt["repository_id"] == REPOSITORY, "repository binding drift")
    require(type(receipt["pull_request"]) is int and receipt["pull_request"] == number, "PR binding drift")
    require(type(receipt["expected_version"]) is int and receipt["expected_version"] == version, "version drift")
    for field, expected in [("expected_source", history["source"]), ("expected_target", old),
                            ("merge_base", history["base"]), ("candidate_commit", candidate),
                            ("source_reference_hex", SOURCE.encode().hex()),
                            ("target_reference_hex", TARGET.encode().hex())]:
        require(receipt[field] == expected, f"review coordinate {field} drift")
    require(type(receipt["decision_sequence"]) is int and receipt["decision_sequence"] > 0, "missing decision")
    require(isinstance(receipt["tx_id"], str) and receipt["tx_id"], "missing transaction identity")
    require(receipt["node_closed"] is True and receipt["cleanup_error"] is None, "node did not close")
    require(receipt["delivery_acknowledged"] is None, "publication invented a delivery acknowledgement")
    if committed:
        require(receipt["repository_commit_id"] and receipt["repository_commit_id"] != candidate, "missing distinct RCR")
        require(receipt["refusal_code"] is None and receipt["refusal_record_id"] is None, "commit claims refusal")
    else:
        require(receipt["repository_commit_id"] is None and receipt["refusal_record_id"], "missing refusal record")
        require(receipt["refusal_code"] == refusal, "wrong canonical refusal code")
    return receipt


def state(binary, node):
    prefix = ["at", node, TENANT, REPOSITORY, "latest"]
    refs = invoke(binary, prefix + ["refs"]).stdout
    summary = invoke(binary, prefix).stdout
    generations = re.findall(rb"\(gen (\d+)\)", summary)
    require(len(generations) == 1, "snapshot must identify one authority generation")
    return refs, summary, int(generations[0])


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix=f"fg-merge-publication-{algorithm}-") as temporary:
        root = Path(temporary)
        node, source = root / "node", root / "source"
        history = make_source(source, algorithm)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "merge-source", source])
        initial = state(binary, node)
        first, second = root / "first.bundle", root / "second.bundle"
        winner = make_candidate(first, algorithm, history, history["target"], "winner")
        loser = make_candidate(second, algorithm, history, history["target"], "loser")
        first_args = arguments(node, first, history, history["target"], winner, "winner")
        no_trust = first_args.copy()
        no_trust.remove("--trusted-local")
        invoke(binary, no_trust, success=False)
        wrong_review = first_args.copy()
        wrong_review[wrong_review.index("--expected-commit") + 1] = loser
        invoke(binary, wrong_review, success=False)
        corrupt = root / "corrupt.bundle"
        data = bytearray(first.read_bytes())
        data[-1] ^= 1
        corrupt.write_bytes(data)
        invoke(binary, arguments(node, corrupt, history, history["target"], winner, "corrupt"), success=False)
        require(state(binary, node) == initial, "pre-admission refusal changed canonical state")
        accepted = terminal(invoke(binary, first_args), history, history["target"], winner)
        after = state(binary, node)
        require(after[2] == initial[2] + 1, "merge published more than one authority transition")
        require(winner.encode() in after[0] and history["source"].encode() in after[0], "wrong ref effects")
        require(terminal(invoke(binary, first_args), history, history["target"], winner) == accepted, "retry changed decision")
        require(state(binary, node) == after, "retry duplicated publication")
        changed = arguments(node, second, history, history["target"], loser, "winner")
        require(not invoke(binary, changed, success=False).stdout, "key reuse must not alias a committed receipt")
        require(state(binary, node) == after, "key misuse changed authority")
        second_args = arguments(node, second, history, history["target"], loser, "loser", number=2)
        rejected = terminal(invoke(binary, second_args, success=False), history, history["target"], loser,
                            number=2, refusal="TargetRefMoved")
        refused_state = state(binary, node)
        require(refused_state[0] == after[0] and refused_state[2] == after[2] + 1, "refusal changed refs or was not canonical")
        require(terminal(invoke(binary, second_args, success=False), history, history["target"], loser,
                         number=2, refusal="TargetRefMoved") == rejected, "refusal retry changed its outcome")
        require(state(binary, node) == refused_state, "refusal retry advanced authority")
        later_path = root / "later.bundle"
        later = make_candidate(later_path, algorithm, history, winner, "later")
        later_args = arguments(node, later_path, history, winner, later, "later", number=3)
        terminal(invoke(binary, later_args), history, winner, later, number=3)
        advanced = state(binary, node)
        require(later.encode() in advanced[0], "later merge did not publish")
        require(terminal(invoke(binary, first_args), history, history["target"], winner) == accepted, "historical outcome lost")
        require(state(binary, node) == advanced, "old retry rolled back the descendant")
        at = ["at", node, TENANT, REPOSITORY, f"decision:{accepted['decision_sequence']}", "refs"]
        historical = invoke(binary, at).stdout
        require(winner.encode() in historical and later.encode() not in historical, "historical ref read drift")
        exported = root / "selected.pack"
        invoke(binary, ["export", node, TENANT, REPOSITORY, exported])
        require(exported.read_bytes().startswith(b"PACK"), "post-merge authority-selected export failed")
        print(json.dumps({"type": "merge_publication_smoke", "format": algorithm,
                          "first_tx_id": accepted["tx_id"], "first_rcr": accepted["repository_commit_id"],
                          "last_generation": advanced[2], "completed": True}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path, help="built fg executable")
    parser.add_argument("--format", choices=["both", "sha1", "sha256"], default="both")
    options = parser.parse_args()
    binary = options.fg.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "--fg must name an executable regular file")
    with binary.open("rb") as handle:
        fingerprint = hashlib.file_digest(handle, "sha256").hexdigest()
    print(json.dumps({"binary": str(binary), "sha256": fingerprint}), flush=True)
    for algorithm in (["sha1", "sha256"] if options.format == "both" else [options.format]):
        run_format(binary, algorithm)


if __name__ == "__main__":
    main()
