#!/usr/bin/env python3
"""Recovered PR CLI campaign, reconciled with main. Self-test runs no Rust."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zlib

TENANT, REPOSITORY, PRINCIPAL = "d1" * 16, "d2" * 16, "d3" * 16
SOURCE, TARGET = "refs/heads/topic", "refs/heads/main"
TITLE = "Native PR: exact metadata"
BODY = 'Untrusted <script> and "quotes"\r\nUnicode: é; controls: \x1b[2J\u009b31m\u202e\n'


def require(value, message):
    if not value:
        raise AssertionError(message)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def commit_body(tree, parents, message):
    return (f"tree {tree}\n" + "".join(f"parent {parent}\n" for parent in parents) +
            "author Fixture <fixture@example.invalid> 1 +0000\n"
            "committer Fixture <fixture@example.invalid> 1 +0000\n\n" + message + "\n").encode()


def fixture(root, algorithm):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
                                ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"))
    def store(kind, body):
        oid = identity(algorithm, kind, body)
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid
    blob = store("blob", b"unchanged repository bytes\n")
    tree = store("tree", b"100644 keep.txt\0" + bytes.fromhex(blob))
    base = store("commit", commit_body(tree, [], "base"))
    target = store("commit", commit_body(tree, [base], "target"))
    source = store("commit", commit_body(tree, [base], "source"))
    (root / TARGET).write_text(target + "\n")
    (root / SOURCE).write_text(source + "\n")
    data = dict(source_reference_hex=SOURCE.encode().hex(), target_reference_hex=TARGET.encode().hex(),
                source_tip=source, target_tip=target, title=TITLE, body=BODY)
    body = commit_body(tree, [target, source], "reviewed PR merge")
    return data, base, tree, body, identity(algorithm, "commit", body)


def candidate_bundle(algorithm, data, body, candidate):
    size = len(body)
    header = bytearray([(1 << 4) | (size & 15)])
    size >>= 4
    if size:
        header[0] |= 128
    while size:
        byte = size & 127
        size >>= 7
        header.append(byte | (128 if size else 0))
    pack = b"PACK" + struct.pack(">II", 2, 1) + header + zlib.compress(body)
    pack += hashlib.new(algorithm, pack).digest()
    preamble = "# v2 git bundle\n" if algorithm == "sha1" else "# v3 git bundle\n@object-format=sha256\n"
    return (preamble + f"-{data['target_tip']} target\n-{data['source_tip']} source\n"
            f"{candidate} {TARGET}\n\n").encode() + pack


def check_receipt(report, data, action, number, version, committed=True):
    require(report["type"] == "pull_request_publication" and report["schema_version"] == 1, "receipt schema")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "receipt scope")
    require(report["principal_id"] == PRINCIPAL, "receipt principal")
    require(report["pull_request"] == number and report["expected_version"] == version, "receipt version coordinates")
    require(report["action"] == action and report["data"] == data, "exact requested data")
    require(report["outcome"] == ("committed" if committed else "refused"), "terminal outcome")
    require(report["command_committed"] is committed and report["refs_changed"] is False, "effect classes")
    require(report["object_format"] == ("sha1" if len(data["source_tip"]) == 40 else "sha256"), "native format")
    require(type(report["decision_sequence"]) is int and report["decision_sequence"] > 0, "decision sequence")
    require(isinstance(report["tx_id"], str) and report["tx_id"], "nonempty transaction identity")
    require(report["delivery_acknowledged"] is None, "enqueue must not claim delivery acknowledgement")
    require(report["node_closed"] is True and report["cleanup_error"] is None, "node close")
    if committed:
        require(bool(report["repository_commit_id"]) and report["refusal_code"] is None and report["refusal_record_id"] is None, "committed receipt")
    else:
        require(report["repository_commit_id"] is None and bool(report["refusal_code"]) and bool(report["refusal_record_id"]), "refused receipt")


def check_view(view, data, number, version, state, candidate=None):
    require(view["number"] == number and view["version"] == version, "row identity/version")
    require(view["kind"] == "pull_request" and view["state"] == state, "row state")
    require(view["data"] == data, "complete metadata and exact byte preservation")
    require(view["opened_by"] == PRINCIPAL and view["last_metadata_actor"] == PRINCIPAL, "metadata actors")
    if candidate is None:
        require(view["merge"] is None, "unmerged row invented a merge")
    else:
        require(view["merge"]["commit"] == candidate, "native merged commit identity")
        require(view["merge"]["source_tip"] == data["source_tip"] and
                view["merge"]["target_tip_before"] == data["target_tip"], "merged parent coordinates")


def check_read(report, algorithm):
    require(report["schema_version"] == 1 and report["scope"] == "native_prs_and_merge_receipts", "read schema")
    require(report["repository_id"] == REPOSITORY and report["object_format"] == algorithm, "read scope")
    require(re.fullmatch(r"alg:[1-9][0-9]*:[0-9a-f]{32,128}", report["snapshot_token"]), "head token")
    require(isinstance(report["source_head"], str) and report["source_head"], "source head identity")
    require(report["tenant_id"] == TENANT, "read tenant")
    require(report["node_closed"] is True, "read close")


def invoke(binary, arguments, code=0, json_result=False):
    process = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, timeout=120)
    require(process.returncode == code, f"fg exit {process.returncode}, wanted {code}: {process.stderr!r}; {process.stdout!r}")
    if json_result:
        require(b"\x1b" not in process.stdout and "\u009b".encode() not in process.stdout and
                "\u202e".encode() not in process.stdout, "raw terminal-control text in JSON")
        return json.loads(process.stdout)
    return process.stdout


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-pr-cli-") as temporary:
        root = Path(temporary)
        node, source = root / "node", root / "source"
        data, base, tree, merge_body, candidate = fixture(source, algorithm)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "pr-fixture", source])
        refs = ["at", node, TENANT, REPOSITORY, "latest", "refs"]
        original_refs = invoke(binary, refs)
        before_reads = invoke(binary, ["at", node, TENANT, REPOSITORY, "latest"])
        def read(verb="list", number=None, extra=(), code=0):
            args = ["pr", verb, node, TENANT, REPOSITORY]
            if number is not None:
                args.append(str(number))
            args += ["--trusted-local", "--object-format", algorithm, *extra]
            result = invoke(binary, args, code, True)
            check_read(result, algorithm)
            return result
        def mutation_args(action, number, version, key, value):
            return ["pr", action, node, TENANT, REPOSITORY, number, "--trusted-local",
                    "--principal", PRINCIPAL, "--idempotency-key", key, "--expected-version", version,
                    "--source-ref-hex", value["source_reference_hex"], "--target-ref-hex", value["target_reference_hex"],
                    "--source-tip", value["source_tip"], "--target-tip", value["target_tip"],
                    "--title", value["title"], "--body", value["body"]]
        def mutate(action, number, version, key, value=data, committed=True):
            result = invoke(binary, mutation_args(action, number, version, key, value), 0 if committed else 3, True)
            check_receipt(result, value, action, number, version, committed)
            require(result["object_format"] == algorithm, "mutation native format")
            require(invoke(binary, refs) == original_refs, "PR metadata operation moved Git refs")
            return result
        empty = read()
        require(empty["count"] == 0 and empty["pull_requests"] == [] and empty["next_after"] is None and empty["has_more"] is False, "empty native page")
        missing = read("show", 7, code=4)
        require(missing["found"] is False and missing["pull_request"] is None, "missing show")
        require(invoke(binary, ["at", node, TENANT, REPOSITORY, "latest"]) == before_reads, "read changed canonical state")
        opened = mutate("open", 7, 0, "open-7")
        check_view(read("show", 7)["pull_request"], data, 7, 1, "open")
        require(mutate("open", 7, 0, "open-7") == opened, "opening retry changed its receipt")
        canonical = mutation_args("open", 7, 0, "open-7", data)
        canonical = [{"--source-tip": "--expected-source", "--target-tip": "--expected-target"}.get(value, value)
                     if isinstance(value, str) else value for value in canonical]
        require(invoke(binary, canonical, json_result=True) == opened, "tip aliases changed transaction identity")
        for number in [10, 2]:
            mutate("open", number, 0, f"open-{number}")
        first = read(extra=["--limit", "2"])
        require([row["number"] for row in first["pull_requests"]] == [2, 7], "numeric rather than lexical ordering")
        require(first["next_after"] == 7 and first["has_more"] is True, "bound continuation")
        second = read(extra=["--limit", "2", "--after", "7", "--expected-head", "head:" + first["snapshot_token"]])
        require(second == read(extra=["--limit", "2", "--after", "7", "--expected-head", first["snapshot_token"]]), "head token alias changed the pinned result")
        require([row["number"] for row in second["pull_requests"]] == [10] and second["next_after"] is None and second["has_more"] is False, "second page")
        require(read("show", 8, code=4)["pull_request"] is None, "show substituted the next higher PR")
        updated_data = dict(data, title="Changed exactly once")
        updated = mutate("update", 7, 1, "update-7", updated_data)
        stale_page = ["pr", "list", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm,
                      "--after", "7", "--expected-head", first["snapshot_token"]]
        require(not invoke(binary, stale_page, 2), "stale page returned a success report")
        check_view(read("show", 7)["pull_request"], updated_data, 7, 2, "open")
        stale = mutate("update", 7, 1, "stale-update", dict(data, title="Must not win"), False)
        require(stale["refusal_code"] == "EvidenceStale", "stale version refusal")
        require(mutate("update", 7, 1, "stale-update", dict(data, title="Must not win"), False) == stale, "refusal retry changed identity")
        changed_key = mutation_args("update", 7, 1, "update-7", dict(data, title="Key conflict"))
        require(not invoke(binary, changed_key, 2), "key reuse masqueraded as a terminal receipt")
        mutate("close", 7, 2, "close-7", updated_data)
        check_view(read("show", 7)["pull_request"], updated_data, 7, 3, "closed")
        require(mutate("open", 7, 0, "open-7") == opened, "old opening retry resurrected a closed PR")
        require(mutate("update", 7, 1, "update-7", updated_data) == updated, "old update retry changed identity")
        denied = mutate("update", 7, 3, "resurrection", updated_data, False)
        require(denied["refusal_code"] == "ProtectedRefTransitionDenied", "closed stream revived")
        for invalid in [mutation_args("open", 9, 0, "bad", data)[:-2],
                        mutation_args("open", 9, 0, "bad", data) + ["--expected-source", data["source_tip"]],
                        mutation_args("open", 9, 0, "bad", data) + ["--expected-target", "f" * len(data["target_tip"])],
                        mutation_args("open", 9, 0, "bad", data) + ["--force", "true"],
                        ["pr", "list", node, TENANT, REPOSITORY, "--trusted-local", "--after", "1"],
                        ["pr", "list", node, TENANT, REPOSITORY, "--trusted-local", "--limit", "101"]]:
            require(not invoke(binary, invalid, 2), "invalid request emitted successful JSON")
        mutate("open", 9, 0, "open-merge")
        bundle = root / "merge.bundle"
        bundle.write_bytes(candidate_bundle(algorithm, data, merge_body, candidate))
        merge_args = ["merge", "apply", node, TENANT, REPOSITORY, TARGET, bundle, "--trusted-local",
                      "--principal", PRINCIPAL, "--idempotency-key", "merge-9", "--source-ref", SOURCE,
                      "--expected-source", data["source_tip"], "--expected-target", data["target_tip"],
                      "--merge-base", base, "--expected-commit", candidate, "--pull-request", "9", "--expected-version", "1"]
        merged = invoke(binary, merge_args, json_result=True)
        require(merged["outcome"] == "committed", "merge publication failed")
        check_view(read("show", 9)["pull_request"], data, 9, 2, "merged", candidate)
        require(invoke(binary, merge_args, json_result=True) == merged, "merge retry duplicated publication")
        require(candidate.encode() in invoke(binary, refs), "target ref did not publish the candidate")
        print(json.dumps({"type": "pull_request_cli_smoke", "format": algorithm,
                          "native_execution": True, "result": "passed"}))


def self_test():
    rejected = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data, base, tree, body, candidate = fixture(root, algorithm)
            for file in root.glob("objects/*/*"):
                raw = zlib.decompress(file.read_bytes())
                framing, payload = raw.split(b"\0", 1)
                kind, size = framing.split(b" ")
                require(int(size) == len(payload), "loose fixture length")
                require(identity(algorithm, kind.decode(), payload) == file.parent.name + file.name, "loose fixture identity")
            bundle = candidate_bundle(algorithm, data, body, candidate)
            pack = bundle.split(b"\n\n", 1)[1]
            width = hashlib.new(algorithm).digest_size
            require(hashlib.new(algorithm, pack[:-width]).digest() == pack[-width:], "candidate pack checksum")
            require(body.startswith(f"tree {tree}\nparent {data['target_tip']}\nparent {data['source_tip']}\n".encode()), "ordered parent fixture")
            original = {"type": "pull_request_publication", "schema_version": 1, "tenant_id": TENANT, "object_format": algorithm,
                        "repository_id": REPOSITORY, "principal_id": PRINCIPAL, "pull_request": 7, "expected_version": 0,
                        "action": "open", "data": data, "outcome": "committed", "command_committed": True,
                        "refs_changed": False, "decision_sequence": 1, "tx_id": "fixture-only",
                        "delivery_acknowledged": None, "node_closed": True, "cleanup_error": None,
                        "repository_commit_id": "fixture-only", "refusal_code": None, "refusal_record_id": None}
            check_receipt(original, data, "open", 7, 0)
            for field, value in {"repository_id": "wrong", "principal_id": "wrong", "expected_version": 1,
                                 "action": "update", "data": dict(data, body="lost text"), "outcome": "refused",
                                 "command_committed": False, "refs_changed": True, "object_format": "wrong",
                                 "decision_sequence": 0, "tx_id": "", "delivery_acknowledged": True, "node_closed": False,
                                 "repository_commit_id": None, "refusal_record_id": "invented"}.items():
                damaged = copy.deepcopy(original)
                damaged[field] = value
                try:
                    check_receipt(damaged, data, "open", 7, 0)
                except AssertionError:
                    rejected += 1
                else:
                    raise AssertionError(f"checker missed damaged {field}")
    print(json.dumps({"type": "pr_fixture_checker_self_test", "rejected_corruptions": rejected,
                      "native_execution": False, "scope": "Python fixtures and checker only"}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fg", type=Path)
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    binary = args.fg.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "--fg must name an executable regular file")
    digest = hashlib.sha256()
    with binary.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    print(json.dumps({"type": "fg_binary", "path": str(binary), "sha256": digest.hexdigest()}))
    for algorithm in ["sha1", "sha256"]:
        run_format(binary, algorithm)


if __name__ == "__main__":
    main()
