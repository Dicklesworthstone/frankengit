#!/usr/bin/env python3
"""Fresh-process fg pr lifecycle/merge campaign; self-test checks fixtures/checkers only."""
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
TARGET, SOURCE = "refs/heads/main", "refs/heads/topic"
BODY = 'Untrusted <script> and "quotes"\\\nUnicode: é\nControls: \x1b\u009b\t\u2028\n'
TITLE = "Native PR: exact bytes"


def require(value, message):
    if not value:
        raise AssertionError(message)


def identity(algorithm, kind, body):
    return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def commit(tree, parents, message):
    text = f"tree {tree}\n" + "".join(f"parent {parent}\n" for parent in parents)
    return (text + "author Test <test@example.invalid> 1 +0000\n"
            "committer Test <test@example.invalid> 1 +0000\n\n" + message + "\n").encode()


def fixture(root, algorithm):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n", encoding="utf-8")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
                                ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"), encoding="utf-8")
    def store(kind, body):
        oid = identity(algorithm, kind, body)
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid
    blob = store("blob", b"unchanged source content\n")
    tree = store("tree", b"100644 preserved.txt\0" + bytes.fromhex(blob))
    base = store("commit", commit(tree, [], "base"))
    target = store("commit", commit(tree, [base], "target"))
    source = store("commit", commit(tree, [base], "source"))
    (root / TARGET).write_text(target + "\n", encoding="ascii")
    (root / SOURCE).write_text(source + "\n", encoding="ascii")
    body = commit(tree, [target, source], "independently reviewed merge")
    candidate = identity(algorithm, "commit", body)
    size = len(body)
    header = bytearray([(1 << 4) | (size & 15)])
    size >>= 4
    while size:
        header[-1] |= 128
        header.append(size & 127)
        size >>= 7
    pack = b"PACK" + struct.pack(">II", 2, 1) + bytes(header) + zlib.compress(body)
    pack += hashlib.new(algorithm, pack).digest()
    envelope = b"# v2 git bundle\n" if algorithm == "sha1" else b"# v3 git bundle\n@object-format=sha256\n"
    bundle = envelope + f"-{target} target\n-{source} source\n{candidate} {TARGET}\n\n".encode() + pack
    return dict(blob=blob, tree=tree, base=base, target=target, source=source,
                candidate=candidate, candidate_body=body, bundle=bundle)


def data_for(f, title=TITLE, body=BODY, target=None):
    return dict(source_reference_hex=SOURCE.encode().hex(), target_reference_hex=TARGET.encode().hex(),
                source_tip=f["source"], target_tip=target or f["target"], title=title, body=body)


def publication(report, algorithm, number, action, version, data, committed=True, code=None):
    require(report["type"] == "pull_request_publication" and report["schema_version"] == 1, "publication schema")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "repository binding")
    require(report["principal_id"] == PRINCIPAL and report["object_format"] == algorithm, "principal/domain binding")
    require(type(report["pull_request"]) is int and report["pull_request"] == number, "PR number")
    require(type(report["expected_version"]) is int and report["expected_version"] == version, "expected version")
    require(report["action"] == action and report["data"] == data, "exact submitted metadata")
    require(report["command_committed"] is committed, "committed flag")
    require(report["outcome"] == ("committed" if committed else "refused"), "terminal outcome")
    require(report["refs_changed"] is False and report["delivery_acknowledged"] is None, "effect/acknowledgement claims")
    require(report["node_closed"] is True and report["cleanup_error"] is None, "explicit close")
    require(type(report["decision_sequence"]) is int and report["decision_sequence"] > 0, "decision position")
    require(isinstance(report["tx_id"], str) and report["tx_id"].startswith("frankengit/ref-txn/v2/"), "transaction identity")
    if committed:
        require(isinstance(report["repository_commit_id"], str) and report["repository_commit_id"].startswith("frankengit/rcr/v1/"), "committed record")
        require(report["refusal_code"] is None and report["refusal_record_id"] is None, "spurious refusal")
    else:
        require(report["repository_commit_id"] is None and report["refusal_code"] == code, "canonical refusal")
        require(isinstance(report["refusal_record_id"], str) and report["refusal_record_id"].startswith("frankengit/refusal-record/v1/"), "refusal record")


def read_header(report, algorithm):
    require(report["schema_version"] == 1 and report["scope"] == "native_prs_and_merge_receipts", "read schema/scope")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "read repository")
    require(report["object_format"] == algorithm and report["node_closed"] is True, "read domain/close")
    require(isinstance(report["source_head"], str) and report["source_head"].startswith("frankengit/authority-head/v1/"), "source head")
    require(re.fullmatch(r"alg:[1-9][0-9]*:(?:[0-9a-f]{2}){1,64}", report["snapshot_token"]) is not None, "snapshot token")


def page(report, algorithm, numbers, after=0, limit=50, next_after=None, head=None):
    read_header(report, algorithm)
    require(report["type"] == "pull_request_page", "page type")
    require(type(report["after"]) is int and report["after"] == after, "page after")
    require(type(report["limit"]) is int and report["limit"] == limit, "page limit")
    require(type(report["count"]) is int and report["count"] == len(numbers), "page count")
    require(report["has_more"] is (next_after is not None) and report["next_after"] == next_after, "page continuation")
    require(len(report["pull_requests"]) == len(numbers), "page row count")
    require([row["number"] for row in report["pull_requests"]] == numbers, "numeric page order")
    require(all(type(row["number"]) is int for row in report["pull_requests"]), "numeric row identity")
    if head is not None:
        require(report["source_head"] == head, "mixed read heads")


def row(actual, number, version, state, data, merged=None):
    require(type(actual["number"]) is int and actual["number"] == number, "row number")
    require(type(actual["version"]) is int and actual["version"] == version, "row version")
    require(actual["kind"] == "pull_request" and actual["state"] == state, "row kind/state")
    require(actual["last_action"] == ("merge" if state == "merged" else "close" if state == "closed" else "open" if version == 1 else "update"), "last transition")
    require(actual["data"] == data and actual["opened_by"] == PRINCIPAL, "preserved metadata/opener")
    require(actual["last_metadata_actor"] == PRINCIPAL and actual["merge"] == merged, "actor/merge attribution")


def invoke(binary, arguments, code=0):
    result = subprocess.run([str(binary), *map(str, arguments)], capture_output=True, timeout=120)
    require(result.returncode == code, f"fg exit {result.returncode}, wanted {code}: {result.stderr!r}; {result.stdout!r}")
    return result


def document(result):
    text = result.stdout.decode("utf-8", errors="strict")
    require(text.endswith("\n") and text.count("\n") == 1, "exactly one JSON line required")
    require(not any(ord(c) < 32 or 127 <= ord(c) <= 159 or c in "\u2028\u2029" for c in text[:-1]), "raw control bytes in JSON")
    def pairs(entries):
        out = {}
        for key, value in entries:
            require(key not in out, f"duplicate JSON key {key}")
            out[key] = value
        return out
    return json.loads(text, object_pairs_hook=pairs)


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-pr-cli-") as temporary:
        root = Path(temporary)
        node, source = root / "node", root / "source"
        f = fixture(source, algorithm)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "native-pr-fixture", source])
        refs_args = ["at", node, TENANT, REPOSITORY, "latest", "refs"]
        refs_before = invoke(binary, refs_args).stdout
        require(f["target"].encode() in refs_before and f["source"].encode() in refs_before, "fixture canonical refs")
        def read_args(action, *extra):
            return ["pr", action, node, TENANT, REPOSITORY, *extra, "--trusted-local", "--object-format", algorithm]
        def listing(*extra):
            return document(invoke(binary, read_args("list", *extra)))
        def showing(number, code=0):
            report = document(invoke(binary, read_args("show", number), code))
            read_header(report, algorithm)
            require(report["type"] == "pull_request" and report["requested_number"] == number, "exact lookup identity")
            require(report["found"] is (code == 0), "exact lookup found")
            return report
        def mutation_args(action, number, version, key, data, body_file=None):
            out = ["pr", action, node, TENANT, REPOSITORY, str(number), "--trusted-local", "--principal", PRINCIPAL,
                   "--idempotency-key", key, "--expected-version", str(version),
                   "--source-ref-hex", data["source_reference_hex"], "--target-ref-hex", data["target_reference_hex"],
                   "--expected-source", data["source_tip"], "--expected-target", data["target_tip"], "--title", data["title"],
                   "--object-format", algorithm]
            return out + (["--body-file", body_file] if body_file is not None else ["--body", data["body"]])
        def mutate(action, number, version, key, data, code=None, body_file=None):
            report = document(invoke(binary, mutation_args(action, number, version, key, data, body_file), 3 if code else 0))
            publication(report, algorithm, number, action, version, data, code is None, code)
            return report
        page(listing(), algorithm, [])
        require(showing(7, 4)["pull_request"] is None, "initial absent PR")
        original = data_for(f)
        opening = mutate("open", 7, 0, "pr-open-7", original)
        row(showing(7)["pull_request"], 7, 1, "open", original)
        missing = showing(6, 4)
        require(missing["pull_request"] is None and "next_after" not in missing, "not-found disclosed another PR")
        pinned = listing()
        require(mutate("open", 7, 0, "pr-open-7", original) == opening, "opening retry changed identity")
        require(listing() == pinned, "opening retry published again")
        updated = data_for(f, "Reviewed updated title", BODY + "second revision\n")
        body_path = root / "body.md"
        body_path.write_bytes(updated["body"].encode())
        updating = mutate("update", 7, 1, "pr-update-7", updated, body_file=body_path)
        row(showing(7)["pull_request"], 7, 2, "open", updated)
        require(mutate("update", 7, 1, "pr-update-7", updated) == updating, "file/inline transport changed seal")
        loser = data_for(f, "Stale competitor", BODY)
        refused = mutate("update", 7, 1, "pr-loser", loser, "EvidenceStale")
        pinned = listing()
        require(mutate("update", 7, 1, "pr-loser", loser, "EvidenceStale") == refused, "refusal retry changed")
        require(listing() == pinned, "refusal retry advanced the head")
        require(not invoke(binary, mutation_args("update", 7, 1, "pr-update-7", loser), 2).stdout, "reused-key error printed success")
        require(listing() == pinned, "reused-key mismatch changed canonical state")
        for number in [10, 2]:
            mutate("open", number, 0, f"pr-open-{number}", original)
        first = listing("--limit", 2)
        page(first, algorithm, [2, 7], limit=2, next_after=7)
        second = listing("--limit", 2, "--after", 7, "--expected-head", first["snapshot_token"])
        page(second, algorithm, [10], after=7, limit=2, head=first["source_head"])
        page(listing("--limit", 3), algorithm, [2, 7, 10], limit=3)
        page(listing("--after", 10, "--expected-head", first["snapshot_token"]), algorithm, [], after=10, head=first["source_head"])
        mutate("open", 3, 0, "pr-open-3", original)
        require(not invoke(binary, read_args("list", "--after", 7, "--expected-head", first["snapshot_token"]), 2).stdout, "stale pin disclosed a mixed page")
        closing = mutate("close", 7, 2, "pr-close-7", updated)
        row(showing(7)["pull_request"], 7, 3, "closed", updated)
        mutate("update", 7, 3, "pr-resurrection", updated, "ProtectedRefTransitionDenied")
        require(invoke(binary, refs_args).stdout == refs_before, "PR metadata changed canonical code refs")

        # A reviewed independently encoded native candidate exercises the
        # existing merge command against both a closed and an active PR.
        bundle = root / "candidate.bundle"
        bundle.write_bytes(f["bundle"])
        def merge_args(number, version, key):
            return ["merge", "apply", node, TENANT, REPOSITORY, TARGET, bundle, "--trusted-local",
                    "--principal", PRINCIPAL, "--idempotency-key", key, "--source-ref", SOURCE,
                    "--expected-source", f["source"], "--expected-target", f["target"],
                    "--merge-base", f["base"], "--expected-commit", f["candidate"],
                    "--pull-request", number, "--expected-version", version]
        rejected = document(invoke(binary, merge_args(7, 3, "closed-pr-merge"), 2))
        require(rejected["outcome"] == "refused" and rejected["refusal_code"] == "ProtectedRefTransitionDenied", "closed PR authorized merge")
        require(invoke(binary, refs_args).stdout == refs_before, "refused merge changed refs")
        merged = document(invoke(binary, merge_args(2, 1, "active-pr-merge")))
        require(merged["outcome"] == "committed" and merged["candidate_commit"] == f["candidate"], "active PR merge")
        merge_data = dict(source_reference_hex=SOURCE.encode().hex(), target_reference_hex=TARGET.encode().hex(),
                          source_tip=f["source"], target_tip_before=f["target"], base_tip=f["base"], commit=f["candidate"])
        row(showing(2)["pull_request"], 2, 2, "merged", original, merge_data)
        refs_after = invoke(binary, refs_args).stdout
        require(refs_after == refs_before.replace(f["target"].encode(), f["candidate"].encode()), "merge changed unrelated refs")
        pinned = listing()
        for action, version, key, data, expected in [
            ("open", 0, "pr-open-7", original, opening), ("update", 1, "pr-update-7", updated, updating),
            ("close", 2, "pr-close-7", updated, closing)]:
            require(mutate(action, 7, version, key, data) == expected, "historical retry changed outcome")
        require(listing() == pinned, "historical retry republished after merge")
        mutate("update", 2, 2, "after-merge-update", original, "ProtectedRefTransitionDenied")
        mutate("open", 4, 0, "stale-tip-open", original, "TargetRefMoved")

        # Rejections must not print partial JSON or create canonical decisions.
        current = data_for(f, target=f["candidate"])
        valid = mutation_args("open", 30, 0, "parse-negative", current)
        no_trust = valid.copy(); no_trust.remove("--trusted-local")
        no_body = valid[:-2]
        negatives = [no_trust, no_body, valid + ["--expected-version", "0"], valid + ["--force", "true"],
                     valid + ["--body-file", body_path], read_args("list", "--limit", 0),
                     read_args("list", "--after", 1), read_args("show", 7, "--limit", 1),
                     read_args("list", "--principal", PRINCIPAL)]
        for payload in [b"\xff", b"\0", b"x" * 65537]:
            path = root / f"invalid-{len(negatives)}"
            path.write_bytes(payload)
            negatives.append(mutation_args("open", 30, 0, "parse-negative", current, path))
        pinned = listing()
        for arguments in negatives:
            require(not invoke(binary, arguments, 2).stdout, "invalid request masqueraded as completed PR JSON")
        require(listing() == pinned, "invalid requests changed the selected head")

        output_fault = False
        if Path("/dev/full").exists():
            fault_args = mutation_args("open", 20, 0, "output-fault", current)
            with open("/dev/full", "wb") as full:
                failed = subprocess.run([str(binary), *map(str, fault_args)], stdout=full, stderr=subprocess.PIPE, timeout=120)
            require(failed.returncode == 2 and b"is committed" in failed.stderr, "output failure erased known commit")
            pinned = listing()
            recovered = mutate("open", 20, 0, "output-fault", current)
            row(showing(20)["pull_request"], 20, 1, "open", current)
            require(listing() == pinned, "output-failure recovery duplicated publication")
            require(recovered["command_committed"] is True, "output-failure recovery")
            output_fault = True
        require(invoke(binary, refs_args).stdout == refs_after, "post-merge metadata changed code refs")
        print(json.dumps(dict(type="pull_request_smoke", format=algorithm, passed=True, rust_executed=True,
                              malformed_requests=len(negatives), output_failure_exercised=output_fault,
                              fresh_processes=True, merge_integration=True)))


def self_test():
    negatives = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); f = fixture(root, algorithm)
            for path in root.glob("objects/*/*"):
                raw = zlib.decompress(path.read_bytes()); header, body = raw.split(b"\0", 1)
                kind, count = header.split(b" ", 1)
                require(int(count) == len(body), "loose framing")
                require(identity(algorithm, kind.decode(), body) == path.parent.name + path.name, "loose identity")
            pack = f["bundle"].split(b"\n\n", 1)[1]; width = hashlib.new(algorithm).digest_size
            require(hashlib.new(algorithm, pack[:-width]).digest() == pack[-width:], "pack checksum")
            require(pack[:12] == b"PACK" + struct.pack(">II", 2, 1), "pack count/version")
            at = 12; first = pack[at]; at += 1; size = first & 15; shift = 4; current = first
            require((first >> 4) & 7 == 1, "pack object kind")
            while current & 128:
                current = pack[at]; at += 1; size |= (current & 127) << shift; shift += 7
            decoder = zlib.decompressobj(); body = decoder.decompress(pack[at:-width]) + decoder.flush()
            require(decoder.eof and not decoder.unused_data and size == len(body), "pack object length")
            require(body == f["candidate_body"] and identity(algorithm, "commit", body) == f["candidate"], "candidate identity")
            data = data_for(f)
            sample = dict(type="pull_request_publication", schema_version=1, action="open", outcome="committed",
                          command_committed=True, tx_id="frankengit/ref-txn/v2/synthetic", decision_sequence=1,
                          repository_commit_id="frankengit/rcr/v1/synthetic", refusal_code=None, refusal_record_id=None,
                          tenant_id=TENANT, repository_id=REPOSITORY, principal_id=PRINCIPAL, object_format=algorithm,
                          pull_request=7, expected_version=0, data=data, refs_changed=False, delivery_acknowledged=None,
                          node_closed=True, cleanup_error=None)
            publication(sample, algorithm, 7, "open", 0, data)
            corruptions = [("command_committed", False), ("outcome", "refused"), ("repository_id", "wrong"),
                           ("principal_id", "wrong"), ("object_format", "wrong"), ("expected_version", 1),
                           ("pull_request", 8), ("action", "close"), ("refs_changed", True),
                           ("delivery_acknowledged", True), ("node_closed", False), ("cleanup_error", "lost"),
                           ("decision_sequence", True), ("tx_id", ""), ("repository_commit_id", None),
                           ("refusal_code", "EvidenceStale"), ("data", data_for(f, "wrong"))]
            for field, value in corruptions:
                bad = copy.deepcopy(sample); bad[field] = value
                try:
                    publication(bad, algorithm, 7, "open", 0, data)
                except (AssertionError, KeyError, TypeError):
                    negatives += 1
                else:
                    raise AssertionError(f"checker accepted damaged {field}")
            sample_row = dict(number=7, version=1, kind="pull_request", state="open", last_action="open",
                              data=data, opened_by=PRINCIPAL, last_metadata_actor=PRINCIPAL, merge=None)
            sample_page = dict(type="pull_request_page", schema_version=1, scope="native_prs_and_merge_receipts",
                               tenant_id=TENANT, repository_id=REPOSITORY, object_format=algorithm,
                               source_head="frankengit/authority-head/v1/synthetic", snapshot_token="alg:1:" + "ab" * 32,
                               node_closed=True, after=0, limit=50, count=1, has_more=False, next_after=None,
                               pull_requests=[sample_row])
            page(sample_page, algorithm, [7]); row(sample_row, 7, 1, "open", data)
            for field, value in [("source_head", ""), ("snapshot_token", "bad"), ("count", 0),
                                 ("node_closed", False), ("has_more", True), ("next_after", 7),
                                 ("after", 1), ("pull_requests", [])]:
                bad = copy.deepcopy(sample_page); bad[field] = value
                try:
                    page(bad, algorithm, [7])
                except (AssertionError, KeyError, TypeError):
                    negatives += 1
                else:
                    raise AssertionError(f"checker accepted damaged page {field}")
            for field, value in [("version", 2), ("opened_by", None), ("last_action", "update"),
                                 ("data", data_for(f, "wrong")), ("merge", {}), ("kind", "merge_receipt")]:
                bad = copy.deepcopy(sample_row); bad[field] = value
                try:
                    row(bad, 7, 1, "open", data)
                except (AssertionError, KeyError, TypeError):
                    negatives += 1
                else:
                    raise AssertionError(f"checker accepted damaged row {field}")
            raw = (json.dumps(sample, ensure_ascii=True) + "\n").encode()
            require(document(subprocess.CompletedProcess([], 0, raw, b"")) == sample, "JSON decoder fixture")
            for bad in [b'{"a":1,"a":2}\n', b'{}\n{}\n', b'{"text":"\x1b"}\n']:
                try:
                    document(subprocess.CompletedProcess([], 0, bad, b""))
                except (AssertionError, json.JSONDecodeError):
                    negatives += 1
                else:
                    raise AssertionError("checker accepted malformed JSON framing")
    print(json.dumps(dict(type="pull_request_checker_self_test", checker_passed=True,
                          damaged_reports_rejected=negatives, rust_executed=False,
                          native_campaign_executed=False, synthetic_checker_inputs=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fg", type=Path)
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    binary = args.fg.resolve()
    require(binary.is_file() and os.access(binary, os.X_OK), "an executable built fg is required; no skipped success")
    with binary.open("rb") as executable:
        fingerprint = hashlib.file_digest(executable, "sha256").hexdigest()
    print(json.dumps(dict(type="binary_identity", sha256=fingerprint)))
    for algorithm in ["sha1", "sha256"]:
        run_format(binary, algorithm)


if __name__ == "__main__":
    main()
