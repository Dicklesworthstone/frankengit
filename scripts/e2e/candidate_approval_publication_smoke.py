#!/usr/bin/env python3
"""Exercise real candidate reviews and gated publication. Self-test checks helpers only."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zlib

TENANT, REPO, OPENER, SUBMITTER, PEER, OTHER = (f"{n:02x}" * 16 for n in range(1, 7))
TARGET, SOURCE = "refs/heads/main", "refs/heads/topic"


def require(value, message):
    if not value:
        raise AssertionError(message)


def oid(fmt, kind, body):
    return hashlib.new(fmt, f"{kind} {len(body)}\0".encode() + body).hexdigest()


def commit(tree, parents, message):
    return (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents)
            + "author Fixture <f@example.invalid> 1 +0000\ncommitter Fixture <f@example.invalid> 1 +0000\n\n").encode() + message


def pack(fmt, objects):
    data = bytearray(b"PACK\0\0\0\x02" + len(objects).to_bytes(4, "big"))
    for kind, body in objects:
        size = len(body)
        first = ({"commit": 1, "tree": 2, "blob": 3}[kind] << 4) | (size & 15)
        size >>= 4
        data.append(first | (128 if size else 0))
        while size:
            byte, size = size & 127, size >> 7
            data.append(byte | (128 if size else 0))
        data.extend(zlib.compress(body))
    data.extend(hashlib.new(fmt, data).digest())
    return bytes(data)


def fixture(path, fmt):
    (path / "refs/heads").mkdir(parents=True)
    (path / "HEAD").write_text(f"ref: {TARGET}\n")
    (path / "config").write_text("[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
                                 if fmt == "sha256" else "[core]\nrepositoryformatversion = 0\nbare = true\n")

    def store(kind, body):
        identity = oid(fmt, kind, body)
        dest = path / "objects" / identity[:2] / identity[2:]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return identity

    roots = []
    for text in (b"base\n", b"target\n", b"source\n"):
        blob = store("blob", text)
        roots.append(store("tree", b"100644 file\0" + bytes.fromhex(blob)))
    base = store("commit", commit(roots[0], [], b"base\n"))
    target = store("commit", commit(roots[1], [base], b"target\n"))
    source = store("commit", commit(roots[2], [base], b"source\n"))
    (path / TARGET).write_text(target + "\n")
    (path / SOURCE).write_text(source + "\n")
    manual = b"manual resolution absent from either parent\n"
    tree = b"100644 file\0" + bytes.fromhex(oid(fmt, "blob", manual))
    body = commit(oid(fmt, "tree", tree), [target, source], b"review this actual candidate\n")
    candidate = oid(fmt, "commit", body)
    header = b"# v2 git bundle\n" if fmt == "sha1" else b"# v3 git bundle\n@object-format=sha256\n"
    bundle = header + f"-{target} target\n-{source} source\n{candidate} {TARGET}\n\n".encode() + pack(fmt, [("blob", manual), ("tree", tree), ("commit", body)])
    return dict(source_tip=source, target_tip=target, merge_base=base, candidate_commit=candidate,
                policy_epoch=1, pull_request_version=1), bundle


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key {key}")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def check_terminal(row, history, kind, status, principal, decision=None, version=None, reviewers=()):
    require(row["schema_version"] == 1 and row["type"] == kind, "receipt type")
    profile = "exact-merge-candidate-v1" if kind == "candidate_review_decision" else "named-candidate-reviewers-v1"
    require(row["profile"] == profile, "profile")
    require(row["tenant_id"] == TENANT and row["repository_id"] == REPO and row["pull_request"] == 1, "scope")
    for key in ("source_tip", "target_tip", "merge_base", "candidate_commit", "policy_epoch", "pull_request_version"):
        require(row[key] == history[key], f"changed {key}")
    require(row["source_reference_hex"] == SOURCE.encode().hex() and row["target_reference_hex"] == TARGET.encode().hex(), "refs")
    require(row["principal"] == principal and row["decision"] == decision and row["expected_review_version"] == version, "actor/decision")
    require(row["required_reviewers"] == sorted(reviewers), "required reviewers")
    require(row["outcome"] == status and row["published_to_repository"] is (status == "committed"), "terminal state")
    require(row["git_refs_changed"] is (status == "committed" and kind == "reviewed_merge_publication"), "ref effect")
    require(row["node_closed"] is True and row["cleanup_error"] is None, "cleanup")
    require(type(row["decision_sequence"]) is int and row["decision_sequence"] > 0 and row["tx_id"], "terminal identity")
    require(bool(row["repository_commit_id"]) == (status == "committed"), "commit evidence")
    require(bool(row["refusal_record_id"]) == (status == "refused") and bool(row["refusal_code"]) == (status == "refused"), "refusal evidence")
    require(row["delivery_acknowledged"] is None and row["repository_wide_branch_protection"] is False, "overclaimed assurance")


def run_fg(binary, args, code=0, report=True):
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, timeout=180)
    require(result.returncode == code, f"exit {result.returncode}, wanted {code}: {result.stderr!r}; {result.stdout!r}")
    return strict_json(result.stdout) if report else result.stdout


def common(node, history):
    return [node, TENANT, REPO, "1", "--trusted-local", "--expected-version", str(history["pull_request_version"]),
            "--source-ref", SOURCE, "--target-ref", TARGET, "--source-tip", history["source_tip"],
            "--target-tip", history["target_tip"], "--merge-base", history["merge_base"],
            "--candidate", history["candidate_commit"], "--policy-epoch", str(history["policy_epoch"])]


def scenario(binary, fmt):
    with tempfile.TemporaryDirectory(prefix=f"fg-review-{fmt}-") as temp:
        root = Path(temp)
        history, bundle = fixture(root / "source", fmt)
        artifact = root / "candidate.bundle"
        artifact.write_bytes(bundle)
        node = root / "node"
        run_fg(binary, ["init", node, TENANT, REPO, fmt], report=False)
        run_fg(binary, ["import", node, TENANT, REPO, OPENER, "review-import", root / "source"], report=False)
        ref_args = ["at", node, TENANT, REPO, "latest", "refs"]
        before = run_fg(binary, ref_args, report=False)
        opened = run_fg(binary, ["pr", "open", node, TENANT, REPO, "1", "--trusted-local", "--principal", OPENER,
                      "--idempotency-key", "open", "--expected-version", "0", "--source-ref", SOURCE,
                      "--target-ref", TARGET, "--source-tip", history["source_tip"], "--target-tip", history["target_tip"],
                      "--title", "Review manual resolution", "--body", "Exact candidate required"])
        require(opened["outcome"] == "committed", "PR opening")
        read_args = ["pr", "reviews", node, TENANT, REPO, "1", "--trusted-local", "--object-format", fmt]
        empty = run_fg(binary, read_args)
        require(empty["reviews"] == [] and empty["complete"] is True, "empty reviewer set")
        history["policy_epoch"] = empty["policy_epoch"]

        def vote(peer, key, version=0, decision="approve", code=0):
            args = ["pr", "review", *common(node, history), "--principal", peer, "--idempotency-key", key,
                    "--review-version", str(version), "--decision", decision, "--reason", "Exact bytes reviewed"]
            if decision != "withdraw":
                args.extend(["--bundle", artifact])
            row = run_fg(binary, args, code)
            check_terminal(row, history, "candidate_review_decision", "committed" if code == 0 else "refused", peer, decision, version)
            return row

        def merge(key, reviewers, code=0):
            args = ["merge", "apply-reviewed", *common(node, history), "--principal", SUBMITTER,
                    "--idempotency-key", key, "--bundle", artifact]
            for peer in reviewers:
                args.extend(["--require-reviewer", peer])
            row = run_fg(binary, args, code)
            check_terminal(row, history, "reviewed_merge_publication", "committed" if code == 0 else "refused", SUBMITTER, reviewers=reviewers)
            return row

        missing = merge("missing", [PEER], 3)
        require(missing["refusal_code"] == "EvidenceMissing", "missing review did not refuse")
        approved = vote(PEER, "approve")
        require(vote(PEER, "approve") == approved, "review retry changed result")
        first_head = run_fg(binary, read_args)["snapshot_token"]
        vote(OTHER, "approve-other")
        run_fg(binary, read_args + ["--after", PEER, "--expected-head", first_head], 2, False)
        first = run_fg(binary, read_args + ["--limit", "1"])
        require(first["next_after"] == PEER and first["complete"] is False and first["page_complete"] is True, "review page truncation")
        second = run_fg(binary, read_args + ["--limit", "1", "--after", PEER, "--expected-head", first["snapshot_token"]])
        require(second["next_after"] is None and second["reviews"][0]["reviewer"] == OTHER, "pinned reviewer continuation")
        require(first["reviews"][0]["candidate_commit"] == history["candidate_commit"], "source-only masqueraded as candidate review")
        vote(PEER, "withdraw", 1, "withdraw")
        blocked = merge("withdrawn", [PEER, OTHER], 3)
        require(blocked["refusal_code"] == "ProtectedRefTransitionDenied", "withdrawal did not block")
        vote(PEER, "approve-again", 2)
        require(merge("missing", [PEER], 3) == missing, "later vote rewrote old refusal")
        require(run_fg(binary, ref_args, report=False) == before, "review/refusal changed Git refs")
        published = merge("publish", [PEER, OTHER])
        require(history["candidate_commit"].encode() in run_fg(binary, ref_args, report=False), "candidate not published")
        require(merge("publish", [PEER, OTHER]) == published, "publication retry changed result")
        require(vote(PEER, "approve") == approved, "historical vote recovery failed after merge")
        vote(PEER, "withdraw-after-merge", 3, "withdraw")
        require(merge("publish", [PEER, OTHER]) == published, "withdrawal erased known committed merge")
        require(artifact.read_bytes() == bundle, "review/apply rewrote artifact")
        print(json.dumps({"type": "candidate_approval_publication_smoke", "format": fmt, "result": "passed", "candidate": history["candidate_commit"]}))


def self_test():
    rejected = 0
    for fmt in ("sha1", "sha256"):
        with tempfile.TemporaryDirectory() as temp:
            history, bundle = fixture(Path(temp), fmt)
            packed = bundle.split(b"\n\n", 1)[1]
            width = hashlib.new(fmt).digest_size
            require(hashlib.new(fmt, packed[:-width]).digest() == packed[-width:], "fixture pack checksum")
            candidate_path = Path(temp) / "objects" / history["candidate_commit"][:2] / history["candidate_commit"][2:]
            require(not candidate_path.exists(), "candidate must not already be imported")
            row = dict(schema_version=1, type="candidate_review_decision", profile="exact-merge-candidate-v1", tenant_id=TENANT,
                       repository_id=REPO, pull_request=1, **history, source_reference_hex=SOURCE.encode().hex(),
                       target_reference_hex=TARGET.encode().hex(), principal=PEER, decision="approve", expected_review_version=0,
                       required_reviewers=[], outcome="committed", published_to_repository=True, git_refs_changed=False,
                       node_closed=True, cleanup_error=None, decision_sequence=3, tx_id="test-tx", repository_commit_id="test-rcr",
                       refusal_code=None, refusal_record_id=None, delivery_acknowledged=None, repository_wide_branch_protection=False)
            check_terminal(row, history, "candidate_review_decision", "committed", PEER, "approve", 0)
            for key, value in [("candidate_commit", history["source_tip"]), ("policy_epoch", 99), ("principal", OPENER),
                ("type", "reviewed_merge_publication"), ("decision", "withdraw"), ("git_refs_changed", True),
                ("node_closed", False), ("decision_sequence", True), ("required_reviewers", [PEER]),
                ("repository_commit_id", None), ("refusal_code", "EvidenceMissing"), ("repository_wide_branch_protection", True)]:
                broken = copy.deepcopy(row)
                broken[key] = value
                try:
                    check_terminal(broken, history, "candidate_review_decision", "committed", PEER, "approve", 0)
                except (AssertionError, KeyError):
                    rejected += 1
                else:
                    raise AssertionError(f"checker missed altered {key}")
    for text in ('{"a":1,"a":2}', '{"a":NaN}'):
        try:
            strict_json(text)
        except (AssertionError, ValueError):
            rejected += 1
        else:
            raise AssertionError("invalid JSON accepted")
    print(f"fixture/checker self-test passed ({rejected} rejected inputs); Rust and fg were not executed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if args.fg is None:
        parser.error("--fg is required for real integration; missing evidence is not success")
    binary = args.fg.resolve(strict=True)
    require(binary.is_file() and os.access(binary, os.X_OK), "fg must be executable")
    print(json.dumps({"type": "binary_under_test", "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
    for fmt in ("sha1", "sha256"):
        scenario(binary, fmt)


if __name__ == "__main__":
    main()
