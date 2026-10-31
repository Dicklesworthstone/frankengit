#!/usr/bin/env python3
"""Fresh-process queue lifecycle against fg's real file-backed authority.

Git fixture objects use Python's standard library. No Git subprocess, batch
submission, or speculative-landing claim. Each command's output is retained.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time
import zlib

from pull_request_smoke import (
    PRINCIPAL, REPOSITORY, SOURCE, TARGET, TENANT,
    commit, document, fixture, identity, require,
)


class Campaign:
    def __init__(self, binary, root, algorithm):
        self.binary, self.root, self.algorithm = binary, root, algorithm
        self.node, self.incarnation, self.calls = root / "node", None, 0
        self.evidence = root / "commands"
        self.evidence.mkdir(parents=True)

    def run(self, arguments, expected=0):
        self.calls += 1
        args = [str(self.binary), *map(str, arguments)]
        start = time.monotonic()
        result = subprocess.run(args, capture_output=True, timeout=120)
        stem = f"{self.calls:03d}"
        (self.evidence / f"{stem}.stdout").write_bytes(result.stdout)
        (self.evidence / f"{stem}.stderr").write_bytes(result.stderr)
        with (self.root / "commands.jsonl").open("a", encoding="utf-8") as log:
            log.write(json.dumps(dict(
                command=args, expected_exit=expected, actual_exit=result.returncode,
                elapsed_seconds=round(time.monotonic() - start, 6),
                stdout=f"commands/{stem}.stdout", stderr=f"commands/{stem}.stderr",
            ), sort_keys=True) + "\n")
        require(result.returncode == expected,
                f"command {stem}: fg exit {result.returncode}, wanted {expected}; "
                f"{result.stderr!r}; {result.stdout!r}")
        return result

    def queue_args(self, action, number=None, *extra):
        args = ["queue", action, self.node, TENANT, REPOSITORY]
        if number is not None:
            args.append(number)
        args += ["--trusted-local", "--object-format", self.algorithm]
        if self.incarnation is not None:
            args += ["--expected-incarnation", self.incarnation]
        return args + list(extra)

    def show(self, number, expected=0, token=None):
        args = self.queue_args("show", number)
        if token is not None:
            args += ["--expected-head", token]
        report = document(self.run(args, expected))
        self.header(report)
        require(report["type"] == "merge_queue" and report["number"] == number, "exact queue lookup")
        require(report["found"] is (expected == 0), "queue presence")
        return report

    def header(self, report):
        require(report["schema_version"] == 1, "queue schema")
        require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "repository scope")
        require(report["object_format"] == self.algorithm and report["node_closed"] is True, "domain/close")
        if self.incarnation is not None:
            require(report["repository_incarnation"] == self.incarnation, "queue incarnation")

    def mutation_args(self, action, queue, version, key, extra):
        return self.queue_args(action, queue, "--principal", PRINCIPAL,
                               "--idempotency-key", key, "--expected-version", version,
                               "--target-ref", TARGET, *extra)

    def mutate(self, action, queue, version, key, extra, code=None):
        report = document(self.run(self.mutation_args(action, queue, version, key, extra), 0 if code is None else 3))
        self.header(report)
        require(report["type"] == "merge_queue_publication", "publication schema")
        require(report["number"] == queue and report["expected_version"] == version, "publication predecessor")
        require(report["principal_id"] == PRINCIPAL and report["target_ref"] == TARGET, "actor/target")
        require(report["proposed_action"]["name"] == action, "publication action")
        require(report["committed"] is (code is None), "terminal commit flag")
        require(report["outcome"] == ("committed" if code is None else "refused"), "terminal outcome")
        require(report["refusal_code"] == code and report["refs_changed"] is False, "refusal/metadata-only effect")
        require(report["cleanup_error"] is None, "explicit cleanup")
        require(type(report["decision_sequence"]) is int and report["decision_sequence"] > 0, "decision sequence")
        return report

    def pull(self, action, number, version, source_ref, source_tip, target_tip, key):
        report = document(self.run([
            "pr", action, self.node, TENANT, REPOSITORY, number, "--trusted-local",
            "--object-format", self.algorithm, "--principal", PRINCIPAL,
            "--idempotency-key", key, "--expected-version", version,
            "--source-ref", source_ref, "--target-ref", TARGET,
            "--expected-source", source_tip, "--expected-target", target_tip,
            "--title", f"Queue PR {number} {key}", "--body", "Native queue lifecycle é",
        ]))
        require(report["command_committed"] is True and report["refs_changed"] is False, "PR metadata publication")


def enqueue_flags(pull, pull_version, reference, source, target, priority=0):
    return ["--pull-request", pull, "--expected-pull-version", pull_version,
            "--source-ref", reference, "--expected-source-tip", source,
            "--expected-target-tip", target, "--priority", priority]


def verify_queue(report, version, order):
    require(report["found"] is True and report["version"] == version, "queue version")
    queue = report["queue"]
    require(queue["target_ref"] == TARGET and queue["target_ref_hex"] == TARGET.encode().hex(), "target ref")
    require(queue["version"] == version and queue["order"] == order, "actual execution order")
    require(len(queue["entries"]) == len(order) and
            sorted(row["pull_request"] for row in queue["entries"]) == sorted(order), "lost/duplicate entries")
    require(all(row["enqueued_by"] == PRINCIPAL for row in queue["entries"]), "derived actor")
    require(queue["active_batch"] is None, "metadata management fabricated a batch")


def campaign(binary, root, algorithm):
    root.mkdir(parents=True, exist_ok=False)
    source = root / "source"
    f = fixture(source, algorithm)

    def branch(name, parent):
        body = commit(f["tree"], [parent], name)
        oid = identity(algorithm, "commit", body)
        path = source / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"commit {len(body)}\0".encode() + body))
        (source / "refs/heads" / name).write_text(oid + "\n", encoding="ascii")
        return oid

    second, third = branch("second", f["target"]), branch("third", f["target"])
    advance = branch("advance", f["target"])
    c = Campaign(binary, root, algorithm)
    c.run(["init", c.node, TENANT, REPOSITORY, algorithm])
    c.run(["import", c.node, TENANT, REPOSITORY, PRINCIPAL, "queue-fixture", source])
    refs_args = ["at", c.node, TENANT, REPOSITORY, "latest", "refs"]
    refs_before = c.run(refs_args).stdout
    absent = c.show(1, 4)
    require(absent["version"] == 0 and absent["queue"] is None, "absent queue state")
    c.incarnation = absent["repository_incarnation"]
    for number, reference, tip in [(7, SOURCE, f["source"]), (9, "refs/heads/second", second),
                                    (11, "refs/heads/third", third)]:
        c.pull("open", number, 0, reference, tip, f["target"], f"open-{number}")
    first_flags = enqueue_flags(7, 1, SOURCE, f["source"], f["target"])
    first = c.mutate("enqueue", 1, 0, "first", first_flags)
    pinned = c.show(1)
    verify_queue(pinned, 1, [7])
    c.mutate("enqueue", 1, 1, "second", enqueue_flags(9, 1, "refs/heads/second", second, f["target"], 10))
    verify_queue(c.show(1), 2, [9, 7])
    c.mutate("reorder", 1, 2, "reorder", ["--entry", 7, "--entry", 9])
    reordered = c.show(1)
    verify_queue(reordered, 3, [7, 9])
    require(c.mutate("enqueue", 1, 0, "first", first_flags) == first, "exact earlier outcome")
    require(c.show(1) == reordered, "retry mutated newer queue")
    require(c.show(1, token=pinned["snapshot_token"]) == pinned, "retained queue snapshot")
    third_flags = enqueue_flags(11, 1, "refs/heads/third", third, f["target"])
    stale = c.mutate("enqueue", 1, 2, "stale", third_flags, "EvidenceStale")
    c.mutate("reorder", 1, 3, "partial-order", ["--entry", 7], "ProtectedRefTransitionDenied")
    c.run(c.mutation_args("reorder", 1, 3, "duplicates", ["--entry", 7, "--entry", 7]), 2)
    verify_queue(c.show(1), 3, [7, 9])
    replacement = enqueue_flags(7, 1, SOURCE, f["source"], f["target"], 20)
    c.mutate("enqueue", 1, 3, "replace", replacement)
    verify_queue(c.show(1), 4, [7, 9])
    c.pull("update", 11, 1, "refs/heads/third", third, f["target"], "review-changed")
    c.mutate("enqueue", 1, 4, "stale-pr", third_flags, "EvidenceStale")

    c.mutate("enqueue", 10, 0, "queue-ten", enqueue_flags(9, 1, "refs/heads/second", second, f["target"]))
    c.mutate("enqueue", 2, 0, "queue-two", first_flags)
    page = document(c.run(c.queue_args("list", None, "--limit", 2)))
    c.header(page)
    require([q["number"] for q in page["queues"]] == [1, 2] and page["next_after"] == 2, "numeric pagination")
    c.run(c.queue_args("list", None, "--after", 2), 2)
    c.mutate("dequeue", 10, 1, "empty-ten", ["--pull-request", 9, "--reason", "withdrawn"])
    old_page = document(c.run(c.queue_args("list", None, "--after", 2, "--limit", 2,
                                         "--expected-head", page["snapshot_token"])))
    require(old_page["source_head"] == page["source_head"] and old_page["next_after"] is None, "page pin")
    require([q["number"] for q in old_page["queues"]] == [10] and old_page["queues"][0]["order"] == [9],
            "historical continuation used current queue")
    verify_queue(c.show(10), 2, [])
    c.mutate("dequeue", 1, 4, "remove-first", ["--pull-request", 7, "--reason", "withdrawn"])
    c.mutate("dequeue", 1, 5, "remove-second", ["--pull-request", 9, "--reason", "evicted"])
    empty = c.show(1)
    verify_queue(empty, 6, [])
    require(c.mutate("enqueue", 1, 0, "first", first_flags) == first, "post-dequeue exact retry")
    require(c.show(1) == empty, "historical retry revived removed entry")
    for key, expected, receipt in [("first", 0, first), ("stale", 3, stale)]:
        outcome = document(c.run([
            "outcome", c.node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm,
            "--principal", PRINCIPAL, "--idempotency-key", key,
        ], expected))
        require(outcome["transaction"]["tx_id"] == receipt["tx_id"], "recovery transaction identity")
    require(c.run(refs_args).stdout == refs_before, "queue management altered Git refs")

    # A separately admitted target move invalidates the old queue candidate;
    # refreshing canonical PR metadata supplies the allowed counterpart.
    moved = document(c.run([
        "branch", "update", c.node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm,
        "--principal", PRINCIPAL, "--idempotency-key", "move-target", "--ref", TARGET,
        "--expected-tip", f["target"], "--target", advance,
    ]))
    require(moved["outcome"] == "committed", "admitted target move")
    moved_refs = c.run(refs_args).stdout
    require(moved_refs != refs_before, "target fixture did not move authority")
    c.mutate("enqueue", 1, 6, "moved", enqueue_flags(11, 2, "refs/heads/third", third, f["target"]), "TargetRefMoved")
    c.pull("update", 11, 2, "refs/heads/third", third, advance, "refresh-target")
    refreshed = enqueue_flags(11, 3, "refs/heads/third", third, advance)
    c.mutate("enqueue", 1, 6, "refreshed", refreshed)
    verify_queue(c.show(1), 7, [11])
    c.pull("close", 11, 3, "refs/heads/third", third, advance, "close-third")
    c.mutate("enqueue", 3, 0, "closed", enqueue_flags(11, 4, "refs/heads/third", third, advance),
             "ProtectedRefTransitionDenied")
    settled = c.show(1)
    c.run(c.mutation_args("enqueue", 1, 0, "first", replacement), 2)
    wrong_incarnation = c.mutation_args("enqueue", 2, 1, "wrong-incarnation", refreshed)
    index = wrong_incarnation.index("--expected-incarnation") + 1
    wrong_incarnation[index] = "01" * 16 if c.incarnation != "01" * 16 else "02" * 16
    c.run(wrong_incarnation, 2)
    require(c.mutate("enqueue", 1, 2, "stale", third_flags, "EvidenceStale") == stale,
            "historical refusal changed after later mutations")
    require(c.show(1) == settled and c.run(refs_args).stdout == moved_refs, "failed request/retry changed state")
    result = dict(
        campaign="native_merge_queue_management", object_format=algorithm, command_count=c.calls,
        executable=str(binary), executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        passed=["lifecycle", "priority_and_explicit_order", "replacement_without_duplicates",
                "exact_retry_after_dequeue", "typed_stale_version_refusals", "complete_reorder",
                "numeric_pinned_pagination", "exact_pr_version", "live_target_guard",
                "closed_pr_refusal", "lost_response_recovery", "incarnation_guard", "refs_unchanged"],
        scope="Canonical queue management; speculative batching and merge landing are not exercised.",
    )
    (root / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--format", required=True, choices=["sha1", "sha256"])
    args = parser.parse_args()
    campaign(args.fg.resolve(), args.root / args.format, args.format)


if __name__ == "__main__":
    main()
