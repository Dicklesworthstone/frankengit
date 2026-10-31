#!/usr/bin/env python3
"""Fresh-process queue lifecycle, fast-forward and two-parent landing against fg.

Git fixture objects use Python's standard library. No Git subprocess or
speculative batch submission is used. Each command's output is retained.
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
    commit, document, fixture, identity, read_header, require,
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
        require(report["refusal_code"] == code, "canonical refusal code")
        require(report["refs_changed"] is (action in ("land", "land-candidate") and code is None),
                "publication ref effect")
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


def landing_flags(pull, pull_version, reference, source, target, policy_epoch):
    return ["--pull-request", pull, "--expected-pull-version", pull_version,
            "--source-ref", reference, "--expected-source-tip", source,
            "--expected-target-tip", target, "--expected-policy-epoch", policy_epoch]


def fixture_branch(source, algorithm, tree, name, parent):
    body = commit(tree, [parent], name)
    oid = identity(algorithm, "commit", body)
    path = source / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(f"commit {len(body)}\0".encode() + body))
    (source / "refs/heads" / name).write_text(oid + "\n", encoding="ascii")
    return oid


def verify_queue(report, version, order):
    require(report["found"] is True and report["version"] == version, "queue version")
    queue = report["queue"]
    require(queue["target_ref"] == TARGET and queue["target_ref_hex"] == TARGET.encode().hex(), "target ref")
    require(queue["version"] == version and queue["order"] == order, "actual execution order")
    require(len(queue["entries"]) == len(order) and
            sorted(row["pull_request"] for row in queue["entries"]) == sorted(order), "lost/duplicate entries")
    require(all(row["enqueued_by"] == PRINCIPAL for row in queue["entries"]), "derived actor")
    require(queue["active_batch"] is None, "queue exposed an unfinished batch")


def landing_campaign(binary, root, algorithm):
    """Land one existing head, then prepare and land its divergent successor."""
    root.mkdir(parents=True, exist_ok=False)
    source = root / "source"
    f = fixture(source, algorithm)
    # The shared PR fixture is deliberately divergent. Replace its source ref
    # with a real child of main before importing, and retain a sibling candidate.
    first = fixture_branch(source, algorithm, f["tree"], "topic", f["target"])
    second = fixture_branch(source, algorithm, f["tree"], "second", f["target"])
    c = Campaign(binary, root, algorithm)
    c.run(["init", c.node, TENANT, REPOSITORY, algorithm])
    c.run(["import", c.node, TENANT, REPOSITORY, PRINCIPAL, "landing-fixture", source])
    refs_args = ["at", c.node, TENANT, REPOSITORY, "latest", "refs"]
    refs_before = c.run(refs_args).stdout
    require(refs_before.count(f["target"].encode()) == 1, "exactly one initial target reference")
    c.incarnation = c.show(1, 4)["repository_incarnation"]

    def show_pull(number, token=None):
        args = ["pr", "show", c.node, TENANT, REPOSITORY, number,
                "--trusted-local", "--object-format", algorithm]
        if token is not None:
            args += ["--expected-head", token]
        report = document(c.run(args))
        read_header(report, algorithm)
        require(report["requested_number"] == number and report["found"] is True, "landing PR lookup")
        return report

    def policy():
        report = document(c.run(["protection", "show", c.node, TENANT, REPOSITORY,
                                 "--trusted-local", "--object-format", algorithm]))
        require(report["type"] == "review_protection" and report["node_closed"] is True, "policy read")
        return report

    def clear_policy(version, epoch, key):
        report = document(c.run([
            "protection", "set", c.node, TENANT, REPOSITORY, "--trusted-local",
            "--object-format", algorithm, "--principal", PRINCIPAL, "--idempotency-key", key,
            "--expected-version", version, "--expected-epoch", epoch, "--admin", PRINCIPAL, "--clear",
        ]))
        require(report["committed"] is True and report["refs_changed"] is False, "policy publication")
        require(report["committed_policy_epoch"] == epoch + 1 and report["node_closed"] is True,
                "exact policy successor")
        return epoch + 1

    current_policy = policy()
    require(current_policy["policy_epoch"] == 1 and current_policy["version"] == 0, "initial policy guard")
    for number, reference, tip in [(7, SOURCE, first), (9, "refs/heads/second", second)]:
        c.pull("open", number, 0, reference, tip, f["target"], f"open-{number}")
    c.mutate("enqueue", 1, 0, "enqueue-first", enqueue_flags(7, 1, SOURCE, first, f["target"]))
    c.mutate("enqueue", 1, 1, "enqueue-priority",
             enqueue_flags(9, 1, "refs/heads/second", second, f["target"], 10))
    verify_queue(c.show(1), 2, [9, 7])
    old_flags = landing_flags(7, 1, SOURCE, first, f["target"], 1)
    c.mutate("land", 1, 2, "skip-priority-head", old_flags, "ProtectedRefTransitionDenied")
    c.mutate("reorder", 1, 2, "choose-head", ["--entry", 7, "--entry", 9])
    stale = c.mutate("land", 1, 2, "stale-queue", old_flags, "EvidenceStale")
    c.mutate("land", 1, 3, "skip-reordered-head",
             landing_flags(9, 1, "refs/heads/second", second, f["target"], 1),
             "ProtectedRefTransitionDenied")

    # Equal commit coordinates do not permit silently refreshing a PR or policy
    # guard. Both change canonically while the queue remains at version three.
    c.pull("update", 7, 1, SOURCE, first, f["target"], "same-tips-new-pr-version")
    c.mutate("land", 1, 3, "stale-pr", old_flags, "EvidenceStale")
    epoch = clear_policy(0, 1, "install-policy")
    c.mutate("land", 1, 3, "stale-policy",
             landing_flags(7, 2, SOURCE, first, f["target"], 1), "EvidenceStale")
    c.mutate("land", 1, 3, "wrong-source-tip",
             landing_flags(7, 2, SOURCE, f["base"], f["target"], epoch), "EvidenceStale")
    c.mutate("land", 1, 3, "wrong-target-tip",
             landing_flags(7, 2, SOURCE, first, f["base"], epoch), "EvidenceStale")
    pinned = c.show(1)
    verify_queue(pinned, 3, [7, 9])
    pull_before = show_pull(7)
    survivor_before = show_pull(9)["pull_request"]
    require(pull_before["source_head"] == pinned["source_head"], "one pre-landing authority head")
    require(pull_before["pull_request"]["version"] == 2 and
            pull_before["pull_request"]["state"] == "open", "refusals merged the PR")
    require(c.run(refs_args).stdout == refs_before, "refused landing changed a ref")

    flags = landing_flags(7, 2, SOURCE, first, f["target"], epoch)
    landed = c.mutate("land", 1, 3, "land-first", flags)
    action = landed["proposed_action"]
    require(action == dict(name="land", method="fast-forward-only", pull_request=7,
                           expected_pull_request_version=2, expected_policy_epoch=epoch,
                           source_ref=SOURCE, source_ref_hex=SOURCE.encode().hex(),
                           head_tip=first, expected_target_tip=f["target"]), "exact sealed landing receipt")
    completed = c.show(1)
    verify_queue(completed, 5, [9])
    require(completed["source_head"] != pinned["source_head"], "landing did not publish authority")
    merged = show_pull(7)
    require(merged["source_head"] == completed["source_head"], "queue and PR use one committed head")
    row = merged["pull_request"]
    require(row["version"] == 3 and row["state"] == "merged" and row["last_action"] == "merge",
            "landing did not advance the PR exactly once")
    require(row["data"] == pull_before["pull_request"]["data"] and
            row["opened_by"] == PRINCIPAL and row["last_metadata_actor"] == PRINCIPAL,
            "landing discarded PR metadata or attribution")
    require(row["merge"] == dict(source_reference_hex=SOURCE.encode().hex(),
                                  target_reference_hex=TARGET.encode().hex(), source_tip=first,
                                  target_tip_before=f["target"], base_tip=f["target"], commit=first),
            "landing invented a merge object or changed its candidate")
    require(show_pull(9)["pull_request"] == survivor_before, "landing changed the other PR")
    refs_after = c.run(refs_args).stdout
    require(refs_after == refs_before.replace(f["target"].encode(), first.encode()),
            "landing changed a source/unrelated ref or failed to advance the target")
    require(c.show(1, token=pinned["snapshot_token"]) == pinned, "landing rewrote retained queue state")
    require(show_pull(7, pinned["snapshot_token"]) == pull_before, "landing rewrote retained PR state")

    # The surviving sibling cannot reuse the old target observation, and an
    # explicitly refreshed PR/queue still fails the native ancestry check.
    c.mutate("land", 1, 5, "survivor-old-target",
             landing_flags(9, 1, "refs/heads/second", second, f["target"], epoch), "TargetRefMoved")
    c.pull("update", 9, 1, "refs/heads/second", second, first, "refresh-survivor-target")
    c.mutate("enqueue", 1, 5, "refresh-survivor-queue",
             enqueue_flags(9, 2, "refs/heads/second", second, first))
    c.mutate("land", 1, 6, "divergent-survivor",
             landing_flags(9, 2, "refs/heads/second", second, first, epoch), "NonFastForwardRefused")
    verify_queue(c.show(1), 6, [9])
    survivor = show_pull(9)["pull_request"]
    require(survivor["state"] == "open" and survivor["version"] == 2, "divergent refusal merged a PR")
    require(c.run(refs_args).stdout == refs_after, "divergent refusal moved the target")
    # A real two-parent candidate handles the divergent survivor without
    # changing the existing fast-forward method or inventing passed checks.
    candidate_guards = landing_flags(9, 2, "refs/heads/second", second, first, epoch)
    before_preparation = c.show(1)
    bundle = root / "queue-head.bundle"
    prepare = c.queue_args(
        "prepare", 1, "--expected-version", 6, "--target-ref", TARGET,
        *candidate_guards, "--profile", "path-v1", "--author", "Queue <queue@example.invalid>",
        "--timestamp", 1700000000, "--message", "Integrate divergent queue head\n",
        "--output-bundle", bundle,
    )
    prepared = document(c.run(prepare))
    c.header(prepared)
    require(prepared["type"] == "merge_queue_preparation" and prepared["outcome"] == "prepared",
            "divergent queue head did not produce a candidate")
    require(prepared["number"] == 1 and prepared["expected_version"] == 6 and
            prepared["pull_request"] == 9 and prepared["expected_pull_request_version"] == 2 and
            prepared["expected_policy_epoch"] == epoch, "candidate lost exact guards")
    require(prepared["expected_source_tip"] == second and prepared["expected_target_tip"] == first and
            prepared["merge_base"] == f["target"], "candidate combined the wrong native histories")
    candidate = prepared["candidate_commit"]
    require(candidate not in (first, second, f["target"]) and prepared["method"] == "merge-commit",
            "preparation substituted an existing source commit")
    require(prepared["bundle_created"] is True and prepared["published_to_repository"] is False and
            prepared["refs_changed"] is False and bundle.is_file() and
            prepared["bundle_bytes"] == bundle.stat().st_size, "candidate artifact contract")
    require(c.show(1) == before_preparation and c.run(refs_args).stdout == refs_after,
            "read-only preparation changed repository authority")
    c.run(prepare, 2)  # A local artifact is never silently replaced.
    require(c.show(1) == before_preparation, "output collision changed queue authority")
    repeat_bundle = root / "queue-head-repeat.bundle"
    repeat_prepare = list(prepare)
    repeat_prepare[repeat_prepare.index("--output-bundle") + 1] = repeat_bundle
    repeated = document(c.run(repeat_prepare))
    require(repeated["candidate_commit"] == candidate and repeat_bundle.read_bytes() == bundle.read_bytes(),
            "same observed head and explicit metadata produced nondeterministic candidate bytes")
    candidate_flags = candidate_guards + ["--merge-base", prepared["merge_base"],
                                         "--expected-commit", candidate, "--bundle", bundle]
    refused_candidate = c.mutate("land-candidate", 1, 5, "candidate-stale-queue", candidate_flags, "EvidenceStale")
    candidate_landed = c.mutate("land-candidate", 1, 6, "land-divergent", candidate_flags)
    verify_queue(c.show(1), 8, [])
    candidate_pr = show_pull(9)["pull_request"]
    require(candidate_pr["version"] == 3 and candidate_pr["state"] == "merged" and
            candidate_pr["merge"]["commit"] == candidate and
            candidate_pr["merge"]["base_tip"] == f["target"] and
            candidate_pr["merge"]["target_tip_before"] == first,
            "candidate landing did not atomically publish the actual two-parent merge")
    landed_refs = c.run(refs_args).stdout
    require(landed_refs == refs_after.replace(f"  {TARGET} -> {first}\n".encode(),
                                             f"  {TARGET} -> {candidate}\n".encode()),
            "candidate landing changed a source/unrelated ref or failed to advance its target")
    refs_after = landed_refs
    require(c.show(1, token=before_preparation["snapshot_token"]) == before_preparation,
            "candidate landing rewrote retained queue history")
    next_epoch = clear_policy(1, epoch, "later-policy")
    latest = c.show(1)
    verify_queue(latest, 8, [])

    # Every invocation is a new process. Retry the original observations and
    # client key after queue and policy advancement; never refresh the request.
    require(c.mutate("land", 1, 3, "land-first", flags) == landed, "landing retry lost its original receipt")
    require(c.mutate("land", 1, 2, "stale-queue", old_flags, "EvidenceStale") == stale,
            "historical landing refusal changed after later publications")
    require(c.mutate("land-candidate", 1, 6, "land-divergent", candidate_flags) == candidate_landed,
            "candidate retry lost its original receipt")
    require(c.mutate("land-candidate", 1, 5, "candidate-stale-queue", candidate_flags, "EvidenceStale") ==
            refused_candidate, "candidate refusal changed after later publications")
    changed_candidate = list(candidate_flags)
    changed_candidate[changed_candidate.index("--expected-commit") + 1] = f["candidate"]
    c.run(c.mutation_args("land-candidate", 1, 6, "land-divergent", changed_candidate), 2)
    c.run(c.mutation_args("land", 1, 3, "land-first",
                         landing_flags(7, 2, SOURCE, first, f["target"], next_epoch)), 2)
    for key, expected, receipt in [("land-first", 0, landed), ("stale-queue", 3, stale),
                                   ("land-divergent", 0, candidate_landed)]:
        outcome = document(c.run([
            "outcome", c.node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm,
            "--principal", PRINCIPAL, "--idempotency-key", key,
        ], expected))
        require(outcome["transaction"]["tx_id"] == receipt["tx_id"], "landing recovery transaction identity")
    require(c.show(1) == latest and c.run(refs_args).stdout == refs_after,
            "landing retry or key reuse changed current queue/refs")
    require(show_pull(7)["pull_request"] == merged["pull_request"], "landing retry rewrote merged PR")
    result = dict(
        campaign="native_merge_queue_head_landing", object_format=algorithm, command_count=c.calls,
        transaction=landed["tx_id"], original_target=f["target"], landed_target=first,
        candidate_transaction=candidate_landed["tx_id"], candidate_target=candidate,
        queue_version=8, merged_pull_request_version=3,
        passed=["native_fast_forward_head", "atomic_target_pr_queue_post_state", "two_queue_versions_one_pr_version",
                "priority_and_reorder_head_guard", "stale_queue_guard", "same_tip_pr_version_guard",
                "policy_epoch_guard", "exact_source_and_target_guards", "retained_pre_landing_snapshots",
                "moved_target_refusal", "divergent_candidate_refusal", "fresh_process_exact_retry",
                "changed_guard_key_reuse_refusal", "original_outcome_recovery", "unrelated_refs_unchanged",
                "divergent_head_native_preparation", "read_only_same_head_artifact",
                "deterministic_create_only_bundle", "atomic_two_parent_candidate_landing",
                "candidate_stale_guard_and_original_outcome_recovery"],
    )
    (root / "results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def campaign(binary, root, algorithm):
    root.mkdir(parents=True, exist_ok=False)
    source = root / "source"
    f = fixture(source, algorithm)

    def branch(name, parent):
        return fixture_branch(source, algorithm, f["tree"], name, parent)

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
    landing = landing_campaign(binary, root / "landing", algorithm)
    result = dict(
        campaign="native_merge_queue_lifecycle", object_format=algorithm,
        command_count=c.calls + landing["command_count"], management_command_count=c.calls,
        landing=landing, landing_command_log="landing/commands.jsonl",
        executable=str(binary), executable_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        passed=["lifecycle", "priority_and_explicit_order", "replacement_without_duplicates",
                "exact_retry_after_dequeue", "typed_stale_version_refusals", "complete_reorder",
                "numeric_pinned_pagination", "exact_pr_version", "live_target_guard",
                "closed_pr_refusal", "lost_response_recovery", "incarnation_guard", "management_refs_unchanged"],
        scope="Canonical queue management, native fast-forward and prepared two-parent head landing; "
              "speculative multi-PR batching and workflow execution are not exercised.",
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
