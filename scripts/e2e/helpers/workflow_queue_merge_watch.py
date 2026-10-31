#!/usr/bin/env python3
"""Actual queue-head CI, retained landing bundles and canonical guarded landing.

The shared fixture independently encodes real native objects; every operation
below invokes the real FG_BIN. No Git executable, mock queue or mock runner is
used. This is trusted-host functional evidence, not hostile-code isolation.
"""

import hashlib
import json
from pathlib import Path
import sys
import zlib

if len(sys.argv) != 3:
    raise SystemExit("usage: workflow_queue_merge_watch.py FG_BIN OUTPUT_DIRECTORY")

from workflow_pull_request_merge_watch import (  # noqa: E402
    AUTHOR, CI_REF, MESSAGE, OWNER, PUBLISHER, RESULTS, ROOT, SOURCE, TARGET,
    TIMESTAMP, Fixture, commit, identity, invoke, poll, record, rows,
)

SECOND = "refs/heads/topic-two"


def put(fixture, kind, body):
    oid = identity(fixture.fmt, kind, body)
    path = fixture.source / "objects" / oid[:2] / oid[2:]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
    return oid


def source_tree(fixture, oid):
    path = fixture.source / "objects" / oid[:2] / oid[2:]
    body = zlib.decompress(path.read_bytes()).split(b"\0", 1)[1]
    return body.split(b"\n", 1)[0].removeprefix(b"tree ").decode("ascii")


class QueueFixture(Fixture):
    def __init__(self, fmt, label, conflict=False):
        super().__init__(fmt, "merge-commit", "queue-" + label, conflict=conflict)
        # A distinct native commit on a second branch proves selection follows
        # canonical queue order rather than the first PR or a configured source.
        second = put(self, "commit", commit(
            source_tree(self, self.incoming), [self.incoming], "second incoming\n",
        ))
        (self.source / SECOND).write_text(second + "\n", encoding="ascii")
        invoke("import-second-queue-source", [
            "import", *self.scope, OWNER, "queue-second-fixture", self.source,
        ])
        self.open_pr(8, SECOND, second)
        self.tips = {7: self.incoming, 8: second}
        self.sources = {7: SOURCE, 8: SECOND}
        self.queue_version = 0
        self.enqueue(7, 1, 0, "queue-first")
        self.enqueue(8, 1, 10, "queue-priority-head")
        self.watch[self.watch.index(SOURCE)] = TARGET
        self.watch[self.watch.index("--pull-request")] = "--merge-queue"
        self.watch[self.watch.index("--merge-queue") + 1] = "1"

    def queue_base(self, operation):
        return [
            "queue", operation, *self.scope, "1", "--trusted-local",
            "--expected-incarnation", self.incarnation, "--object-format", self.fmt,
        ]

    def enqueue(self, number, pull_version, priority, key):
        result = json.loads(invoke("enqueue", self.queue_base("enqueue") + [
            "--principal", OWNER, "--idempotency-key", key,
            "--expected-version", str(self.queue_version), "--target-ref", TARGET,
            "--pull-request", str(number), "--expected-pull-version", str(pull_version),
            "--source-ref", self.sources[number], "--expected-source-tip", self.tips[number],
            "--expected-target-tip", self.target, "--priority", str(priority),
        ]))
        assert result["committed"] and result["node_closed"], result
        self.queue_version += 1

    def reorder(self, order):
        fields = [value for number in order for value in ("--entry", str(number))]
        result = json.loads(invoke("reorder", self.queue_base("reorder") + [
            "--principal", OWNER, "--idempotency-key", f"queue-reorder-{self.queue_version}",
            "--expected-version", str(self.queue_version), "--target-ref", TARGET, *fields,
        ]))
        assert result["committed"] and result["node_closed"], result
        self.queue_version += 1

    def queue(self):
        result = json.loads(invoke("queue-state", self.queue_base("show")))
        assert result["found"] and result["complete"] and result["node_closed"], result
        return result["queue"]

    def candidate_for(self, number):
        return identity(self.fmt, "commit", commit(
            self.merged_tree, [self.target, self.tips[number]], MESSAGE, TIMESTAMP,
        ))

    def require_original_refs(self):
        _, refs = self.refs()
        assert refs[TARGET] == self.target, refs
        for number in (7, 8):
            assert refs[self.sources[number]] == self.tips[number], refs
        assert not self.excluded.exists(), "target-only or wrong-trigger workflow executed"
        return refs

    def land(self, number, bundle, key, epoch, accepted=False, queue_version=None):
        result = json.loads(invoke("guarded-queue-landing", self.queue_base("land-candidate") + [
            "--principal", OWNER, "--idempotency-key", key,
            "--expected-version", str(self.queue_version if queue_version is None else queue_version),
            "--expected-policy-epoch", str(epoch), "--pull-request", str(number),
            "--expected-pull-version", "1", "--source-ref", self.sources[number],
            "--target-ref", TARGET, "--expected-source-tip", self.tips[number],
            "--expected-target-tip", self.target, "--merge-base", self.base,
            "--expected-commit", self.candidate_for(number), "--bundle", bundle,
        ], 0 if accepted else 3))
        assert result["committed"] is accepted and result["refs_changed"] is accepted, result
        assert result["node_closed"] and result["cleanup_error"] is None, result
        return result


def require_candidate(fixture, observed, number, epoch):
    assert observed["state"] == "dispatched" and observed["execution_settled"], observed
    event, dispatch = observed["event"], observed["dispatch"]
    queue = event["merge_queue"]
    assert queue == {
        "number": "1", "version": str(fixture.queue_version),
        "target_ref_hex": TARGET.encode().hex(), "pull_request": str(number),
        "pull_request_version": "1", "policy_epoch": str(epoch),
    }, queue
    assert event["pull_request"]["number"] == str(number)
    assert event["commit"] == fixture.tips[number]
    candidate = event["merge_candidate"]
    assert candidate["ref_hex"] == CI_REF.encode().hex()
    assert candidate["commit"] == fixture.candidate_for(number)
    assert candidate["parents"] == [fixture.target, fixture.tips[number]]
    assert dispatch["succeeded"] and dispatch["matched_count"] == dispatch["executed_count"] == 1
    assert len(dispatch["runs"]) == 1
    run = dispatch["runs"][0]
    assert run["executed_commit"] == fixture.candidate_for(number)
    assert run["executed_tree"] == fixture.merged_tree
    assert run["input_kind"] == "canonical" and run["workspaces_closed"]
    assert run["execution"]["jobs"][0]["steps"][0]["stdout_hex"] == b"target\nsource\n".hex()
    selected = [item for item in dispatch["plan"]["workflows"] if item["selected"]]
    assert len(selected) == 1 and selected[0]["path_hex"] == b"ci/build.yml".hex()
    directory = Path(bytes.fromhex(event["custody_directory_hex"]).decode())
    landing = directory / candidate["landing_bundle"]
    assert candidate["landing_bundle"] == "landing.bundle" and landing.is_file()
    assert hashlib.sha256(landing.read_bytes()).hexdigest() == candidate["landing_bundle_sha256"]
    assert hashlib.sha256((directory / "candidate.bundle").read_bytes()).hexdigest() == candidate["bundle_sha256"]
    assert f"{fixture.candidate_for(number)} {TARGET}\n\n".encode() in landing.read_bytes()
    assert (directory / "settled").is_file()
    fixture.require_original_refs()
    return landing, selected[0]["graph_sha256"]


def success(fmt):
    f = QueueFixture(fmt, "success")
    assert f.queue()["order"] == [8, 7]
    automatic = f.watch + ["--publish-checks", "--principal-id", PUBLISHER]
    first_output = invoke("priority-head-ci", automatic)
    first = poll(first_output)
    _, graph = require_candidate(f, first, 8, 1)
    assert f.count() == [b"merged"]
    first_decisions = [row for row in rows(first_output) if row["type"] == "workflow_check_set_decision"]
    assert len(first_decisions) == 1 and first_decisions[0]["command_committed"]
    record(f, "priority-selects-second-pr-and-executes-exact-combined-candidate", candidate=f.candidate_for(8))

    before, _ = f.refs()
    assert poll(invoke("queue-restart", automatic))["state"] == "previously_settled"
    assert f.refs()[0] == before and f.count() == [b"merged"]
    f.reorder([7, 8])
    reordered = poll(invoke("reordered-head-ci", f.watch))
    old_bundle, reordered_graph = require_candidate(f, reordered, 7, 1)
    assert reordered_graph == graph and f.candidate_for(7) != f.candidate_for(8)
    assert f.count() == [b"merged", b"merged"]
    assert f.queue()["order"] == [7, 8] and f.queue()["version"] == 3
    record(f, "explicit-reorder-selects-new-native-candidate-without-moving-either-pr")

    changed = list(f.watch)
    changed[changed.index("--merge-message") + 1] = "changed immutable candidate configuration\n"
    invoke("changed-custody-config", changed, 2)
    assert f.count() == [b"merged", b"merged"]
    f.require_original_refs()

    policy = json.loads(invoke("queue-and-exact-check-policy", [
        "protection", "set", *f.scope, "--trusted-local", "--principal", OWNER,
        "--admin", OWNER, "--idempotency-key", "queue-exact-check-policy",
        "--expected-version", "0", "--expected-epoch", "1", "--object-format", fmt,
        "--require-merge-queue", TARGET,
        "--require-check", f"{TARGET}:{CI_REF}:{PUBLISHER}:{graph}:build",
    ]))
    assert policy["committed"] and policy["committed_policy_epoch"] == 2
    stale = f.land(7, old_bundle, "old-policy-landing", 1)
    assert stale["refusal_code"] == "EvidenceStale", stale
    refreshed = poll(invoke("policy-change-retests-candidate", f.watch))
    landing, new_graph = require_candidate(f, refreshed, 7, 2)
    assert new_graph == graph and f.count() == [b"merged"] * 3
    denied = f.land(7, landing, "local-success-without-canonical-check", 2)
    assert denied["refusal_code"] == "ProtectedRefTransitionDenied", denied
    f.require_original_refs()
    record(f, "policy-change-invalidates-original-landing-and-reserves-fresh-execution")

    publication = rows(invoke("publish-retained-queue-checks", automatic))
    decisions = [row for row in publication if row["type"] == "workflow_check_set_decision"]
    assert len(decisions) == 2 and all(row["command_committed"] for row in decisions), decisions
    assert all(row["conclusion"] == "success" and not row["execution_retried"] for row in decisions)
    assert publication[-1]["committed_check_decisions"] == 2 and publication[-1]["node_closed"]
    assert poll(b"\n".join(json.dumps(row).encode() for row in publication))["state"] == "previously_settled"
    assert f.count() == [b"merged"] * 3
    assert not f.checks(7)["checks"] and not f.checks(8)["checks"]
    f.require_original_refs()
    assert f.land(7, landing, "local-success-without-canonical-check", 2) == denied
    record(f, "retained-candidate-checks-publish-without-replay-or-source-head-relabeling")

    # Even actual canonical passing checks cannot bypass the required queue.
    ordinary = json.loads(invoke("ordinary-merge-cannot-bypass-queue", [
        "merge", "apply", *f.scope, TARGET, landing, "--trusted-local", "--principal", OWNER,
        "--idempotency-key", "ordinary-checked-merge", "--source-ref", SOURCE,
        "--expected-source", f.incoming, "--expected-target", f.target,
        "--merge-base", f.base, "--expected-commit", f.candidate_for(7),
        "--pull-request", "7", "--expected-version", "1", "--method", "merge-commit",
    ], 2))
    assert ordinary["outcome"] == "refused" and ordinary["refusal_code"] == "ProtectedRefTransitionDenied"
    accepted = f.land(7, landing, "checked-canonical-queue-landing", 2, accepted=True)
    assert f.land(7, landing, "checked-canonical-queue-landing", 2, accepted=True) == accepted
    remaining = f.queue()
    assert remaining["version"] == 5 and remaining["order"] == [8] and remaining["active_batch"] is None
    _, refs = f.refs()
    assert refs[TARGET] == refs[CI_REF] == f.candidate_for(7)
    assert refs[SOURCE] == f.incoming and refs[SECOND] == f.tips[8]
    stale_head = poll(invoke("next-head-needs-explicit-target-refresh", automatic, 1))
    assert stale_head["state"] == "queue_head_stale" and stale_head["dispatch"] is None
    assert f.count() == [b"merged"] * 3
    record(f, "retained-exact-bundle-lands-one-head-and-stale-successor-never-executes",
           tx=accepted["tx_id"], remaining_version=remaining["version"])


def source_refresh(fmt):
    f = QueueFixture(fmt, "source-refresh")
    old = f.tips[8]
    updated = put(f, "commit", commit(source_tree(f, old), [old], "explicit source refresh\n"))
    (f.source / SECOND).write_text(updated + "\n", encoding="ascii")
    invoke("advance-queued-source", ["import", *f.scope, OWNER, "queue-source-advanced", f.source])
    f.tips[8] = updated
    before, _ = f.refs()
    stale = poll(invoke("queued-source-is-stale", f.watch, 1))
    assert stale["state"] == "queue_head_stale" and stale["dispatch"] is None
    assert not f.count() and not list(f.runs.glob("watch-*/event-*"))
    assert f.refs()[0] == before
    refreshed = json.loads(invoke("refresh-native-pr", [
        "pr", "update", *f.scope, "8", "--trusted-local", "--principal", OWNER,
        "--idempotency-key", "queue-pr-refresh", "--expected-version", "1",
        "--source-ref", SECOND, "--target-ref", TARGET,
        "--expected-source", updated, "--expected-target", f.target,
        "--title", "Explicitly refreshed queue candidate", "--body", "New exact source observation",
        "--object-format", fmt,
    ]))
    assert refreshed["command_committed"]
    assert poll(invoke("queue-entry-still-old", f.watch, 1))["state"] == "queue_head_stale"
    assert not f.count()
    f.enqueue(8, 2, 10, "explicitly-refresh-queue-entry")
    observed = poll(invoke("refreshed-queue-head-ci", f.watch))
    assert observed["state"] == "dispatched" and observed["dispatch"]["succeeded"]
    assert observed["event"]["merge_queue"]["pull_request_version"] == "2"
    assert observed["event"]["merge_candidate"]["commit"] == f.candidate_for(8)
    assert f.count() == [b"merged"]
    f.require_original_refs()
    record(f, "source-movement-requires-both-explicit-pr-refresh-and-reenqueue")


def conflict(fmt):
    f = QueueFixture(fmt, "conflict", conflict=True)
    before, refs = f.refs()
    for label in ("conflicted-queue", "conflicted-queue-restart"):
        observed = poll(invoke(label, f.watch, 1))
        assert observed["state"] == "merge_conflicted" and observed["dispatch"] is None
        assert f.refs() == (before, refs)
        assert not f.count() and not list(f.runs.glob("watch-*/event-*"))
        assert CI_REF not in refs
    record(f, "conflicted-head-never-publishes-candidate-or-starts-scripts")


if __name__ == "__main__":
    for object_format in ("sha1", "sha256"):
        success(object_format)
        source_refresh(object_format)
        conflict(object_format)
    (ROOT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n", encoding="utf-8")
