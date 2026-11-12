#!/usr/bin/env python3
"""Real discovered-PR merged-tree CI, canonical checks and restart recovery.

Every workflow requires a file that exists only on the target branch. The
expected merged trees are independently encoded native Git fixtures. The real
fg imports them, discovers PRs, publishes separate candidate refs, runs shell
jobs, publishes checks and reopens its original custody after process restart.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from workflow_pull_request_collection import (
    CollectionServer, Fixture, OTHER_TARGET, clean, collection_arguments, custody,
)
from workflow_http_service import event_directories
from workflow_watch_continuous import Campaign, PRINCIPAL, TARGET

PREFIX = "refs/heads/ci/auto"
AUTHOR = "Collection Verifier <collection@example.invalid>"


def candidate_ref(number, prefix=PREFIX):
    return f"{prefix}/pr-{number}"


def arguments(fixture, stop_file, *, method="merge-commit", prefix=PREFIX, encoded=False):
    args = collection_arguments(fixture, stop_file, maximum=3, publish=True)
    flag = "--workflow-merge-candidate-ref-prefix-hex" if encoded else "--workflow-merge-candidate-ref-prefix"
    return args + [
        "--workflow-input", "target-only", flag, prefix.encode().hex() if encoded else prefix,
        "--workflow-merge-principal", PRINCIPAL,
        "--workflow-merge-author", AUTHOR, "--workflow-merge-committer", AUTHOR,
        "--workflow-merge-timestamp", 19, "--workflow-merge-message", "test exact collection candidate",
        "--workflow-merge-profile", "path", "--workflow-merge-method", method,
    ]


class MergeCollectionServer(CollectionServer):
    def __init__(self, fixture, label, *, method="merge-commit", encoded=False):
        self.fixture = fixture
        self.stop_file = fixture.root / f"{label}.stop"
        self.output, self.diagnostic = fixture.root / f"{label}.out", fixture.root / f"{label}.err"
        self.endpoint = None
        args = arguments(fixture, self.stop_file, method=method, encoded=encoded)
        with self.output.open("wb") as stdout, self.diagnostic.open("wb") as stderr:
            self.child = subprocess.Popen(
                [str(fixture.campaign.binary), *map(str, args)], stdout=stdout, stderr=stderr,
            )


def retained_candidates(fixture, numbers, method):
    observed = {}
    for directory in event_directories(fixture):
        assert (directory / "settled").is_file() and (directory / "reported").is_file(), directory
        event = json.loads((directory / "event.json").read_bytes())
        number = int(event["pull_request"]["number"])
        assert number in numbers and number not in observed, event
        assert event["pull_request"]["execution_profile"] == "exact-admitted-merge-candidate"
        assert event["pull_request"]["target_ref_hex"] == TARGET.encode().hex()
        assert event["commit"] == fixture.tips[number]
        candidate = event["merge_candidate"]
        assert candidate["ref_hex"] == candidate_ref(number).encode().hex(), candidate
        assert candidate["tree"] == fixture.merged_trees[number], candidate
        expected_parents = [fixture.base, fixture.tips[number]] if method == "merge-commit" else [fixture.base]
        assert candidate["parents"] == expected_parents and candidate["method"] == method, candidate
        assert candidate["principal"] == PRINCIPAL and candidate["expected_old"] is None, candidate
        assert candidate["bundle_sha256"] == hashlib.sha256((directory / "candidate.bundle").read_bytes()).hexdigest()
        publication = json.loads((directory / "candidate-publication.json").read_bytes())
        assert publication["committed"] and publication["candidate"] == candidate["commit"], publication
        dispatch = json.loads((directory / f"dispatch-{event['dispatch_id']}" / "report.json").read_bytes())
        assert dispatch["succeeded"] and dispatch["matched_count"] == dispatch["executed_count"] == 1
        plan = dispatch["plan"]
        assert plan["source_ref_hex"] == candidate_ref(number).encode().hex()
        assert plan["source_commit"] == candidate["commit"] and plan["source_tree"] == candidate["tree"]
        assert plan["trigger_ref_hex"] == TARGET.encode().hex()
        assert len(dispatch["runs"]) == 1
        run = dispatch["runs"][0]
        assert run["executed_commit"] == candidate["commit"] and run["executed_tree"] == candidate["tree"]
        assert run["workspaces_closed"] and run["succeeded"] and not run["request_interrupted"]
        assert run["execution"]["jobs"][0]["outcome"] == "succeeded"
        observed[number] = (candidate["commit"], directory)
    assert set(observed) == set(numbers), observed
    assert len({commit for commit, _ in observed.values()}) == len(numbers), observed
    return observed


def open_check_subject(fixture, number, candidate):
    # A read-only check query needs a canonical PR that names the CI branch.
    # Use another target so automatic discovery cannot recursively watch it.
    fixture.campaign.invoke(f"candidate-check-subject-{number}", [
        "pr", "open", *fixture.scope, 1000 + number, "--trusted-local", "--principal", PRINCIPAL,
        "--idempotency-key", f"candidate-check-subject-{number}", "--expected-version", 0,
        "--source-ref", candidate_ref(number), "--target-ref", OTHER_TARGET,
        "--expected-source", candidate, "--expected-target", fixture.base,
        "--title", f"Exact candidate check subject {number}", "--body", "Independent check observation",
        "--object-format", fixture.format,
    ])


def candidate_check(fixture, number, candidate):
    page = json.loads(fixture.campaign.invoke(f"read-candidate-check-{number}", [
        "pr", "checks", *fixture.scope, 1000 + number, "--trusted-local",
        "--object-format", fixture.format,
    ]))
    assert page["source_current"] and page["source_tip"] == candidate, page
    assert page["source_ref_hex"] == candidate_ref(number).encode().hex(), page
    assert len(page["checks"]) == 1, page
    check = page["checks"][0]
    assert check["job"] == "check" and check["conclusion"] == "success", check
    assert check["publisher"] == PRINCIPAL and len(check["evidence_sha256"]) == 64, check
    return check["id"]


def canonical_checks(fixture):
    page = json.loads(fixture.campaign.invoke("canonical-workflow-events", [
        "events", *fixture.scope, "--trusted-local", "--object-format", fixture.format, "--limit", 100,
    ]))
    assert not page["has_more"] and page["node_closed"], page
    checks = [row["aggregate"] for row in page["events"] if row["aggregate"].startswith("check/")]
    assert len(checks) == len(set(checks)), checks
    return set(checks)


def refused_configuration(fixture, label, args, *, expected_error):
    before, evidence = fixture.authority(), custody(fixture)
    counts = fixture.counts()
    raw = fixture.campaign.invoke(label, args, 2)
    diagnostic = (fixture.campaign.root / f"{fixture.campaign.sequence:03d}-{label}.err").read_text()
    assert expected_error in diagnostic, (expected_error, diagnostic)
    rows = [json.loads(line) for line in raw.splitlines() if line]
    assert not any(row.get("type") == "smart_http_listening" for row in rows), rows
    receipts = [row for row in rows if row.get("type") == "workflow_service_drained"]
    assert len(receipts) == 1, rows
    receipt = receipts[0]
    assert receipt["node_closed"] and receipt["service_failed"], receipt
    assert receipt["dispatched"] == 0 and not receipt["execution_retried"], receipt
    assert receipt["checks_committed"] == receipt["checks_refused"] == 0, receipt
    assert fixture.authority() == before and custody(fixture) == evidence
    assert fixture.counts() == counts


def lifecycle(campaign, fmt, method):
    fixture = Fixture(campaign, fmt, f"merge-collection-{method}", merge_candidates=True)
    for number in (1, 2):
        fixture.transition(number, "open")
    with MergeCollectionServer(fixture, "initial", method=method) as server:
        server.ready()
        assert server.request("GET", "/info/refs?service=git-upload-pack", authenticated=False)[0] == 401
        assert server.request("GET", "/info/refs?service=git-receive-pack")[0] == 403
        server.settled(2)
        candidates = retained_candidates(fixture, (1, 2), method)
        assert fixture.counts() == {1: 1, 2: 1}, fixture.counts()
        for number in candidates:
            original = server.page(number)
            assert original["source_tip"] == fixture.tips[number] and not original["checks"], original
        server.idle()
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 2, workflow
    ids = canonical_checks(fixture)
    assert len(ids) == 2
    campaign.record(fmt, "PR-MERGE-COLLECTION-001-distinct-merged-trees-and-canonical-checks",
                    method=method, candidates={n: c for n, (c, _) in candidates.items()})

    # Recover a lost reporting acknowledgement from a now-closed member while
    # admitting a new PR, retaining original evidence and avoiding script replay.
    # The native on_ready regression separately proves strict readiness ordering.
    first_directory = candidates[1][1]
    original_evidence = custody(fixture)
    (first_directory / "reported").unlink()
    fixture.transition(1, "close")
    fixture.transition(3, "open")
    with MergeCollectionServer(fixture, "recovery", method=method, encoded=True) as server:
        server.ready()
        assert (first_directory / "reported").is_file()
        server.settled(3)
        all_candidates = retained_candidates(fixture, (1, 2, 3), method)
        assert not server.page(3)["checks"], "candidate success must not become source-head success"
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == 1 and workflow["checks_committed"] == 2, workflow
    assert fixture.counts() == {1: 1, 2: 1, 3: 1}
    all_ids = canonical_checks(fixture)
    assert len(all_ids) == 3 and ids < all_ids
    assert all(hashlib.sha256((fixture.runs / path).read_bytes()).hexdigest() == digest
               for path, digest in original_evidence.items())
    campaign.record(fmt, "PR-MERGE-COLLECTION-002-closed-member-recovery-without-reexecution", method=method)

    before, evidence = fixture.authority(), custody(fixture)
    with MergeCollectionServer(fixture, "restart", method=method) as server:
        server.ready()
        assert all(not server.page(n)["checks"] for n in all_candidates)
        server.idle()
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 0, workflow
    assert fixture.authority() == before and custody(fixture) == evidence
    assert canonical_checks(fixture) == all_ids
    assert fixture.counts() == {1: 1, 2: 1, 3: 1}
    campaign.record(fmt, "PR-MERGE-COLLECTION-003-restart-preserves-every-candidate-and-check", method=method)

    refused_configuration(fixture, "prefix-drift", arguments(
        fixture, fixture.root / "prefix-drift.stop", method=method, prefix="refs/heads/ci/changed",
    ), expected_error="PR collection inventory: scope, publisher or execution configuration differs")
    refused_configuration(fixture, "mode-drift", collection_arguments(
        fixture, fixture.root / "mode-drift.stop", maximum=3, publish=True,
    ) + ["--workflow-input", "target-only"],
        expected_error="PR collection inventory: scope, publisher or execution configuration differs")
    campaign.record(fmt, "PR-MERGE-COLLECTION-004-configuration-drift-retains-original-custody", method=method)

    # After the collection is fully drained, independently query its actual
    # canonical observations through PRs naming the generated candidate refs.
    # Those refs now deliberately violate the collection's exclusive namespace:
    # a later start must refuse even though these PRs target another branch.
    observed_ids = set()
    for number, (candidate, _) in all_candidates.items():
        open_check_subject(fixture, number, candidate)
        observed_ids.add(candidate_check(fixture, number, candidate))
    assert observed_ids == all_ids
    refused_configuration(fixture, "unrelated-pr-namespace-collision", arguments(
        fixture, fixture.root / "collision.stop", method=method,
    ), expected_error="collection CI namespace must be disjoint from every PR source and target branch")
    campaign.record(fmt, "PR-MERGE-COLLECTION-005-canonical-check-binding-and-foreign-pr-namespace-refusal", method=method)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    assert sys.platform.startswith("linux"), "native workflow collection requires Linux"
    output = options.output.resolve() if options.output else Path(tempfile.mkdtemp(prefix="fg-pr-merge-collection-"))
    campaign = Campaign(binary, output)
    for fmt in ("sha1", "sha256"):
        for method in ("merge-commit", "squash"):
            lifecycle(campaign, fmt, method)
    print(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": len(campaign.results), "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
