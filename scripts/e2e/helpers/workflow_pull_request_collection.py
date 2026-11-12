#!/usr/bin/env python3
"""Real HTTP-owned discovery of native PRs, original checks and retained custody.

The supplied fg creates and changes the actual repository and runs every shell
job. Only native loose-object fixture encoding and the existing HTTP service
process/wait/drain scaffolding are shared. Inventory files remain opaque: the
observations below are real effects, immutable run evidence and canonical reads.
"""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

from workflow_http_service import Server, arguments, credentials, event_directories
from workflow_watch_continuous import (
    Campaign, PRINCIPAL, REPOSITORY, TARGET, TENANT, commit, tree, write_object,
)

OTHER_TARGET = "refs/heads/release"


class Fixture:
    def __init__(self, campaign, fmt, label, *, merge_candidates=False):
        self.campaign, self.format = campaign, fmt
        self.root = campaign.root / f"{fmt}-{label}"
        self.root.mkdir(mode=0o700)
        self.source, self.node = self.root / "source", self.root / "node"
        self.runs, self.effects = self.root / "runs", self.root / "effects"
        self.runs.mkdir(mode=0o700)
        (self.source / "refs/heads").mkdir(parents=True)
        (self.source / "HEAD").write_text(f"ref: {TARGET}\n", encoding="utf-8")
        (self.source / "config").write_text(
            "[core]\nbare=true\nrepositoryformatversion="
            + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"),
            encoding="utf-8",
        )
        empty = write_object(self.source, fmt, "tree", b"")
        self.base = write_object(self.source, fmt, "commit", commit(empty, None, 1, b"base\n"))
        self.tips, self.future, self.pulls, self.merged_trees = {}, {}, {}, {}
        target_blob = write_object(self.source, fmt, "blob", b"only in the target branch\n") if merge_candidates else None
        for number in (1, 2, 3, 4, 9):
            target_check = "test -f target-only || exit 91; " if merge_candidates else ""
            definition = (
                "name: native-pr-collection\non:\n  pull_request:\n    branches: [target]\njobs:\n"
                "  check:\n    runs-on: fgit-trusted-local\n    steps:\n"
                f"      - run: {target_check}printf '{number}\\n' >> {shlex.quote(str(self.effects))}; "
                f"printf 'checked source {number}\\n'\n"
            )
            blob = write_object(self.source, fmt, "blob", definition.encode())
            ci = write_object(self.source, fmt, "tree", tree([(b"100644", b"build.yml", blob)]))
            root = write_object(self.source, fmt, "tree", tree([(b"40000", b"ci", ci)]))
            if merge_candidates:
                self.merged_trees[number] = write_object(self.source, fmt, "tree", tree([
                    (b"40000", b"ci", ci), (b"100644", b"target-only", target_blob),
                ]))
            tip = write_object(self.source, fmt, "commit", commit(root, self.base, 2, f"topic {number}\n".encode()))
            future = write_object(self.source, fmt, "commit", commit(root, tip, 3, f"advance {number}\n".encode()))
            self.tips[number], self.future[number] = tip, future
            (self.source / self.reference(number)).write_text(tip + "\n", encoding="utf-8")
            (self.source / f"refs/heads/future-{number}").write_text(future + "\n", encoding="utf-8")
        if merge_candidates:
            target_tree = write_object(self.source, fmt, "tree", tree([(b"100644", b"target-only", target_blob)]))
            self.base = write_object(self.source, fmt, "commit", commit(target_tree, self.base, 4, b"target-only change\n"))
        for name in (TARGET, OTHER_TARGET):
            (self.source / name).write_text(self.base + "\n", encoding="utf-8")
        self.scope = [self.node, TENANT, REPOSITORY]
        campaign.invoke("collection-init", ["init", *self.scope, fmt])
        campaign.invoke("collection-import", [
            "import", *self.scope, PRINCIPAL, "collection-fixture", self.source,
        ])
        header = campaign.invoke("collection-incarnation", [
            "serve-http", *self.scope, "127.0.0.1:0", "--trusted-local", "--print-credentials-header",
        ]).decode().strip().split()
        assert header[:3] == ["frankengit-http-credentials-v1", TENANT, REPOSITORY]
        assert len(header) == 4 and len(header[3]) == 32, header
        self.incarnation = header[3]
        credentials(self)

    @staticmethod
    def reference(number):
        return f"refs/heads/topic-{number}"

    def transition(self, number, action, target=TARGET):
        if action == "open":
            assert number not in self.pulls
            previous = 0
            row = {"tip": self.tips[number], "target": target, "version": 0}
        else:
            row = dict(self.pulls[number])
            previous = row["version"]
            if action == "reopen":
                row["tip"] = self.tips[number]
        self.campaign.invoke(f"collection-pr-{number}-{action}", [
            "pr", action, *self.scope, number, "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", f"collection-pr-{number}-{action}-{previous}",
            "--expected-version", previous, "--source-ref", self.reference(number),
            "--target-ref", row["target"], "--expected-source", row["tip"],
            "--expected-target", self.base, "--title", f"Collection PR {number}",
            "--body", "Trusted source-head execution", "--object-format", self.format,
        ])
        row["version"] = previous + 1
        self.pulls[number] = row

    def advance(self, number):
        old, new = self.tips[number], self.future[number]
        assert old != new
        self.campaign.invoke(f"collection-advance-{number}", [
            "branch", "update", *self.scope, "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", f"collection-advance-{number}", "--ref", self.reference(number),
            "--expected-tip", old, "--target", new, "--object-format", self.format,
        ])
        self.tips[number] = new

    def counts(self):
        if not self.effects.exists():
            return Counter()
        data = self.effects.read_bytes()
        assert len(data) <= 4096, "unexpected repeated collection execution"
        return Counter(int(line) for line in data.splitlines())

    def authority(self):
        return self.campaign.invoke("collection-authority", [
            "pr", "list", *self.scope, "--trusted-local", "--object-format", self.format,
        ])


def collection_arguments(fixture, stop_file, *, maximum=3, publish=True):
    args = arguments(fixture, stop_file, publish=publish, attempt=30)
    args[args.index("--workflow-ref") + 1] = TARGET
    args += ["--workflow-pull-requests", "--workflow-max-pull-requests", maximum]
    return args


class CollectionServer(Server):
    def __init__(self, fixture, label, *, maximum=3, publish=True):
        self.fixture = fixture
        self.stop_file = fixture.root / f"{label}.stop"
        self.output, self.diagnostic = fixture.root / f"{label}.out", fixture.root / f"{label}.err"
        self.endpoint = None
        args = collection_arguments(fixture, self.stop_file, maximum=maximum, publish=publish)
        with self.output.open("wb") as stdout, self.diagnostic.open("wb") as stderr:
            self.child = subprocess.Popen(
                [str(fixture.campaign.binary), *map(str, args)], stdout=stdout, stderr=stderr,
            )

    def rows(self):
        assert self.output.stat().st_size <= 4 * 1024 * 1024, "service observation exceeds campaign bound"
        return super().rows()

    def settled(self, count, *, reported=True):
        def complete(_):
            entries = event_directories(self.fixture)
            return len(entries) >= count and all(
                (entry / "settled").is_file() and (not reported or (entry / "reported").is_file())
                for entry in entries
            )
        self.wait(complete)
        entries = event_directories(self.fixture)
        assert len(entries) == count, entries
        return entries

    def page(self, number):
        status, data = self.request("GET", f"/api/v1/pulls/{number}/checks")
        assert status == 200, (status, data)
        page = json.loads(data)
        assert page["found"] and page["complete"], page
        return page

    def check(self, number):
        page = self.page(number)
        assert page["source_current"], page
        assert page["source_tip"] == self.fixture.tips[number], page
        assert len(page["checks"]) == 1, page
        check = page["checks"][0]
        assert check["job"] == "check" and check["conclusion"] == "success", check
        assert check["publisher"] == PRINCIPAL and len(check["evidence_sha256"]) == 64, check
        return check

    def idle(self):
        # All expected executions are already acknowledged. Observe continued
        # service life long enough for several complete serial polling rounds.
        deadline = time.monotonic() + 0.7
        while time.monotonic() < deadline:
            assert self.child.poll() is None, (self.rows(), self.diagnostic.read_bytes())
            time.sleep(0.03)


def clean(receipt):
    assert not receipt["non_green"] and not receipt["interrupted"], receipt
    assert not receipt["requires_reconciliation"] and not receipt["publication_pending"], receipt
    assert receipt["pending_execution"] == 0 and receipt["checks_refused"] == 0, receipt


def verified_events(fixture, expected):
    observed = set()
    for directory in event_directories(fixture):
        assert (directory / "settled").is_file(), directory
        event = json.loads((directory / "event.json").read_bytes())
        pull = event["pull_request"]
        number, version = int(pull["number"]), int(pull["version"])
        identity = (number, event["commit"], version)
        assert identity not in observed, identity
        observed.add(identity)
        assert event["profile"] == "latest-canonical-pull-request-head-v1"
        assert event["repository_incarnation"] == fixture.incarnation
        assert event["ref_hex"] == fixture.reference(number).encode().hex()
        assert pull["target_ref_hex"] == TARGET.encode().hex()
        assert pull["execution_profile"] == "source-head-only" and not pull["synthetic_merge"]
        assert "merge_candidate" not in event
        dispatch = json.loads((directory / f"dispatch-{event['dispatch_id']}" / "report.json").read_bytes())
        assert dispatch["succeeded"] and dispatch["matched_count"] == dispatch["executed_count"] == 1
        assert dispatch["plan"]["event"] == "pull_request"
        assert dispatch["plan"]["source_ref_hex"] == fixture.reference(number).encode().hex()
        assert dispatch["plan"]["source_commit"] == event["commit"]
        assert dispatch["plan"]["trigger_ref_hex"] == TARGET.encode().hex()
        assert len(dispatch["runs"]) == 1
        run = dispatch["runs"][0]
        assert run["executed_commit"] == event["commit"] and run["input_kind"] == "canonical"
        assert run["succeeded"] and run["workspaces_closed"] and not run["request_interrupted"]
        assert len(run["execution"]["jobs"]) == 1
        assert run["execution"]["jobs"][0]["outcome"] == "succeeded"
    assert observed == set(expected), (observed, expected)


def custody(fixture):
    # Only original execution identity/proof files are compared. Publication
    # may create acknowledgements, but it must not rewrite original evidence.
    names = {"event.json", "dispatch.json", "check-sources", "settled", "execution.owner", "check-proposals.journal"}
    return {
        str(path.relative_to(fixture.runs)): hashlib.sha256(path.read_bytes()).hexdigest()
        for event in event_directories(fixture) for path in event.rglob("*")
        if path.is_file() and path.name in names
    }


def refused_start(fixture, label, *, maximum):
    raw = fixture.campaign.invoke(label, collection_arguments(
        fixture, fixture.root / f"{label}.stop", maximum=maximum,
    ), 2)
    rows = [json.loads(line) for line in raw.splitlines() if line]
    assert not any(row.get("type") == "smart_http_listening" for row in rows), rows
    receipts = [row for row in rows if row.get("type") == "workflow_service_drained"]
    assert len(receipts) == 1, rows
    receipt = receipts[0]
    assert receipt["node_closed"] and receipt["service_failed"], receipt
    assert receipt["dispatched"] == 0 and not receipt["execution_retried"], receipt


def discovery_and_capacity(campaign, fmt):
    fixture = Fixture(campaign, fmt, "collection-lifecycle")
    for number in (1, 2, 4):
        fixture.transition(number, "open")
    fixture.transition(4, "close")
    fixture.transition(9, "open", OTHER_TARGET)
    original = dict(fixture.tips)
    expected = {(1, original[1], 1), (2, original[2], 1)}
    with CollectionServer(fixture, "discover") as server:
        server.ready()
        assert server.request("GET", "/info/refs?service=git-upload-pack", authenticated=False)[0] == 401
        assert server.request("GET", "/info/refs?service=git-receive-pack")[0] == 403
        server.settled(2)
        assert fixture.counts() == {1: 1, 2: 1}, fixture.counts()
        initial = {number: server.check(number)["id"] for number in (1, 2)}
        assert len(set(initial.values())) == 2
        verified_events(fixture, expected)
        # Closing the lower-numbered member must not starve either later
        # member. It retains its original custody while its source can advance.
        fixture.transition(1, "close")
        fixture.advance(1)
        fixture.advance(2)
        fixture.transition(3, "open")
        server.settled(4)
        expected |= {(2, fixture.tips[2], 1), (3, fixture.tips[3], 1)}
        verified_events(fixture, expected)
        assert fixture.counts() == {1: 1, 2: 2, 3: 1}, fixture.counts()
        # Source-head CI follows the current branch without rewriting PR
        # metadata. The existing PR checks API correctly refuses to present
        # newer-tip success as a check for the old recorded source snapshot.
        stale = server.page(2)
        assert not stale["source_current"] and stale["source_tip"] == original[2]
        assert stale["checks"] == [], stale
        final_id = server.check(3)["id"]
        assert final_id not in initial.values()
        server.idle()
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 4, workflow
    campaign.record(fmt, "PR-COLLECTION-001-discovers-current-and-future-prs-with-serial-progress",
                    executions=4, retained_members=3, ignored_other_target=9, closed_member=1)

    before, original_custody = fixture.authority(), custody(fixture)
    with CollectionServer(fixture, "restart") as server:
        server.ready()
        assert server.check(3)["id"] == final_id
        stale = server.page(2)
        assert not stale["source_current"] and not stale["checks"], stale
        server.idle()
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 0, workflow
    assert fixture.authority() == before and custody(fixture) == original_custody
    assert fixture.counts() == {1: 1, 2: 2, 3: 1}
    campaign.record(fmt, "PR-COLLECTION-002-restart-preserves-original-runs-and-checks")

    # There are only three CURRENT open matching PRs, but the closed original
    # still consumes a retained membership slot. A larger cap uses the same
    # custody rather than obtaining new execution identities for old members.
    fixture.transition(4, "reopen")
    before, original_custody = fixture.authority(), custody(fixture)
    refused_start(fixture, "retained-capacity", maximum=3)
    assert fixture.authority() == before and custody(fixture) == original_custody
    assert fixture.counts() == {1: 1, 2: 2, 3: 1}
    with CollectionServer(fixture, "larger-capacity", maximum=4) as server:
        server.ready()
        server.settled(5)
        expected.add((4, fixture.tips[4], 3))
        verified_events(fixture, expected)
        server.check(4)
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 1, workflow
    assert fixture.counts() == {1: 1, 2: 2, 3: 1, 4: 1}
    campaign.record(fmt, "PR-COLLECTION-003-retained-capacity-refusal-and-larger-cap-permitted-twin")


def closed_member_recovery(campaign, fmt):
    fixture = Fixture(campaign, fmt, "collection-recovery")
    for number in (1, 2):
        fixture.transition(number, "open")
    with CollectionServer(fixture, "original", maximum=2) as server:
        server.ready()
        old = server.settled(2)
        original_ids = {number: server.check(number)["id"] for number in (1, 2)}
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 2, workflow
    original_custody = custody(fixture)
    # Lose only derived acknowledgements after real canonical checks. Keep
    # the collection's original execution configuration and publisher fixed.
    for entry in old:
        (entry / "reported").unlink()
    for number in (1, 2):
        fixture.transition(number, "close")
    fixture.transition(3, "open")
    with CollectionServer(fixture, "recover-closed", maximum=3) as server:
        server.ready()
        # Existing members finish original check publication before readiness;
        # current closed state cannot erase their reporting responsibility.
        assert len(old) == 2 and all((entry / "reported").is_file() for entry in old)
        ids = {number: server.check(number)["id"] for number in (1, 2)}
        assert ids == original_ids
        assert all(hashlib.sha256((fixture.runs / path).read_bytes()).hexdigest() == digest
                   for path, digest in original_custody.items())
        server.settled(3)
        server.check(3)
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == 1 and workflow["checks_committed"] == 3, workflow
    assert fixture.counts() == {1: 1, 2: 1, 3: 1}
    campaign.record(fmt, "PR-COLLECTION-004-closed-members-recover-original-checks-before-new-execution")

    # Model lost local acknowledgements after actual canonical publication.
    # The original event/check journals and request identities are untouched.
    before, original_custody = fixture.authority(), custody(fixture)
    for entry in old:
        (entry / "reported").unlink()
    with CollectionServer(fixture, "lost-acknowledgements", maximum=3) as server:
        server.ready()
        assert {number: server.check(number)["id"] for number in (1, 2)} == ids
        server.idle()
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == 0, workflow
    assert fixture.authority() == before and custody(fixture) == original_custody
    assert fixture.counts() == {1: 1, 2: 1, 3: 1}
    campaign.record(fmt, "PR-COLLECTION-005-lost-acknowledgements-recover-original-terminal-decisions")


def unresolved_member_blocks_group(campaign, fmt):
    fixture = Fixture(campaign, fmt, "collection-unresolved")
    fixture.transition(1, "open")
    with CollectionServer(fixture, "original", maximum=2) as server:
        server.ready()
        entry, = server.settled(1)
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == workflow["checks_committed"] == 1, workflow
    proof = entry / "check-sources"
    original = proof.read_bytes()
    (entry / "settled").unlink()
    (entry / "reported").unlink()
    proof.write_bytes(original[:-1])
    fixture.transition(1, "close")
    fixture.transition(2, "open")
    before = fixture.authority()
    refused_start(fixture, "unresolved-closed-member", maximum=2)
    assert fixture.authority() == before and fixture.counts() == {1: 1}
    assert len(event_directories(fixture)) == 1
    assert proof.read_bytes() == original[:-1] and not (entry / "settled").exists()
    assert not (entry / "reported").exists()
    # Restore only the original proof, leaving the missing settlement marker.
    # Native recovery must derive settlement from the actual completed jobs.
    proof.write_bytes(original)
    with CollectionServer(fixture, "repaired-original-proof", maximum=2) as server:
        server.ready()
        assert (entry / "settled").is_file() and (entry / "reported").is_file()
        server.settled(2)
        server.check(1)
        server.check(2)
        workflow, _ = server.stop()
        clean(workflow)
        assert workflow["dispatched"] == 1 and workflow["checks_committed"] == 2, workflow
    assert fixture.counts() == {1: 1, 2: 1} and proof.read_bytes() == original
    campaign.record(fmt, "PR-COLLECTION-006-unresolved-old-member-blocks-entire-group-with-repair-twin")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    assert sys.platform.startswith("linux"), "native workflow collection requires Linux"
    output = options.output.resolve() if options.output else Path(tempfile.mkdtemp(prefix="fg-pr-collection-"))
    campaign = Campaign(binary, output)
    for fmt in ("sha1", "sha256"):
        discovery_and_capacity(campaign, fmt)
        closed_member_recovery(campaign, fmt)
        unresolved_member_blocks_group(campaign, fmt)
    print(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": len(campaign.results), "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
