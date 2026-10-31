#!/usr/bin/env python3
"""Actual HTTP-owned queue CI, dynamic head selection and bounded restart/drain."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

if len(sys.argv) != 3:
    raise SystemExit("usage: workflow_queue_merge_service.py FG_BIN OUTPUT_DIRECTORY")

from workflow_pull_request_merge_service import (  # noqa: E402
    FG, Server, arguments as pr_arguments, credentials, event_directories,
)
from workflow_queue_merge_watch import (  # noqa: E402
    CI_REF, PUBLISHER, RESULTS, ROOT, TARGET, QueueFixture, invoke, record,
)


def arguments(fixture, stop_file):
    result = pr_arguments(fixture, stop_file)
    result[result.index("--workflow-ref") + 1] = TARGET
    result[result.index("--workflow-pull-request")] = "--workflow-merge-queue"
    result[result.index("--workflow-merge-queue") + 1] = "1"
    return result


class QueueServer(Server):
    """Reuse actual TCP observations and drain assertions with queue arguments."""

    def __init__(self, fixture, label):
        self.fixture = fixture
        self.stop_file = fixture.root / f"{label}.stop"
        self.output = fixture.root / f"{label}.out"
        self.diagnostic = fixture.root / f"{label}.err"
        self.endpoint = None
        with self.output.open("wb") as stdout, self.diagnostic.open("wb") as stderr:
            self.child = subprocess.Popen(
                [FG, *map(str, arguments(fixture, self.stop_file))],
                stdout=stdout, stderr=stderr,
            )


def completed(fixture, number):
    directories = event_directories(fixture)
    return len(directories) == number and all(
        (directory / "settled").is_file() and (directory / "reported").is_file()
        for directory in directories
    )


def retained(fixture, number, queue_version):
    selected = []
    for directory in event_directories(fixture):
        event = json.loads((directory / "event.json").read_bytes())
        if event["merge_queue"]["version"] == str(queue_version):
            selected.append((directory, event))
    assert len(selected) == 1, selected
    directory, event = selected[0]
    assert (directory / "settled").is_file() and (directory / "reported").is_file()
    assert event["merge_queue"]["number"] == "1"
    assert event["merge_queue"]["pull_request"] == str(number)
    assert event["merge_queue"]["target_ref_hex"] == TARGET.encode().hex()
    assert event["merge_queue"]["policy_epoch"] == "1"
    candidate = event["merge_candidate"]
    assert candidate["commit"] == fixture.candidate_for(number)
    assert candidate["tree"] == fixture.merged_tree
    assert candidate["parents"] == [fixture.target, fixture.tips[number]]
    assert candidate["ref_hex"] == CI_REF.encode().hex()
    for name, field in (("candidate.bundle", "bundle_sha256"), ("landing.bundle", "landing_bundle_sha256")):
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == candidate[field]
    assert f"{fixture.candidate_for(number)} {TARGET}\n\n".encode() in (directory / "landing.bundle").read_bytes()
    publication = json.loads((directory / "candidate-publication.json").read_bytes())
    assert publication["committed"] and publication["candidate"] == fixture.candidate_for(number)
    assert publication["publication_key"] == candidate["publication_key"]
    report = json.loads((directory / f"dispatch-{event['dispatch_id']}" / "report.json").read_bytes())
    assert report["succeeded"] and report["matched_count"] == report["executed_count"] == 1
    assert report["plan"]["trigger_ref_hex"] == TARGET.encode().hex()
    assert report["plan"]["changed_paths"]["after"] == fixture.tips[number]
    run = report["runs"][0]
    assert run["executed_commit"] == fixture.candidate_for(number) and run["executed_tree"] == fixture.merged_tree
    assert run["input_kind"] == "canonical" and run["workspaces_closed"]
    assert run["execution"]["jobs"][0]["steps"][0]["stdout_hex"] == b"target\nsource\n".hex()
    selected = [item for item in report["plan"]["workflows"] if item["selected"]]
    assert len(selected) == 1 and selected[0]["path_hex"] == b"ci/build.yml".hex()
    return event, selected[0]["graph_sha256"]


def startup(fmt):
    fixture = QueueFixture(fmt, "http-startup")
    credentials(fixture)
    before, _ = fixture.refs()
    base = arguments(fixture, fixture.root / "startup.stop")
    for flag in ("--expected-incarnation", "--workflow-merge-queue", "--workflow-merge-principal"):
        invalid = list(base)
        index = invalid.index(flag)
        del invalid[index:index + 2]
        output = invoke("incomplete-http-queue-selection", invalid, 2)
        assert b'"type":"smart_http_listening"' not in output
        assert fixture.refs()[0] == before
        assert not fixture.count() and not event_directories(fixture)
    output = invoke("http-pr-and-queue-conflict", base + ["--workflow-pull-request", "7"], 2)
    assert b'"type":"smart_http_listening"' not in output
    diagnostic = fixture.root / "broken-readiness.err"
    with open("/dev/full", "wb") as stdout, diagnostic.open("wb") as stderr:
        result = subprocess.run(
            [FG, *map(str, base)], stdout=stdout, stderr=stderr, timeout=45, check=False,
        )
    error = diagnostic.read_bytes()
    if error:
        sys.stderr.buffer.write(error)
        sys.stderr.buffer.flush()
    assert result.returncode == 2, (result.returncode, error)
    assert fixture.refs()[0] == before and not fixture.count() and not event_directories(fixture)
    record(fixture, "queue-service-needs-complete-explicit-selection-and-successful-listener-readiness")


def lifecycle(fmt):
    fixture = QueueFixture(fmt, "http-lifecycle")
    credentials(fixture)
    with QueueServer(fixture, "queue-service") as server:
        server.ready()
        assert server.request("GET", "/info/refs?service=git-upload-pack", authenticated=False)[0] == 401
        assert server.request("GET", "/info/refs?service=git-receive-pack")[0] == 403
        assert server.request("POST", "/api/v1/source/tree", fields={"ref": CI_REF, "object_format": fmt})[0] == 403
        server.wait(lambda _: completed(fixture, 1))
        first, graph = retained(fixture, 8, 2)
        assert fixture.count() == [b"merged"]
        fixture.require_original_refs()
        assert not server.checks(8)["checks"]
        fixture.open_pr(9, CI_REF, fixture.candidate_for(8))
        first_page = server.checks(9)
        assert len(first_page["checks"]) == 1
        assert first_page["checks"][0]["publisher"] == PUBLISHER
        assert first_page["checks"][0]["graph_root"] == graph
        assert first_page["checks"][0]["conclusion"] == "success"
        fixture.reorder([7, 8])
        server.wait(lambda _: completed(fixture, 2))
        second, next_graph = retained(fixture, 7, 3)
        assert next_graph == graph and first["event_id"] != second["event_id"]
        assert fixture.count() == [b"merged", b"merged"]
        fixture.require_original_refs()
        fixture.open_pr(10, CI_REF, fixture.candidate_for(7))
        second_page = server.checks(10)
        assert len(second_page["checks"]) == 1
        assert second_page["checks"][0]["publisher"] == PUBLISHER
        assert second_page["checks"][0]["graph_root"] == graph
        assert second_page["checks"][0]["conclusion"] == "success"
        status, discovery = server.request("GET", "/info/refs?service=git-upload-pack")
        assert status == 200 and fixture.candidate_for(7).encode() in discovery
        workflow, _ = server.stop()
        assert workflow["dispatched"] == 2 and workflow["checks_committed"] == 2, workflow
    assert fixture.queue()["order"] == [7, 8]
    record(fixture, "http-owned-controller-follows-reordered-head-and-publishes-real-candidate-checks")

    before, refs = fixture.refs()
    with QueueServer(fixture, "queue-restart") as server:
        server.ready()
        assert server.checks(10)["checks"] == second_page["checks"]
        until = time.monotonic() + 0.5
        while time.monotonic() < until:
            assert server.child.poll() is None, server.diagnostic.read_bytes()
            time.sleep(0.03)
        workflow, _ = server.stop()
        assert workflow["dispatched"] == 0 and workflow["checks_committed"] == 0, workflow
    assert fixture.refs() == (before, refs)
    assert fixture.count() == [b"merged", b"merged"]
    assert retained(fixture, 8, 2) == (first, graph)
    assert retained(fixture, 7, 3) == (second, graph)
    record(fixture, "http-owned-queue-restart-drains-without-replaying-or-republishing-either-candidate")


if __name__ == "__main__":
    assert sys.platform.startswith("linux"), "native trusted queue CI requires Linux"
    for object_format in ("sha1", "sha256"):
        startup(object_format)
        lifecycle(object_format)
    (ROOT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n", encoding="utf-8")
