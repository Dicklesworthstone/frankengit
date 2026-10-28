#!/usr/bin/env python3
"""Actual HTTP-owned PR candidate CI, canonical checks and restart custody.

Reuses independent native Git object fixtures from the foreground campaign.
Every repository operation uses the real FG_BIN. HTTP observations use the
standard library; no authority store, execution controller or runner is mocked.
This is functional trusted-host evidence, not hostile-runner isolation.
"""

import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
from urllib.parse import urlencode, urlsplit

if len(sys.argv) != 3:
    raise SystemExit("usage: workflow_pull_request_merge_service.py FG_BIN OUTPUT_DIRECTORY")

# The shared fixture takes the same two positional arguments. Its campaign is
# guarded by __main__; importing it performs no repository command or execution.
from workflow_pull_request_merge_watch import (  # noqa: E402
    AUTHOR, CI_REF, FG, MESSAGE, OWNER, PUBLISHER, REPOSITORY, RESULTS, ROOT,
    SOURCE, TARGET, TENANT, TIMESTAMP, Fixture, invoke, record,
)


def credentials(fixture):
    fixture.token = secrets.token_hex(32)
    fixture.credentials = fixture.root / "http-credentials"
    digest = hashlib.sha256(fixture.token.encode()).hexdigest()
    header = f"frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {fixture.incarnation}"
    # The token permits receive, but the listener flag remains disabled. Local
    # CI authority must not grant the corresponding network operation.
    descriptor = os.open(fixture.credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(f"{header}\n{digest} {OWNER} read,receive,pulls-read\n")


def arguments(fixture, stop_file):
    return [
        "serve-http", *fixture.scope, "127.0.0.1:0", "--trusted-local",
        "--credentials-file", fixture.credentials, "--allow-pulls",
        "--continuous", "--stop-file", stop_file, "--max-in-flight", "2",
        "--session-timeout-secs", "10", "--processing-timeout-secs", "30",
        "--expected-incarnation", fixture.incarnation,
        "--workflow-trusted-local", "--workflow-ref", SOURCE,
        "--workflow-pull-request", "7", "--workflow-dir", "ci",
        "--workflow-input", "ci", "--workflow-input", "left", "--workflow-input", "right",
        "--workflow-run-parent", fixture.runs, "--workflow-format", fixture.fmt,
        "--workflow-interval-ms", "100", "--workflow-attempt-timeout-secs", "30",
        "--workflow-merge-candidate-ref", CI_REF, "--workflow-merge-principal", OWNER,
        "--workflow-merge-author", AUTHOR, "--workflow-merge-committer", AUTHOR,
        "--workflow-merge-timestamp", str(TIMESTAMP), "--workflow-merge-message", MESSAGE,
        "--workflow-merge-profile", "path", "--workflow-merge-method", fixture.method,
        "--workflow-publish-checks", "--workflow-principal", PUBLISHER,
    ]


def event_directories(fixture):
    return sorted(fixture.runs.glob("watch-*/event-*"))


class Server:
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

    def rows(self):
        data = self.output.read_bytes()
        assert len(data) <= 4 * 1024 * 1024, "service observation exceeds campaign bound"
        # Concurrently appended records are complete only after their newline.
        return [json.loads(line) for line in data.split(b"\n")[:-1] if line]

    def wait(self, condition, seconds=45):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            observed = self.rows()
            if condition(observed):
                return observed
            assert self.child.poll() is None, (
                "candidate service exited before the expected observation", self.child.returncode,
                self.output.read_bytes(), self.diagnostic.read_bytes(),
            )
            time.sleep(0.03)
        raise AssertionError(("candidate service wait expired", self.output.read_bytes(),
                              self.diagnostic.read_bytes()))

    def ready(self):
        observed = self.wait(lambda rows: any(row.get("type") == "smart_http_listening" for row in rows))
        candidates = [row for row in observed if row.get("type") == "smart_http_listening"]
        assert len(candidates) == 1, observed
        ready = candidates[0]
        assert ready["schema_version"] == 1 and ready["workflow_enabled"] is True
        assert ready["lifetime"] == "continuous" and ready["credential_mode"] == "reloadable"
        assert not ready["receive_enabled"] and not ready["source_enabled"]
        assert ready["pulls_enabled"] and ready["repository_incarnation"] == self.fixture.incarnation
        self.endpoint = urlsplit(ready["url"])
        assert self.endpoint.scheme == "http" and self.endpoint.hostname == "127.0.0.1"
        assert self.endpoint.path == f"/{REPOSITORY}.git"

    def request(self, method, route, *, fields=None, authenticated=True):
        assert self.endpoint is not None
        connection = http.client.HTTPConnection(self.endpoint.hostname, self.endpoint.port, timeout=15)
        headers = {
            "Connection": "close",
            "User-Agent": "frankengit-e2e (+https://github.com/Dicklesworthstone/frankengit)",
        }
        if authenticated:
            headers["Authorization"] = "Bearer " + self.fixture.token
        body = None
        if fields is not None:
            body = urlencode(fields).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request(method, self.endpoint.path + route, body=body, headers=headers)
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            assert len(data) <= 1024 * 1024, "HTTP observation exceeds campaign bound"
            return response.status, data
        finally:
            connection.close()

    def checks(self, number):
        status, body = self.request("GET", f"/api/v1/pulls/{number}/checks")
        assert status == 200, (status, body)
        page = json.loads(body)
        assert page["found"] and page["complete"] and page["source_current"], page
        return page

    def stop(self):
        self.stop_file.write_text("operator requested candidate CI and HTTP drain\n", encoding="utf-8")
        code = self.child.wait(timeout=30)
        diagnostic = self.diagnostic.read_bytes()
        if diagnostic:
            sys.stderr.buffer.write(diagnostic)
            sys.stderr.buffer.flush()
        observed = self.rows()
        assert code == 0, (code, self.output.read_bytes(), diagnostic)
        workflow = [row for row in observed if row.get("type") == "workflow_service_drained"]
        transport = [row for row in observed if row.get("type") == "smart_http_drained"]
        assert len(workflow) == len(transport) == 1, observed
        assert observed.index(workflow[0]) < observed.index(transport[0]), observed
        assert workflow[0]["node_closed"] and not workflow[0]["service_failed"], workflow[0]
        assert not workflow[0]["execution_retried"] and not workflow[0]["interrupted"]
        assert not workflow[0]["requires_reconciliation"] and not workflow[0]["publication_pending"]
        assert not workflow[0]["non_green"] and workflow[0]["checks_refused"] == 0
        assert transport[0]["accepted"] == (
            transport[0]["completed_transports"] + transport[0]["refused_transports"]
        ), transport[0]
        assert self.stop_file.is_file(), "service removed the operator's stop control"
        return workflow[0], transport[0]

    def close(self):
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGTERM)
            try:
                self.child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        # Exceptional fixture cleanup is never evidence of the native drain.
        self.close()


def retained_candidate(fixture):
    entries = event_directories(fixture)
    assert len(entries) == 1, entries
    directory = entries[0]
    assert (directory / "settled").is_file() and (directory / "reported").is_file()
    event = json.loads((directory / "event.json").read_bytes())
    assert event["commit"] == fixture.incoming
    assert event["pull_request"]["number"] == "7" and event["pull_request"]["version"] == "1"
    assert event["pull_request"]["execution_profile"] == "exact-admitted-merge-candidate"
    candidate = event["merge_candidate"]
    assert candidate["ref_hex"] == CI_REF.encode().hex()
    assert candidate["commit"] == fixture.candidate and candidate["tree"] == fixture.merged_tree
    assert candidate["parents"] == fixture.parents and candidate["method"] == fixture.method
    assert candidate["principal"] == OWNER and candidate["expected_old"] is None
    assert candidate["bundle_sha256"] == hashlib.sha256((directory / "candidate.bundle").read_bytes()).hexdigest()
    publication = json.loads((directory / "candidate-publication.json").read_bytes())
    assert publication["committed"] and publication["candidate"] == fixture.candidate
    assert publication["publication_key"] == candidate["publication_key"]

    batch = directory / f"dispatch-{event['dispatch_id']}"
    dispatch = json.loads((batch / "report.json").read_bytes())
    assert dispatch["succeeded"] and dispatch["matched_count"] == dispatch["executed_count"] == 1
    plan = dispatch["plan"]
    assert plan["event"] == "pull_request" and plan["source_ref_hex"] == CI_REF.encode().hex()
    assert plan["source_commit"] == fixture.candidate and plan["source_tree"] == fixture.merged_tree
    assert plan["trigger_ref_hex"] == TARGET.encode().hex()
    assert plan["changed_paths"]["after"] == fixture.incoming and plan["changed_paths"]["count"] == 1
    selected = [definition for definition in plan["workflows"] if definition["selected"]]
    assert len(selected) == 1 and selected[0]["path_hex"] == b"ci/build.yml".hex()
    assert len(dispatch["runs"]) == 1
    run = dispatch["runs"][0]
    assert run["executed_commit"] == fixture.candidate and run["executed_tree"] == fixture.merged_tree
    assert run["input_kind"] == "canonical" and run["source_commit"] == fixture.candidate
    assert run["succeeded"] and run["workspaces_closed"]
    assert run["execution"]["jobs"][0]["steps"][0]["stdout_hex"] == b"target\nsource\n".hex()
    return event, selected[0]["graph_sha256"]


def startup_boundaries(fmt):
    fixture = Fixture(fmt, "merge-commit", "http-startup")
    credentials(fixture)
    original, refs = fixture.refs()
    assert refs == {TARGET: fixture.target, SOURCE: fixture.incoming}
    base = arguments(fixture, fixture.root / "startup.stop")
    for flag in ("--expected-incarnation", "--workflow-pull-request", "--workflow-merge-principal"):
        invalid = list(base)
        at = invalid.index(flag)
        del invalid[at:at + 2]
        raw = invoke("http-incomplete-candidate-selection", invalid, 2)
        assert b'"type":"smart_http_listening"' not in raw
        assert not fixture.count() and not event_directories(fixture)
        assert fixture.refs()[0] == original
    record(fixture, "http-candidate-publication-requires-explicit-incarnation-pr-and-writer")

    # A genuinely broken readiness sink must stop the worker before candidate
    # admission as well as before scripts. An existing ordinary controller test
    # only covers source-head execution and cannot establish this ref boundary.
    diagnostic = fixture.root / "broken-readiness.err"
    with open("/dev/full", "wb") as stdout, diagnostic.open("wb") as stderr:
        result = subprocess.run([FG, *map(str, base)], stdout=stdout, stderr=stderr,
                                timeout=45, check=False)
    error = diagnostic.read_bytes()
    if error:
        sys.stderr.buffer.write(error)
        sys.stderr.buffer.flush()
    assert result.returncode == 2, (result.returncode, error)
    assert not fixture.count() and not event_directories(fixture)
    assert fixture.refs()[0] == original and not fixture.excluded.exists()
    record(fixture, "broken-http-readiness-publishes-no-candidate-and-starts-no-script")


def lifecycle(fmt, method):
    fixture = Fixture(fmt, method, "http-lifecycle")
    credentials(fixture)
    with Server(fixture, "service") as server:
        server.ready()
        assert server.request("GET", "/info/refs?service=git-upload-pack", authenticated=False)[0] == 401
        assert server.request("GET", "/info/refs?service=git-receive-pack")[0] == 403
        assert server.request("POST", "/api/v1/source/tree", fields={
            "ref": CI_REF, "object_format": fmt,
        })[0] == 403
        record(fixture, "candidate-service-retains-independent-http-endpoint-grants")
        server.wait(lambda _: len(event_directories(fixture)) == 1 and
                    (event_directories(fixture)[0] / "reported").is_file())
        event, graph = retained_candidate(fixture)
        assert fixture.count() == [b"merged"]
        assert fixture.require_original_refs() == {
            TARGET: fixture.target, SOURCE: fixture.incoming, CI_REF: fixture.candidate,
        }
        source_checks = server.checks(7)
        assert source_checks["source_tip"] == fixture.incoming and not source_checks["checks"]

        # A separate native fixture PR selects the CI branch for the existing
        # canonical check reader. It does not rewrite the actual PR's subject.
        fixture.open_pr(8, CI_REF, fixture.candidate)
        page = server.checks(8)
        assert page["source_ref_hex"] == CI_REF.encode().hex() and page["source_tip"] == fixture.candidate
        assert len(page["checks"]) == 1, page
        check = page["checks"][0]
        assert check["publisher"] == PUBLISHER and check["graph_root"] == graph
        assert check["job"] == "build" and check["conclusion"] == "success"
        assert len(check["evidence_sha256"]) == 64
        status, discovery = server.request("GET", "/info/refs?service=git-upload-pack")
        assert status == 200 and fixture.candidate.encode() in discovery
        workflow, transport = server.stop()
        assert workflow["dispatched"] == 1 and workflow["checks_committed"] == 1, workflow
        assert transport["accepted"] >= 6, transport
    record(fixture, "http-service-prepares-admits-executes-and-reports-exact-candidate",
           candidate=fixture.candidate, parents=fixture.parents, check=check["id"], graph=graph)

    before, refs = fixture.refs()
    with Server(fixture, "restart") as server:
        server.ready()
        assert server.checks(8)["checks"] == page["checks"]
        until = time.monotonic() + 0.5
        while time.monotonic() < until:
            assert server.child.poll() is None, server.diagnostic.read_bytes()
            time.sleep(0.03)
        workflow, _ = server.stop()
        assert workflow["dispatched"] == 0 and workflow["checks_committed"] == 0, workflow
    assert fixture.refs() == (before, refs)
    assert fixture.count() == [b"merged"] and not fixture.excluded.exists()
    assert retained_candidate(fixture) == (event, graph)
    record(fixture, "http-restart-preserves-candidate-check-and-execution-identities-without-replay")


def main():
    assert sys.platform.startswith("linux"), "native candidate workflow service requires Linux"
    assert Path(FG).is_file() and os.access(FG, os.X_OK), "FG_BIN must be a real executable"
    for fmt in ("sha1", "sha256"):
        startup_boundaries(fmt)
        for method in ("merge-commit", "squash"):
            lifecycle(fmt, method)
    (ROOT / "results.json").write_text(json.dumps(RESULTS, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"binary_sha256": hashlib.sha256(Path(FG).read_bytes()).hexdigest(),
                      "results": len(RESULTS), "output": str(ROOT)}), flush=True)


if __name__ == "__main__":
    main()
