#!/usr/bin/env python3
"""Native HTTP serving, real workflow jobs, canonical checks and owned drain.

The listener and its workflow sibling are the actual fg subprocess. Fixtures
use native loose objects; HTTP requests use the standard library. No runner,
authority store, service controller, or transport is substituted. Every wait is
bounded and successful drain is asserted before exceptional fixture cleanup.
"""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlsplit

from workflow_watch_continuous import (
    Campaign, Fixture, PRINCIPAL, REF, REPOSITORY, TENANT, live, read_rows,
)


def credentials(fixture):
    fixture.token = secrets.token_hex(32)
    fixture.credentials = fixture.root / "http-credentials"
    header = f"frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {fixture.incarnation}"
    # This grant deliberately permits receive. The disabled HTTP service flag
    # must still deny it; configuring trusted local CI grants no network scope.
    digest = hashlib.sha256(fixture.token.encode()).hexdigest()
    with os.fdopen(os.open(fixture.credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{digest} {PRINCIPAL} read,receive,pulls-read\n")


def arguments(fixture, stop_file, *, publish=False, attempt=30):
    args = ["serve-http", *fixture.scope, "127.0.0.1:0", "--trusted-local",
            "--credentials-file", fixture.credentials, "--allow-pulls", "--continuous",
            "--stop-file", stop_file, "--max-in-flight", 2,
            "--session-timeout-secs", 10, "--processing-timeout-secs", 30,
            "--workflow-trusted-local", "--workflow-ref", REF, "--workflow-dir", "ci",
            "--workflow-input", "ci", "--workflow-run-parent", fixture.runs,
            "--workflow-format", fixture.format, "--workflow-interval-ms", 100,
            "--workflow-attempt-timeout-secs", attempt,
            "--expected-incarnation", fixture.incarnation]
    if publish:
        args += ["--workflow-publish-checks", "--workflow-principal", PRINCIPAL]
    return args


def event_directories(fixture):
    return sorted(fixture.runs.glob("watch-*/event-*"))


class Server:
    def __init__(self, fixture, label, *, publish=False, attempt=30):
        self.fixture = fixture
        self.stop_file = fixture.root / f"{label}.stop"
        self.output = fixture.root / f"{label}.out"
        self.diagnostic = fixture.root / f"{label}.err"
        self.endpoint = None
        args = arguments(fixture, self.stop_file, publish=publish, attempt=attempt)
        with self.output.open("wb") as stdout, self.diagnostic.open("wb") as stderr:
            self.child = subprocess.Popen(
                [str(fixture.campaign.binary), *map(str, args)], stdout=stdout, stderr=stderr
            )

    def rows(self):
        return read_rows(self.output)

    def wait(self, condition, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            observed = self.rows()
            if condition(observed):
                return observed
            assert self.child.poll() is None, (
                "HTTP workflow service exited early", self.child.returncode,
                self.output.read_bytes(), self.diagnostic.read_bytes(),
            )
            time.sleep(0.03)
        raise AssertionError(("HTTP workflow service wait expired", self.output.read_bytes(),
                              self.diagnostic.read_bytes()))

    def ready(self):
        observed = self.wait(lambda rows: any(row.get("type") == "smart_http_listening" for row in rows))
        ready = next(row for row in observed if row.get("type") == "smart_http_listening")
        assert ready["schema_version"] == 1 and ready["workflow_enabled"] is True
        assert ready["lifetime"] == "continuous" and ready["credential_mode"] == "reloadable"
        assert not ready["receive_enabled"] and not ready["source_enabled"]
        assert ready["pulls_enabled"] and ready["repository_incarnation"] == self.fixture.incarnation
        self.endpoint = urlsplit(ready["url"])
        assert self.endpoint.scheme == "http" and self.endpoint.hostname == "127.0.0.1"
        assert self.endpoint.path == f"/{REPOSITORY}.git"
        return ready

    def request(self, method, route, *, fields=None, authenticated=True):
        assert self.endpoint is not None
        connection = http.client.HTTPConnection(self.endpoint.hostname, self.endpoint.port, timeout=15)
        headers = {"Connection": "close"}
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
            assert len(data) <= 1024 * 1024, "HTTP observation exceeded fixture bound"
            return response.status, data
        finally:
            connection.close()

    def check(self):
        f = self.fixture
        page = None

        def observed(_):
            nonlocal page
            status, body = self.request("GET", f"/api/v1/pulls/{f.current + 1}/checks")
            assert status == 200, (status, body)
            page = json.loads(body)
            assert page["source_current"] and page["source_tip"] == f.tips[f.current], page
            return bool(page["checks"])

        self.wait(observed)
        assert page["complete"] and len(page["checks"]) == 1, page
        check = page["checks"][0]
        assert check["job"] == "a" and check["conclusion"] == "success", check
        assert check["publisher"] == PRINCIPAL and len(check["evidence_sha256"]) == 64
        return check

    def stop(self, code=0):
        self.stop_file.write_text("operator requested HTTP and workflow drain\n")
        return self.finish(code)

    def finish(self, code):
        result = self.child.wait(timeout=30)
        error = self.diagnostic.read_bytes()
        if error:
            sys.stderr.buffer.write(error)
            sys.stderr.buffer.flush()
        observed = self.rows()
        assert result == code, (result, code, self.output.read_bytes(), error)
        workflow = [row for row in observed if row.get("type") == "workflow_service_drained"]
        transport = [row for row in observed if row.get("type") == "smart_http_drained"]
        assert len(workflow) == len(transport) == 1, observed
        assert observed.index(workflow[0]) < observed.index(transport[0]), observed
        assert workflow[0]["node_closed"] and not workflow[0]["service_failed"], workflow[0]
        assert not workflow[0]["execution_retried"]
        assert transport[0]["accepted"] == (
            transport[0]["completed_transports"] + transport[0]["refused_transports"]
        ), transport[0]
        assert self.stop_file.is_file(), "the native service must retain the operator control"
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
        # Exceptional cleanup never counts as proof of the product's drain.
        self.close()


def lifecycle(campaign, fmt):
    fixture = Fixture(campaign, fmt, "http-service")
    credentials(fixture)
    fixture.open_pull()
    check_ids = set()
    with Server(fixture, "service", publish=True, attempt=5) as server:
        server.ready()
        assert server.request("GET", "/info/refs?service=git-upload-pack", authenticated=False)[0] == 401
        assert server.request("GET", "/info/refs?service=git-receive-pack")[0] == 403
        assert server.request("POST", "/api/v1/source/tree", fields={
            "ref": REF, "object_format": fmt,
        })[0] == 403
        campaign.record(fmt, "local-workflow-controller-does-not-enable-source-or-receive")
        for revision in range(3):
            if revision:
                fixture.advance()
                fixture.open_pull()
            check = server.check()
            assert check["id"] not in check_ids
            check_ids.add(check["id"])
            assert fixture.effects_count() == revision + 1
            server.wait(lambda _: len(event_directories(fixture)) == revision + 1 and all(
                (event / "reported").is_file() for event in event_directories(fixture)
            ))
            # The listener still serves useful authenticated Git requests while
            # its sibling observes new canonical changes and publishes checks.
            status, discovery = server.request("GET", "/info/refs?service=git-upload-pack")
            assert status == 200 and fixture.tips[revision].encode() in discovery
            if revision == 0:
                until = time.monotonic() + 5.5
                while time.monotonic() < until:
                    assert server.child.poll() is None, server.diagnostic.read_bytes()
                    time.sleep(0.03)
                assert fixture.effects_count() == 1
        workflow, transport = server.stop()
        assert workflow["dispatched"] == 3 and workflow["checks_committed"] == 3, workflow
        assert workflow["checks_refused"] == 0 and not workflow["non_green"]
        assert not workflow["interrupted"] and not workflow["requires_reconciliation"]
        assert not workflow["publication_pending"] and transport["accepted"] >= 6
    campaign.record(fmt, "one-http-process-serves-and-checks-successive-canonical-sources",
                    executions=3, checks=3, outlived_attempt=True)
    before = fixture.authority()
    with Server(fixture, "restart", publish=True) as server:
        server.ready()
        assert server.check()["id"] in check_ids
        until = time.monotonic() + 0.5
        while time.monotonic() < until:
            assert server.child.poll() is None
            time.sleep(0.03)
        workflow, _ = server.stop()
        assert workflow["dispatched"] == 0 and workflow["checks_committed"] == 0, workflow
        assert not workflow["requires_reconciliation"] and not workflow["publication_pending"]
    assert fixture.effects_count() == 3 and fixture.authority() == before
    campaign.record(fmt, "http-restart-retains-original-execution-and-check-identities")


def active_stop(campaign, fmt):
    fixture = Fixture(campaign, fmt, "http-active", active=True)
    credentials(fixture)
    before = fixture.authority()
    pids = []
    try:
        with Server(fixture, "active") as server:
            server.ready()
            server.wait(lambda _: fixture.pids.exists() and len(fixture.pids.read_text().splitlines()) == 2)
            pids = [int(value) for value in fixture.pids.read_text().splitlines()]
            assert len(set(pids)) == 2 and all(live(pid) for pid in pids)
            assert server.request("GET", "/info/refs?service=git-upload-pack")[0] == 200
            assert all(live(pid) for pid in pids), "HTTP read must finish while the real workflow is active"
            workflow, transport = server.stop(1)
            assert all(not live(pid) for pid in pids), "native HTTP service returned before workflow child drain"
            assert workflow["dispatched"] == 1 and workflow["checks_committed"] == 0
            assert workflow["non_green"] and workflow["interrupted"] and workflow["requires_reconciliation"]
            assert not workflow["publication_pending"] and transport["accepted"] >= 1
        assert fixture.effects_count() == 1 and not fixture.late.exists()
        assert fixture.authority() == before
        campaign.record(fmt, "http-and-active-workflow-drain-before-return", drained_processes=2)
        fixture.advance()
        after_update = fixture.authority()
        refused = campaign.invoke("http-unresolved-restart", arguments(
            fixture, fixture.root / "unresolved.stop",
        ), 2)
        rows = [json.loads(line) for line in refused.splitlines() if line]
        assert not any(row.get("type") == "smart_http_listening" for row in rows)
        for row in rows:
            if row.get("type") == "workflow_service_drained":
                assert row["service_failed"] and row["node_closed"] and row["dispatched"] == 0
        assert fixture.effects_count() == 1 and not fixture.late.exists()
        assert fixture.authority() == after_update
        campaign.record(fmt, "unresolved-workflow-refuses-http-readiness-after-source-update")
    finally:
        for pid in pids:
            if live(pid):
                os.kill(pid, signal.SIGKILL)


def startup_boundaries(campaign, fmt):
    fixture = Fixture(campaign, fmt, "http-startup")
    credentials(fixture)
    before = fixture.authority()
    base = arguments(fixture, fixture.root / "startup.stop", publish=True)
    cases = []
    missing_trust = list(base)
    missing_trust.remove("--workflow-trusted-local")
    cases.append(("http-no-script-trust", missing_trust))
    bounded = list(base)
    bounded.remove("--continuous")
    index = bounded.index("--stop-file")
    del bounded[index:index + 2]
    cases.append(("http-no-owned-continuous-lifetime", bounded))
    missing_publisher = list(base)
    index = missing_publisher.index("--workflow-principal")
    del missing_publisher[index:index + 2]
    cases.append(("http-no-publisher", missing_publisher))
    wrong_format = list(base)
    wrong_format[wrong_format.index("--workflow-format") + 1] = "sha256" if fmt == "sha1" else "sha1"
    cases.append(("http-wrong-workflow-format", wrong_format))
    token_file = fixture.root / "static-token"
    with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as token:
        token.write(fixture.token + "\n")
    static = list(base)
    index = static.index("--credentials-file")
    static[index:index + 2] = ["--token-file", token_file, "--principal", PRINCIPAL]
    cases.append(("http-no-scoped-credentials", static))
    for label, args in cases:
        raw = campaign.invoke(label, args, 2)
        assert b'"type":"smart_http_listening"' not in raw
        assert fixture.effects_count() == 0 and not event_directories(fixture)
    assert fixture.authority() == before
    campaign.record(fmt, "http-workflows-require-separate-script-trust-and-bound-selection", cases=len(cases))
    # Readiness is the activation barrier: a real broken output stream must
    # cause joined startup failure before even the first trusted script runs.
    diagnostic = fixture.root / "broken-readiness.err"
    with open("/dev/full", "wb") as stdout, diagnostic.open("wb") as stderr:
        failed = subprocess.run([str(campaign.binary), *map(str, base)], stdout=stdout,
                                stderr=stderr, timeout=40, check=False)
    assert failed.returncode == 2, (failed.returncode, diagnostic.read_bytes())
    assert fixture.effects_count() == 0 and not event_directories(fixture)
    assert fixture.authority() == before
    campaign.record(fmt, "http-readiness-output-failure-never-starts-workflow-scripts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    assert sys.platform.startswith("linux"), "native workflow service requires Linux"
    output = options.output.resolve() if options.output else Path(tempfile.mkdtemp(prefix="fg-http-workflow-"))
    campaign = Campaign(binary, output)
    for fmt in ("sha1", "sha256"):
        startup_boundaries(campaign, fmt)
        lifecycle(campaign, fmt)
        active_stop(campaign, fmt)
    print(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": len(campaign.results), "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
