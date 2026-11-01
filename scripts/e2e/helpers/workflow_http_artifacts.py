#!/usr/bin/env python3
"""Actual HTTP-owned build/test artifacts, independent reads and restart custody.

All repository operations use the supplied native fg. Fixtures encode native
loose Git objects directly; no Git engine, workflow controller, runner or
artifact store is substituted. Success requires real processes, original checks,
verified HTTP payloads and the native service's completed drain.
"""

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile
import time

from workflow_http_service import Server, arguments, event_directories
from workflow_watch_continuous import (
    Campaign, PRINCIPAL, REF, REPOSITORY, TARGET, TENANT, commit, tree, write_object,
)

PAYLOAD = b"payload\0bytes\xff"
WORKFLOW = "ci/build.yml"


def private_file(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)


class Pipeline:
    def __init__(self, campaign, fmt, case):
        self.campaign, self.format, self.case = campaign, fmt, case
        self.root = campaign.root / f"{fmt}-{case}"
        self.root.mkdir(mode=0o700)
        self.source, self.node = self.root / "source", self.root / "node"
        self.runs, self.artifacts = self.root / "runs", self.root / "artifacts"
        self.runs.mkdir(mode=0o700)
        self.artifacts.mkdir(mode=0o700)
        self.effects, self.consumer = self.root / "effects", self.root / "consumer-started"
        (self.source / "refs/heads").mkdir(parents=True)
        (self.source / "HEAD").write_text(f"ref: {REF}\n", encoding="utf-8")
        (self.source / "config").write_text(
            "[core]\nbare=true\nrepositoryformatversion="
            + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"),
            encoding="utf-8",
        )
        produce = "printf 'payload\\000bytes\\377' > out.bin; chmod +x out.bin"
        if case == "failed-producer":
            produce += "; exit 17"
        elif case == "missing-output":
            produce = "printf 'no selected output\\n'"
        elif case == "oversized-output":
            produce = "head -c 1048577 /dev/zero > out.bin"
        elif case == "delivery-budget":
            produce = "head -c 524289 /dev/zero > out.bin"
        producer = (
            f"printf 'build\\n' >> {shlex.quote(str(self.effects))}; "
            f"printf 'producer-log\\n'; {produce}"
        )
        consumer = (
            f"printf 'started\\n' > {shlex.quote(str(self.consumer))}; "
            "test ! -d ../job-000; test ! -e out.bin; test -x .fgit-artifacts/package.bin; "
            "printf 'payload\\000bytes\\377' > expected.bin; "
            "cmp expected.bin .fgit-artifacts/package.bin; "
            "cp .fgit-artifacts/package.bin tested.bin; "
            f"printf 'test\\n' >> {shlex.quote(str(self.effects))}; printf 'consumer-log\\n'"
        )
        definition = (
            "name: native-http-artifact-pipeline\non: push\njobs:\n"
            "  build:\n    runs-on: fgit-trusted-local\n    steps:\n"
            f"      - run: {producer}\n"
            "  test:\n    needs: build\n    runs-on: fgit-trusted-local\n    steps:\n"
            f"      - run: {consumer}\n"
        )
        blob = write_object(self.source, fmt, "blob", definition.encode())
        ci = write_object(self.source, fmt, "tree", tree([(b"100644", b"build.yml", blob)]))
        root = write_object(self.source, fmt, "tree", tree([(b"40000", b"ci", ci)]))
        self.base = write_object(self.source, fmt, "commit", commit(root, None, 1, b"base\n"))
        self.tip = write_object(self.source, fmt, "commit", commit(root, self.base, 2, b"pipeline\n"))
        (self.source / TARGET).write_text(self.base + "\n", encoding="utf-8")
        (self.source / REF).write_text(self.tip + "\n", encoding="utf-8")
        self.scope = [self.node, TENANT, REPOSITORY]
        campaign.invoke("artifact-init", ["init", *self.scope, fmt])
        campaign.invoke("artifact-import", [
            "import", *self.scope, PRINCIPAL, "http-artifact-pipeline", self.source,
        ])
        header = campaign.invoke("artifact-incarnation", [
            "serve-http", *self.scope, "127.0.0.1:0", "--trusted-local", "--print-credentials-header",
        ]).decode().strip().split()
        assert header[:3] == ["frankengit-http-credentials-v1", TENANT, REPOSITORY]
        assert len(header) == 4 and len(header[3]) == 32, header
        self.incarnation = header[3]
        campaign.invoke("artifact-pr", [
            "pr", "open", *self.scope, 1, "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", "http-artifact-pr", "--expected-version", "0",
            "--source-ref", REF, "--target-ref", TARGET, "--expected-source", self.tip,
            "--expected-target", self.base, "--title", "Artifact pipeline",
            "--body", "Original build/test observations", "--object-format", fmt,
        ])
        # The producer's local execution authorization and HTTP disclosure are
        # independent. The artifact-only token cannot acquire a Git read grant.
        self.token, self.artifact_token = secrets.token_hex(32), secrets.token_hex(32)
        self.credentials = self.root / "http-credentials"
        private_file(self.credentials, self.credential_bytes(True))

    def credential_bytes(self, artifact_reader):
        grants = [(hashlib.sha256(self.token.encode()).hexdigest(), "read,pulls-read")]
        if artifact_reader:
            grants.append((hashlib.sha256(self.artifact_token.encode()).hexdigest(), "artifact-read"))
        header = f"frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {self.incarnation}\n"
        return (header + "".join(f"{digest} {PRINCIPAL} {scopes}\n" for digest, scopes in sorted(grants))).encode()

    def artifact_reader(self, enabled):
        temporary = self.root / "credentials-next"
        private_file(temporary, self.credential_bytes(enabled))
        os.replace(temporary, self.credentials)

    def capture_arguments(self):
        args = [
            "--artifact-root", self.artifacts, "--workflow-artifact-logs",
            "--workflow-artifact", f"{WORKFLOW}:build:out.bin",
            "--workflow-artifact-hex", f"{WORKFLOW.encode().hex()}:test:{b'tested.bin'.hex()}",
            "--workflow-artifact-input-hex",
            f"{WORKFLOW.encode().hex()}:test:build:{b'out.bin'.hex()}:{b'package.bin'.hex()}",
            "--workflow-max-artifact-mib", "1", "--workflow-max-artifact-total-mib", "3",
            "--workflow-max-artifact-input-total-mib", "1",
        ]
        if self.case == "delivery-budget":
            args += ["--workflow-artifact-input", f"{WORKFLOW}:test:build:out.bin:second.bin"]
        return args

    def effects_bytes(self):
        return self.effects.read_bytes() if self.effects.exists() else b""


class ArtifactServer(Server):
    def __init__(self, fixture, label):
        self.fixture = fixture
        self.stop_file = fixture.root / f"{label}.stop"
        self.output, self.diagnostic = fixture.root / f"{label}.out", fixture.root / f"{label}.err"
        self.endpoint = None
        args = arguments(fixture, self.stop_file, publish=True, attempt=30)
        args += fixture.capture_arguments()
        with self.output.open("wb") as stdout, self.diagnostic.open("wb") as stderr:
            self.child = subprocess.Popen(
                [str(fixture.campaign.binary), *map(str, args)], stdout=stdout, stderr=stderr,
            )

    def rows(self):
        assert self.output.stat().st_size <= 4 * 1024 * 1024, "service observation exceeds campaign bound"
        return super().rows()

    def request(self, method, route, *, token=None, authenticated=True):
        assert self.endpoint is not None
        connection = http.client.HTTPConnection(self.endpoint.hostname, self.endpoint.port, timeout=15)
        headers = {
            "Connection": "close",
            "User-Agent": "frankengit-e2e (+https://github.com/Dicklesworthstone/frankengit)",
        }
        if authenticated:
            headers["Authorization"] = "Bearer " + (self.fixture.token if token is None else token)
        try:
            connection.request(method, self.endpoint.path + route, headers=headers)
            response = connection.getresponse()
            data = response.read(2 * 1024 * 1024 + 1)
            assert len(data) <= 2 * 1024 * 1024, "HTTP response exceeds campaign bound"
            return response.status, data
        finally:
            connection.close()

    def checks(self):
        status, body = self.request("GET", "/api/v1/pulls/1/checks")
        assert status == 200, (status, body)
        page = json.loads(body)
        assert page["complete"] and page["source_current"] and page["source_tip"] == self.fixture.tip, page
        return page["checks"]

    def settled(self):
        def complete(_):
            entries = event_directories(self.fixture)
            return len(entries) == 1 and all((entries[0] / name).is_file() for name in ("settled", "reported"))

        self.wait(complete)
        reports = list(self.fixture.runs.glob("watch-*/event-*/dispatch-*/workflow-*/report.json"))
        assert len(reports) == 1, reports
        assert reports[0].stat().st_size <= 2 * 1024 * 1024
        report = json.loads(reports[0].read_bytes())
        assert report["type"] == "trusted_workflow_run" and report["executed_commit"] == self.fixture.tip
        assert report["workspaces_closed"] and not report["request_interrupted"], report
        assert not (reports[0].parent / "job-000").exists()
        assert not (reports[0].parent / "job-001").exists()
        assert not any(path.name.startswith(".job-") for path in reports[0].parent.iterdir())
        return reports[0], report


def download(server, artifact_id, payload):
    fixture = server.fixture
    route = f"/api/v1/artifacts/{artifact_id}"
    status, body = server.request("GET", route, token=fixture.artifact_token)
    assert status == 200, (status, body)
    metadata = json.loads(body)
    assert metadata["artifact_id"] == artifact_id and metadata["payload_verified"], metadata
    assert metadata["payload_bytes"] == len(payload)
    assert metadata["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert metadata["repository_incarnation_id"] == fixture.incarnation
    assert not metadata["canonical_repository_published"] and not metadata["provenance_authenticated"]
    status, actual = server.request("GET", route + "/content", token=fixture.artifact_token)
    assert status == 200 and actual == payload, (status, actual[:256])
    return metadata


def retained(fixture):
    return {
        str(path.relative_to(fixture.runs)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in fixture.runs.rglob("*") if path.is_file() and path.name != "owner.lock"
    }


def pipeline(campaign, fmt):
    fixture = Pipeline(campaign, fmt, "success")
    with ArtifactServer(fixture, "pipeline") as server:
        ready = server.ready()
        assert ready["artifacts_enabled"]
        path, report = server.settled()
        assert report["succeeded"], report
        assert fixture.effects_bytes() == b"build\ntest\n" and fixture.consumer.read_bytes() == b"started\n"
        jobs = {bytes.fromhex(job["job_id_hex"]).decode(): job for job in report["artifacts"]}
        assert set(jobs) == {"build", "test"}, jobs
        output = jobs["build"]["outputs"][0]
        assert output["path_hex"] == b"out.bin".hex() and output["executable"]
        assert output["payload_sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
        artifact_id = output["artifact_id_sha256"]
        assert len(report["artifact_inputs"]) == 1
        delivery = report["artifact_inputs"][0]
        assert delivery["job_id_hex"] == b"test".hex() and len(delivery["inputs"]) == 1
        source = delivery["inputs"][0]
        assert source["producer_job_id_hex"] == b"build".hex()
        assert source["producer_manifest_id_sha256"] == jobs["build"]["manifest_id_sha256"]
        assert source["output"] == output
        assert source["destination_path_hex"] == b".fgit-artifacts/package.bin".hex()
        assert (path.parent / "job-001-artifact-inputs.json").is_file()
        metadata = download(server, artifact_id, PAYLOAD)
        download(server, jobs["test"]["outputs"][0]["artifact_id_sha256"], PAYLOAD)
        logs = {bytes.fromhex(job["job_id_hex"]).decode(): job for job in report["artifact_logs"]}
        stdout = next(log for log in logs["build"]["logs"] if log["stream"] == "stdout")
        assert stdout["output_complete"]
        download(server, stdout["artifact_id_sha256"], b"producer-log\n")
        checks = server.checks()
        assert len(checks) == 2 and {check["job"] for check in checks} == {"build", "test"}, checks
        assert all(check["conclusion"] == "success" and check["publisher"] == PRINCIPAL for check in checks)
        identities = {check["job"]: check["id"] for check in checks}
        route = f"/api/v1/artifacts/{artifact_id}"
        assert server.request("GET", route)[0] == 403
        assert server.request("GET", route + "/content")[0] == 403
        assert server.request("GET", route, authenticated=False)[0] == 401
        assert server.request("GET", "/info/refs?service=git-upload-pack", token=fixture.artifact_token)[0] == 403
        fixture.artifact_reader(False)
        assert server.request("GET", route + "/content", token=fixture.artifact_token)[0] == 401
        fixture.artifact_reader(True)
        assert download(server, artifact_id, PAYLOAD) == metadata
        workflow, _ = server.stop()
        assert workflow["dispatched"] == 1 and workflow["checks_committed"] == 2, workflow
        assert not workflow["requires_reconciliation"] and not workflow["publication_pending"]
        assert not workflow["interrupted"] and not workflow["non_green"] and workflow["checks_refused"] == 0
    original = retained(fixture)
    campaign.record(fmt, "HTTP-ARTIFACT-001-real-producer-consumer-checks-download",
                    artifact_id=artifact_id, payload_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
                    check_ids=identities, independent_scope=True, revocation=True)
    with ArtifactServer(fixture, "restart") as server:
        server.ready()
        assert download(server, artifact_id, PAYLOAD) == metadata
        assert {check["job"]: check["id"] for check in server.checks()} == identities
        until = time.monotonic() + 0.5
        while time.monotonic() < until:
            assert server.child.poll() is None
            time.sleep(0.03)
        workflow, _ = server.stop()
        assert workflow["polls"] >= 1 and workflow["dispatched"] == 0, workflow
        assert workflow["checks_committed"] == 0 and not workflow["publication_pending"]
        assert not workflow["requires_reconciliation"] and not workflow["non_green"]
    assert fixture.effects_bytes() == b"build\ntest\n"
    assert retained(fixture) == original, "restart changed original execution, journal or artifact receipts"
    campaign.record(fmt, "HTTP-ARTIFACT-002-fresh-server-identical-bytes-and-no-script-replay",
                    original_custody_files=len(original), original_check_ids=identities)


def refusals(campaign, fmt):
    for case in ("failed-producer", "missing-output", "oversized-output", "delivery-budget"):
        fixture = Pipeline(campaign, fmt, case)
        with ArtifactServer(fixture, "refused") as server:
            server.ready()
            _, report = server.settled()
            assert not report["succeeded"], report
            assert fixture.effects_bytes() == b"build\n" and not fixture.consumer.exists()
            assert not report["artifact_inputs"], report
            checks = server.checks()
            assert len(checks) == 2 and {check["job"] for check in checks} == {"build", "test"}, checks
            assert all(check["publisher"] == PRINCIPAL for check in checks), checks
            outcomes = {job["id"]: job["outcome"] for job in report["execution"]["jobs"]}
            conclusions = {check["job"]: check["conclusion"] for check in checks}
            consumer = next(job for job in report["execution"]["jobs"] if job["id"] == "test")
            assert not consumer["steps"], consumer
            if case == "delivery-budget":
                assert outcomes == {"build": "succeeded", "test": "refused"}, outcomes
                assert conclusions == {"build": "success", "test": "failure"}, conclusions
                assert len(report["artifacts"]) == 1
            elif case == "failed-producer":
                assert outcomes == {"build": "failed", "test": "skipped"}, outcomes
                assert conclusions == {"build": "failure", "test": "action_required"}, conclusions
                # Failed scripts may retain diagnostic outputs. Custody alone
                # cannot satisfy successful dependency evidence or start a job.
                assert len(report["artifacts"]) == 1
                artifact = report["artifacts"][0]
                assert artifact["job_id_hex"] == b"build".hex()
                download(server, artifact["outputs"][0]["artifact_id_sha256"], PAYLOAD)
            else:
                assert outcomes == {"build": "refused", "test": "skipped"}, outcomes
                assert conclusions == {"build": "failure", "test": "action_required"}, conclusions
                assert not report["artifacts"], report
            workflow, _ = server.stop(1)
            assert workflow["non_green"] and workflow["dispatched"] == 1
            assert workflow["checks_committed"] == 2 and workflow["checks_refused"] == 0
            assert not workflow["requires_reconciliation"] and not workflow["publication_pending"]
        campaign.record(fmt, f"HTTP-ARTIFACT-003-{case}-blocks-consumer-and-false-success",
                        consumer_started=False, original_conclusions={row["job"]: row["conclusion"] for row in checks})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    assert sys.platform.startswith("linux"), "native artifact workflows require Linux"
    output = options.output.resolve() if options.output else Path(tempfile.mkdtemp(prefix="fg-http-artifacts-"))
    campaign = Campaign(binary, output)
    for fmt in ("sha1", "sha256"):
        pipeline(campaign, fmt)
        refusals(campaign, fmt)
    print(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": len(campaign.results), "output": str(output)}), flush=True)


if __name__ == "__main__":
    main()
