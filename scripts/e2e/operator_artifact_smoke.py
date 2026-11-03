"""Native workflow custody -> Rust inspect/export -> shipped JS HTTP download.

Fixed trusted-host fixture bytes only. No artifact store, runner, HTTP peer or
canonical node is substituted; downloaded observations never grant check authority.
"""
from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
from urllib.parse import urlsplit

from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, require

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = b"artifact\0bytes\xff"
BINARY_LOG = b"log\0bytes\xff"


def artifact_case(c, home, repository, config, credentials, incarnation, token, grants, before):
    fmt, artifact_root = config["object_format"], Path(config["artifacts"]["root"])
    copies = home / "artifact-receipts"
    copies.mkdir(mode=0o700)
    originals = sorted(Path(config["run_parent"]).rglob("job-*-artifacts.json"))
    logs = sorted(Path(config["run_parent"]).rglob("job-*-logs.json"))
    require(len(originals) == 1 and len(logs) == 2, "actual native output/log receipts are incomplete")
    saved = {}
    for path in [*originals, *logs]:
        saved[path] = path.read_bytes()
        (copies / path.name).write_bytes(saved[path])
    output = json.loads(saved[originals[0]])
    require(output["manifest"]["job_id_hex"] == b"a_success".hex()
            and len(output["manifest"]["outputs"]) == 1
            and output["manifest"]["outputs"][0]["executable"] is True,
            "native artifact is not the selected executable producer output")
    require((home / "artifact-delivery-verified").read_bytes() == b"verified",
            "dependent failed job did not verify same-attempt bytes and executable mode")
    selections = [(copies / originals[0].name, output, {"path_hex": b"result.bin".hex()}, PAYLOAD)]
    seen_jobs = set()
    for path in logs:
        value = json.loads(saved[path])
        job = bytes.fromhex(value["manifest"]["job_id_hex"]).decode()
        require(job in ["a_success", "b_failure"] and job not in seen_jobs
                and [row["stream"] for row in value["manifest"]["logs"]] == ["stdout", "stderr"],
                "skipped job gained logs or an executed stream disappeared")
        seen_jobs.add(job)
        require(value["manifest"]["observed_job_outcome"] == ("succeeded" if job == "a_success" else "failed"),
                "retained native log promoted failed execution")
        for row in value["manifest"]["logs"]:
            require(row["step_index"] == 0 and row["output_complete"] is True
                    and row["exit_code"] == (0 if job == "a_success" else 7), "native step observation changed")
            expected = (b"workflow-ok" if job == "a_success" else b"workflow-failed") if row["stream"] == "stdout" \
                else BINARY_LOG if job == "a_success" else b""
            selections.append((copies / path.name, value,
                               {"step_index": 0, "stream": row["stream"]}, expected))
    require(len(selections) == 5 and seen_jobs == {"a_success", "b_failure"},
            "one output and four exact executed streams required")
    scope = [artifact_root, TENANT, REPOSITORY, incarnation, "--trusted-local",
             "--trust-domain", "trusted-workflow-local-owner"]

    def selected_row(receipt, selector):
        rows = receipt["manifest"]["logs" if "stream" in selector else "outputs"]
        matches = [row for row in rows if all(row.get(k) == v for k, v in selector.items())]
        require(len(matches) == 1, "artifact selector lost its exact native receipt")
        return matches[0]

    for index, (_, receipt, selector, expected) in enumerate(selections):
        row = selected_row(receipt, selector)
        metadata = json.loads(c.run("artifact", "inspect", *scope, "--id", row["artifact_id_sha256"]))
        require(metadata["type"] == "artifact_custody_result" and metadata["operation"] == "inspect"
                and metadata["payload_verified"] is True and metadata["refs_changed"] is False
                and metadata["artifact_id"] == row["artifact_id_sha256"]
                and metadata["payload_sha256"] == row["payload_sha256"] == hashlib.sha256(expected).hexdigest()
                and metadata["payload_bytes"] == row["payload_bytes"] == len(expected)
                and metadata["repository_incarnation_id"] == incarnation
                and metadata["canonical_repository_published"] is metadata["provenance_authenticated"] is False,
                "native store/receipt differ from independent output or stream bytes")
        exported = home / f"native-artifact-{index}"
        result = json.loads(c.run("artifact", "export", *scope, "--id", row["artifact_id_sha256"], "--output", exported))
        require(result["payload_verified"] is True and exported.read_bytes() == expected,
                "native export lost actual binary/empty stream bytes")
    c.facts[fmt + "_artifact_native_capture_and_delivery"] = True
    cli = ROOT / "scripts/fg_workflow_watch.mjs"
    descriptor = home / "artifact-input.json"

    def download(server, index, destination, expected=0, receipt_override=None):
        path, receipt, selector, _ = selections[index]
        descriptor.write_text(json.dumps({"endpoint": server.url, "scope": {"tenant_id": TENANT,
            "repository_id": REPOSITORY, "repository_incarnation_id": incarnation,
            "trust_domain": "trusted-workflow-local-owner"}, "job_id_hex": receipt["manifest"]["job_id_hex"], **selector}))
        return c.node_command(cli, ["artifact-download", "--input", str(descriptor),
            "--receipt", str(receipt_override or path), "--token-file", str(token), "--output", str(destination)],
            expected, error_reply=expected != 0)

    def refused(server, name):
        row = selected_row(output, selections[0][2])
        url = urlsplit(server.url)
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=10)
        try:
            connection.request("GET", url.path + "/api/v1/artifacts/" + row["artifact_id_sha256"],
                headers={"Authorization": "Bearer " + token.read_text(), "Connection": "close",
                    "User-Agent": "frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)"})
            response = connection.getresponse()
            body = response.read(16385)
            c.record(kind="native_artifact_grant_probe", status=response.status, response_sha256=hashlib.sha256(body).hexdigest())
            require(response.status == 403 and len(body) <= 16384, "native artifact refusal was not HTTP403")
        finally:
            connection.close()
        destination = home / name
        result = download(server, 0, destination, 2)
        require(result["code"] == "artifact_http_refused" and not destination.exists(), "denied JS download published output")

    grants("artifact-read")
    with HttpServer(c, repository, credentials, "operator-artifacts-disabled-" + fmt) as server:
        refused(server, "disabled-artifact")
    server = HttpServer(c, repository, credentials, "operator-artifacts-enabled-" + fmt)
    server.command.extend(["--artifact-root", str(artifact_root), "--expected-incarnation", incarnation])
    with server:
        grants("read")
        refused(server, "denied-artifact")
        grants("artifact-read")
        for index, (_, receipt, selector, expected) in enumerate(selections):
            destination = home / f"downloaded-artifact-{index}"
            result = download(server, index, destination)
            require(destination.read_bytes() == expected == (home / f"native-artifact-{index}").read_bytes()
                    and destination.stat().st_mode & 0o777 == 0o600
                    and result["payload_sha256_verified"] is result["scope_matches_expected"] is True
                    and result["execution_performed"] is result["canonical_repository_published"] is False
                    and result["provenance_authenticated"] is result["job_success_asserted"] is False
                    and result["executable_mode_applied"] is False,
                    "JS download lost exact native bytes/mode or promoted evidence")
            if "stream" in selector:
                require(result["log_observation"]["output_complete"] is True
                        and result["log_observation"]["observed_job_outcome"] == receipt["manifest"]["observed_job_outcome"]
                        and result["log_observation"]["observed_step_outcome"] ==
                        ("succeeded" if receipt["manifest"]["job_id_hex"] == b"a_success".hex() else "failed")
                        and result["log_observation"]["exit_code"] ==
                        (0 if receipt["manifest"]["job_id_hex"] == b"a_success".hex() else 7),
                        "download changed failed or empty stream observation")
            collision = download(server, index, destination, 2)
            require(collision["code"] == "artifact_output_exists" and destination.read_bytes() == expected,
                    "duplicate download changed original output")
        c.facts[fmt + "_artifact_binary_empty_failed_logs"] = True
        wrong = json.loads(json.dumps(output))
        wrong["manifest"]["outputs"][0]["payload_sha256"] = "0" * 64
        wrong_path = copies / "wrong-receipt.json"
        wrong_path.write_text(json.dumps(wrong))
        rejected = home / "wrong-artifact"
        result = download(server, 0, rejected, 2, wrong_path)
        require(result["code"] == "artifact_metadata_mismatch" and not rejected.exists(), "wrong selected bytes acquired output")
        # Revoke after actual successful reads, then re-enable for restart.
        grants("read")
        refused(server, "revoked-artifact")
        grants("artifact-read")
        c.facts[fmt + "_artifact_download_grant_and_ceiling_twins"] = True
    # Restart without original jobs/receipts at their old paths. The client has
    # only exact copied receipts; the server retains its immutable artifact store.
    runs, retained = Path(config["run_parent"]), home / "retained-artifact-runs"
    runs.rename(retained)
    try:
        restarted = HttpServer(c, repository, credentials, "operator-artifacts-restart-" + fmt)
        restarted.command.extend(["--artifact-root", str(artifact_root), "--expected-incarnation", incarnation])
        with restarted:
            destination = home / "restarted-artifact"
            result = download(restarted, 0, destination)
            require(destination.read_bytes() == PAYLOAD and result["artifact_id"] ==
                    output["manifest"]["outputs"][0]["artifact_id_sha256"], "restart replaced the original artifact identity")
    finally:
        retained.rename(runs)
    require(all(path.read_bytes() == data for path, data in saved.items())
            and (home / "executions").read_bytes() == b"sf"
            and c.run("at", repository, TENANT, REPOSITORY, "latest") == before
            and not any(home.glob("*.writing-*")), "artifact reads reran jobs, changed custody/state or leaked staging")
    c.facts[fmt + "_artifact_restart_custody_and_no_reexecution"] = True
