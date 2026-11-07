"""Native output-loss cases: actual bounded listener, OS pipe and Rust reads.

The two-session listener publishes a real receipt then retires before the
client's confirmation. No response, outcome or canonical state is synthesized.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, require


@contextmanager
def output_sink(destination, blocked: bool):
    if not blocked:
        yield destination, 0
        return
    reader, writer = os.pipe()
    try:
        os.set_blocking(writer, False)
        filled = 0
        while filled <= 1024 * 1024:
            try:
                count = os.write(writer, b" " * 65536)
            except BlockingIOError:
                break
            require(count > 0, "output pipe made no progress")
            filled += count
        require(0 < filled <= 1024 * 1024, "output pipe did not reach bounded real backpressure")
        # The parent holds, but never reads, this pipe. No stream prefetch can
        # consume its bytes before the actual CLI tries to deliver its result.
        yield writer, filled
    finally:
        try:
            os.close(writer)
        finally:
            os.close(reader)


def native_outcome(campaign, root: Path, fmt: str, key: str, state: str):
    campaign.serial += 1
    stem = campaign.work / f"command-{campaign.serial:03d}"
    command = [str(campaign.fg), "outcome", str(root), TENANT, REPOSITORY,
               "--trusted-local", "--object-format", fmt, "--principal", PRINCIPAL,
               "--idempotency-key", key]
    expected_exit = 0 if state == "committed" else 3
    started = time.monotonic()
    with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
        try:
            completed = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       timeout=90, check=False)
        except BaseException as error:
            campaign.record(kind="command", command=command, interruption=type(error).__name__,
                            artifacts=str(stem), expected_exit=expected_exit)
            raise
    campaign.record(kind="command", command=command, exit=completed.returncode,
                    duration_ms=round((time.monotonic() - started) * 1000), artifacts=str(stem),
                    expected_exit=expected_exit)
    if completed.returncode != expected_exit:
        sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
        raise AssertionError(f"native original-key outcome differs; see {stem}")
    result = json.loads(stem.with_suffix(".stdout").read_bytes())
    require(result["type"] == "transaction_outcome" and result["tenant_id"] == TENANT
            and result["repository_id"] == REPOSITORY and result["principal_id"] == PRINCIPAL
            and result["object_format"] == fmt and result["read_only"] is True
            and result["request_reexecuted"] is False and result["node_closed"] is True,
            "native original-key read did not preserve scope/read-only/close boundaries")
    return result


def run_output_cases(campaign, issue_server, canonical, directory: Path, root: Path,
                     credentials: Path, fmt: str, token_path: Path, incarnation: str, script: Path):
    for state in ("committed", "refused"):
        for mode in ("complete", "confirmation", "blocked"):
            name = f"output-{state}-{mode}"
            before = canonical()
            version = before["issue"]["version"]
            require(version > 1, "output refusal twin needs an older positive predecessor")
            expected_version = version if state == "committed" else version - 1
            sessions = 3 if mode == "complete" else 2
            with issue_server(campaign, root, credentials, f"{fmt}-{name}", max_sessions=sessions) as server:
                source, slot = directory / f"{name}.json", directory / f"{name}.slot"
                body = f"native {fmt} {name}"
                with source.open("x", encoding="utf-8") as out:
                    json.dump({"endpoint": server.url, "scope": {"tenant_id": TENANT,
                        "repository_id": REPOSITORY, "repository_incarnation": incarnation,
                        "principal_id": PRINCIPAL}, "number": "1", "action": "comment",
                        "expected_version": str(expected_version), "fields": {"body": body}}, out)
                prepared = campaign.node_command(script, ["prepare", "--input", str(source),
                    "--token-file", str(token_path), "--request-dir", str(slot)])
                original = (slot / "intent.json").read_bytes()
                result = campaign.node_command(script, ["send", "--request-dir", str(slot),
                    "--token-file", str(token_path), "--confirm-key", prepared["key"],
                    "--timeout-ms", "1500"],
                    (0 if state == "committed" else 1) if mode == "complete" else 3,
                    error_reply=mode == "blocked", block_stdout=mode == "blocked")
            values = [json.loads(line) for line in server.stdout_path.read_bytes().splitlines()]
            drains = [value for value in values if value.get("type") == "smart_http_drained"]
            require(len(drains) == 1 and drains[0]["accepted"] == sessions,
                    "bounded native listener admitted an unexpected request count")
            if mode == "complete":
                require(result["type"] == "remote_issue_result" and result["outcome"]["state"] == state,
                        "complete native confirmation twin did not observe its terminal")
            else:
                require(result["type"] == "remote_issue_error" and result["phase"] == "confirmation"
                        and result["dispatched_this_call"] is True and result["outcome_unknown"] is True
                        and result["absence_proves_non_commit"] is False and result["native_result"] is None,
                        "output failure erased native publication evidence or invented confirmation")
                require(result["code"] != "operator_output_cancelled_or_deadline",
                        "output failure replaced the original native command error")
                require((result.get("output_failure") == "operator_output_cancelled_or_deadline")
                        == (mode == "blocked"), "output failure metadata differs from the real sink")
            publication = result["publication"]
            recovered = native_outcome(campaign, root, fmt, prepared["key"], state)
            require(recovered["state"] == state and recovered["terminal"] is True
                    and recovered["transaction"]["tx_id"] == publication["tx_id"]
                    and str(recovered["decision"]["decision_sequence"]) == publication["decision_sequence"],
                    "native original-key transaction/decision differs from the preserved receipt")
            if state == "committed":
                require(recovered["decision"]["repository_commit_id"] == publication["repository_commit_id"],
                        "native RCR differs from the preserved receipt")
            else:
                require(recovered["decision"]["refusal_record_id"] == publication["refusal_record_id"]
                        and recovered["decision"]["code"] == publication["refusal_code"],
                        "native refusal differs from the preserved receipt")
            after = canonical()
            if state == "committed":
                require(after["issue"]["version"] == version + 1
                        and len(after["events"]) == len(before["events"]) + 1
                        and after["events"][-1]["action"] == {"name": "comment", "body": body},
                        "native output case did not commit exactly its original comment")
            else:
                require(after["issue"] == before["issue"] and after["events"] == before["events"],
                        "native refused output case changed issue state/events")
            require((slot / "intent.json").read_bytes() == original,
                    "output/confirmation failure changed original recovery custody")
            require(native_outcome(campaign, root, fmt, prepared["key"], state) == recovered
                    and canonical() == after, "original-key recovery republished or changed native state")
            campaign.facts[f"{fmt}_output_{state}_{mode}"] = True
