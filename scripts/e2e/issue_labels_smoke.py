#!/usr/bin/env python3
"""Real CLI/HTTP additive labels, bounded concurrency and process recovery.

Uses a persisted native node and the prebuilt product binary. Each service
lifetime retains its output and must drain before the next process starts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from concurrent_writers_smoke import REPOSITORY, TENANT, api, principal, require, serve


def publication(response, action, actor, *, number=1, expected_version=None,
                outcome="committed", refusal_code=None):
    """Validate the canonical typed HTTP receipt for this exact request owner."""
    status, raw = response
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(document, dict) or status != (200 if outcome == "committed" else 409):
        return {}
    expected = {"type": "issue_publication", "schema_version": 1,
                "tenant_id": TENANT, "repository_id": REPOSITORY,
                "principal_id": actor, "number": number, "action": action,
                "expected_version": expected_version, "outcome": outcome,
                "refusal_code": refusal_code, "delivery_acknowledged": None}
    if action == "add-labels":
        expected["command_profile"] = "issue.add-labels.v1"
    elif "command_profile" in document:
        return {}
    if any(field not in document or document[field] != value for field, value in expected.items()):
        return {}
    record = "repository_commit_id" if outcome == "committed" else "refusal_record_id"
    absent = "refusal_record_id" if outcome == "committed" else "repository_commit_id"
    if (not all(isinstance(document.get(field), str) and document[field] for field in ("tx_id", record))
            or absent not in document or document[absent] is not None
            or type(document.get("decision_sequence")) is not int
            or document["decision_sequence"] < 1):
        return {}
    return document


def request_error(response, status, code):
    try:
        document = json.loads(response[1])
    except json.JSONDecodeError:
        return False
    return response[0] == status and document == {
        "type": "issue_error", "schema_version": 1, "code": code, "outcome_unknown": False}


def exercise(fg: str, root: Path, object_format: str) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    node = root / "node"
    summary = {"artifacts": str(root), "object_format": object_format}

    def command(*arguments):
        completed = subprocess.run(
            [fg, *map(str, arguments)], capture_output=True, text=True, timeout=180
        )
        with (root / "commands.jsonl").open("a") as output:
            output.write(json.dumps({"arguments": list(map(str, arguments)),
                                     "exit": completed.returncode,
                                     "stdout": completed.stdout,
                                     "stderr": completed.stderr}) + "\n")
        require(completed.returncode == 0, f"fg {arguments[:2]} failed: {completed.stderr}")
        return completed.stdout.strip()

    command("init", node, TENANT, REPOSITORY, object_format)

    def local(action, *fields, key=None):
        arguments = ["issue", action, node, TENANT, REPOSITORY, "2",
                     "--trusted-local", "--object-format", object_format]
        if key is not None:
            arguments += ["--principal", principal(9), "--idempotency-key", key]
        result = json.loads(command(*arguments, *fields))
        require(result.get("node_closed") is True, "local issue command did not close its node")
        return result

    local("open", "--expected-version", "0", "--title", "CLI labels", "--body", "Keep this body",
          "--label", "existing", key="cli-open")
    cli_labels = ["--label", "triage", "--label", "work"]
    cli_added = local("add-labels", *cli_labels, key="cli-add")
    summary["cli_typed_profile"] = all((
        cli_added.get("type") == "issue_publication",
        cli_added.get("schema_version") == 1,
        cli_added.get("command_profile") == "issue.add-labels.v1",
        "expected_version" in cli_added and cli_added["expected_version"] is None,
        cli_added.get("action") == {"name": "add-labels", "labels": ["triage", "work"]},
        cli_added.get("outcome") == "committed",
        cli_added.get("command_committed") is True,
        cli_added.get("tenant_id") == TENANT,
        cli_added.get("repository_id") == REPOSITORY,
        cli_added.get("principal_id") == principal(9),
        cli_added.get("number") == 2,
        cli_added.get("object_format") == object_format,
        cli_added.get("refs_changed") is False,
        cli_added.get("cleanup_error") is None,
    ))
    cli_selected = local("show", "--limit", "100")
    summary["cli_union_exact"] = (cli_selected["issue"]["labels"] == ["existing", "triage", "work"]
                                  and cli_selected["issue"]["version"] == 2)
    summary["cli_retry_exact"] = local("add-labels", *cli_labels, key="cli-add") == cli_added
    summary["cli_retry_publishes_nothing"] = local("show", "--limit", "100") == cli_selected
    local("edit", "--expected-version", "2", "--label", "existing", key="cli-remove")
    cli_retained = local("show", "--limit", "100")
    summary["cli_removal_exact"] = (cli_retained["issue"]["labels"] == ["existing"]
                                    and cli_retained["issue"]["version"] == 3)
    summary["cli_recovery_does_not_readd"] = (
        local("add-labels", *cli_labels, key="cli-add") == cli_added
        and local("show", "--limit", "100") == cli_retained)

    header = command("serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                     "--trusted-local", "--print-credentials-header")
    tokens = [secrets.token_hex(32) for _ in range(10)]
    credentials = root / "credentials"
    with os.fdopen(os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(header + "\n")
        for index, token in enumerate(tokens):
            scopes = "read,issues-read"
            if index != 9:
                scopes += ",issues-write"
            scopes += ",outcomes-read"
            output.write(f"{hashlib.sha256(token.encode()).hexdigest()} {principal(index + 1)} {scopes}\n")
    admin = tokens[8]
    added_labels = [f"label-{index:02}" for index in range(8)]

    def write(url, action, fields, key, token=admin, number=1):
        return api(url, f"/api/v1/issues/{number}/{action}", token, fields=fields, key=key)

    def addition(url, index):
        return write(url, "add-labels", [("label", added_labels[index]), ("label", "shared")],
                     f"independent-label-{index}", tokens[index])

    def show(url):
        status, raw = api(url, "/api/v1/issues/1?limit=100", admin)
        require(status == 200, f"issue read failed: {status} {raw}")
        document = json.loads(raw)
        require(document.get("type") == "issue_history" and document.get("schema_version") == 1
                and document.get("tenant_id") == TENANT and document.get("repository_id") == REPOSITORY
                and document.get("object_format") == object_format and document.get("found") is True
                and document.get("after_version") == 0 and document.get("limit") == 100
                and "next_after_version" in document and document["next_after_version"] is None,
                "issue history is not a complete canonical observation")
        require(all(isinstance(document.get(field), str) and document[field]
                    for field in ("source_head", "snapshot_token")), "issue history has no source commitment")
        return document

    def issue(document):
        return document["issue"]

    with serve(fg, node, root, credentials, 1) as url:
        opened = write(url, "open", {"expected_version": "0", "title": "Concurrent work",
                                    "body": "Preserve this description", "label": "work"}, "open")
        require(publication(opened, "open", principal(9), expected_version=0), f"open failed: {opened}")
        # Independent edits are retained by every additive request, including
        # state/lock changes that must not prevent label maintenance.
        for version, action, fields in (
                (1, "edit", {"title": "Edited while labels pending"}),
                (2, "close", {}), (3, "lock", {})):
            reply = write(url, action, {"expected_version": str(version), **fields}, f"before-{action}")
            require(publication(reply, action, principal(9), expected_version=version),
                    f"intervening {action} failed: {reply}")
        barrier = threading.Barrier(8)

        def contend(index):
            barrier.wait(timeout=30)
            return addition(url, index)

        with ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(contend, range(8)))
        receipts = [publication(reply, "add-labels", principal(index + 1))
                    for index, reply in enumerate(replies)]
        summary["concurrent_additions"] = sum(bool(receipt) for receipt in receipts)
        summary["typed_profiles"] = all(receipts)
        summary["transactions_unique"] = len({receipt.get("tx_id") for receipt in receipts if receipt}) == 8
        selected = show(url)
        summary["union_exact"] = issue(selected)["labels"] == sorted(added_labels + ["shared", "work"])
        summary["one_event_per_addition"] = issue(selected)["version"] == 12 and len(selected["events"]) == 12
        additions = [event for event in selected["events"] if event["action"]["name"] == "add-labels"]
        summary["label_history_exact"] = (
            len(additions) == 8
            and [event["version"] for event in additions] == list(range(5, 13))
            and {(event["actor"], tuple(event["action"]["labels"])) for event in additions}
            == {(principal(index + 1), (added_labels[index], "shared")) for index in range(8)})
        summary["unrelated_fields_preserved"] = all((
            issue(selected)["title"] == "Edited while labels pending",
            issue(selected)["body"] == "Preserve this description",
            issue(selected)["assignees"] == [],
            issue(selected)["state"] == "closed",
            issue(selected)["opened_by"] == principal(9),
            issue(selected)["comments"] == 0,
            issue(selected)["locked"] is True,
            issue(selected)["milestone"] is None,
        ))
        summary["same_server_retries"] = all(addition(url, index) == replies[index] for index in range(8))
        summary["retries_publish_nothing"] = show(url) == selected

        strict = write(url, "edit", {"expected_version": "1", "label": "replacement"}, "stale-strict")
        summary["strict_stale_refuses"] = bool(publication(
            strict, "edit", principal(9), expected_version=1, outcome="refused", refusal_code="EvidenceStale"))
        denied = write(url, "add-labels", {"label": "forbidden"}, "read-only", tokens[9])
        summary["scope_refuses"] = request_error(denied, 403, "forbidden")
        shaped = write(url, "add-labels", {"expected_version": "12", "label": "unexpected"}, "bad-version")
        summary["version_field_refuses"] = request_error(shaped, 400, "unknown_or_inapplicable_field")
        changed = write(url, "add-labels", {"label": "different"}, "independent-label-0", tokens[0])
        summary["changed_key_refuses"] = request_error(changed, 409, "idempotency_key_reuse")
        missing = write(url, "add-labels", {"label": "absent"}, "missing-issue", number=99)
        summary["missing_issue_refuses"] = bool(publication(
            missing, "add-labels", principal(9), number=99, outcome="refused", refusal_code="EvidenceStale"))
        after_refusals = show(url)
        summary["refusals_preserve_issue"] = (
            issue(after_refusals) == issue(selected) and after_refusals["events"] == selected["events"])

        fill = [f"fill-{index:02}" for index in range(22)]
        full = sorted(added_labels + ["shared", "work"] + fill)
        filled_reply = write(url, "add-labels", [("label", value) for value in fill], "fill-bound")
        filled = show(url)
        summary["exact_bound_commits"] = (bool(publication(filled_reply, "add-labels", principal(9)))
                                          and issue(filled)["labels"] == full
                                          and issue(filled)["version"] == 13)
        overflow = write(url, "add-labels", {"label": "overflow"}, "over-bound")
        summary["overflow_refuses"] = bool(publication(
            overflow, "add-labels", principal(9), outcome="refused", refusal_code="ResourceBudgetExceeded"))
        after_overflow = show(url)
        summary["overflow_preserves_issue"] = (
            issue(after_overflow) == issue(filled) and after_overflow["events"] == filled["events"])
        overlap = write(url, "add-labels", [("label", added_labels[0]), ("label", "shared")], "overlap-at-bound")
        before_removal = issue(show(url))
        summary["overlap_at_bound_commits"] = (bool(publication(overlap, "add-labels", principal(9)))
                                               and before_removal["labels"] == full
                                               and before_removal["version"] == 14)
        remaining = [label for label in full if label != added_labels[0]]
        removed = write(url, "edit", [("expected_version", str(before_removal["version"]))]
                        + [("label", value) for value in remaining], "remove-after-add")
        require(publication(removed, "edit", principal(9), expected_version=before_removal["version"]),
                f"strict removal failed: {removed}")
        retained = show(url)
        summary["removal_exact"] = issue(retained)["labels"] == remaining and issue(retained)["version"] == 15
        summary["old_outcome_does_not_readd"] = addition(url, 0) == replies[0] and show(url) == retained

    with serve(fg, node, root, credentials, 2) as url:
        summary["restart_preserves_state"] = show(url) == retained
        summary["restart_retries_original"] = all(addition(url, index) == replies[index] for index in range(8))
        summary["restart_retries_publish_nothing"] = show(url) == retained
        summary["refused_outcome_survives_restart"] = (
            write(url, "add-labels", {"label": "overflow"}, "over-bound") == overflow)
        summary["refused_retry_preserves_state"] = show(url) == retained
        allowed = write(url, "add-labels", {"label": "overflow"}, "after-removal-new-key")
        final = show(url)
        summary["new_intent_uses_freed_capacity"] = (
            bool(publication(allowed, "add-labels", principal(9)))
            and issue(final)["labels"] == sorted(remaining + ["overflow"])
            and issue(final)["version"] == 16)
    summary["services_drained"] = True
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--object-format", choices=("sha1", "sha256"), required=True)
    arguments = parser.parse_args()
    result = exercise(str(Path(arguments.fg).resolve()), arguments.root, arguments.object_format)
    arguments.summary.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    require(result["concurrent_additions"] == 8, "not every independent addition committed")
    require(all(value is True for key, value in result.items()
                if key not in ("artifacts", "object_format", "concurrent_additions")),
            "one or more label checks failed")


if __name__ == "__main__":
    main()
