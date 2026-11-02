#!/usr/bin/env python3
"""Real HTTP concurrency and fresh-process recovery for additive assignments.

No mocked authority or foreign Git is used. The shared service owner retains
stdout/stderr and requires a graceful stop before returning from each lifetime.
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


def publication(response, action, actor, *, expected_version=None,
                outcome="committed", refusal_code=None):
    """Accept only the canonical typed receipt for this exact request owner."""
    status, raw = response
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(document, dict) or status != (200 if outcome == "committed" else 409):
        return {}
    expected = {"type": "issue_publication", "schema_version": 1,
                "tenant_id": TENANT, "repository_id": REPOSITORY,
                "principal_id": actor, "number": 1, "action": action,
                "expected_version": expected_version, "outcome": outcome,
                "refusal_code": refusal_code, "delivery_acknowledged": None}
    if action == "add-assignees":
        expected["command_profile"] = "issue.add-assignees.v1"
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


def exercise(fg: str, root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    node = root / "node"

    def command(*arguments):
        completed = subprocess.run(
            [fg, *map(str, arguments)], capture_output=True, text=True, timeout=180
        )
        with (root / "commands.jsonl").open("a") as output:
            output.write(json.dumps({"arguments": list(map(str, arguments)),
                                     "exit": completed.returncode,
                                     "stdout": completed.stdout,
                                     "stderr": completed.stderr}) + "\n")
        require(completed.returncode == 0, f"fg {arguments[0]} failed: {completed.stderr}")
        return completed.stdout.strip()

    command("init", node, TENANT, REPOSITORY, "sha1")
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
    assigned = [principal(index) for index in range(100, 108)]
    summary = {"artifacts": str(root)}

    def write(url, action, fields, key, token=admin, number=1):
        return api(url, f"/api/v1/issues/{number}/{action}", token, fields=fields, key=key)

    def addition(url, index):
        return write(url, "add-assignees", [("assignee", assigned[index])],
                     f"independent-assignee-{index}", tokens[index])

    def show(url):
        status, raw = api(url, "/api/v1/issues/1?limit=100", admin)
        require(status == 200, f"issue read failed: {status} {raw}")
        document = json.loads(raw)
        require(document.get("type") == "issue_history" and document.get("schema_version") == 1
                and document.get("tenant_id") == TENANT and document.get("repository_id") == REPOSITORY
                and document.get("object_format") == "sha1" and document.get("found") is True
                and document.get("after_version") == 0 and document.get("limit") == 100
                and "next_after_version" in document and document["next_after_version"] is None,
                "issue history is not a complete canonical observation")
        require(all(isinstance(document.get(field), str) and document[field]
                    for field in ("source_head", "snapshot_token")), "issue history has no source commitment")
        # Preserve the head as well as the issue and events: exact retries must
        # not publish anything, even an authority change hidden from the issue.
        return document

    def issue(document):
        return document["issue"]

    with serve(fg, node, root, credentials, 1) as url:
        opened = write(url, "open", {"expected_version": "0", "title": "Concurrent work",
                                    "body": "Preserve this description", "label": "work"}, "open")
        require(publication(opened, "open", principal(9), expected_version=0), f"open failed: {opened}")
        barrier = threading.Barrier(8)

        def contend(index):
            barrier.wait(timeout=30)
            return addition(url, index)

        with ThreadPoolExecutor(max_workers=8) as pool:
            replies = list(pool.map(contend, range(8)))
        receipts = [publication(reply, "add-assignees", principal(index + 1))
                    for index, reply in enumerate(replies)]
        summary["concurrent_additions"] = sum(bool(receipt) for receipt in receipts)
        summary["typed_profiles"] = all(receipts)
        summary["transactions_unique"] = len({receipt.get("tx_id") for receipt in receipts if receipt}) == 8
        selected = show(url)
        summary["union_exact"] = issue(selected)["assignees"] == sorted(assigned)
        summary["one_event_per_addition"] = issue(selected)["version"] == 9 and len(selected["events"]) == 9
        additions = [event for event in selected["events"] if event["action"]["name"] == "assign"]
        summary["assignment_history_exact"] = (
            len(additions) == 8
            and [event["version"] for event in additions] == list(range(2, 10))
            and {(event["actor"], tuple(event["action"]["assignees"])) for event in additions}
            == {(principal(index + 1), (assigned[index],)) for index in range(8)}
        )
        summary["unrelated_fields_preserved"] = all((
            issue(selected)["title"] == "Concurrent work",
            issue(selected)["body"] == "Preserve this description",
            issue(selected)["labels"] == ["work"],
            issue(selected)["state"] == "open",
            issue(selected)["opened_by"] == principal(9),
            issue(selected)["comments"] == 0,
            issue(selected)["locked"] is False,
            issue(selected)["milestone"] is None,
        ))
        summary["same_server_retries"] = all(addition(url, index) == replies[index] for index in range(8))
        summary["retries_publish_nothing"] = show(url) == selected

        strict = write(url, "assign", {"expected_version": "1", "assignee": principal(190)}, "stale-strict")
        summary["strict_stale_refuses"] = bool(publication(
            strict, "assign", principal(9), expected_version=1, outcome="refused", refusal_code="EvidenceStale"))
        denied = write(url, "add-assignees", {"assignee": principal(191)}, "read-only", tokens[9])
        summary["scope_refuses"] = request_error(denied, 403, "forbidden")
        shaped = write(url, "add-assignees", {"expected_version": "9", "assignee": principal(192)}, "bad-version")
        summary["version_field_refuses"] = request_error(shaped, 400, "unknown_or_inapplicable_field")
        changed = write(url, "add-assignees", {"assignee": principal(193)}, "independent-assignee-0", tokens[0])
        summary["changed_key_refuses"] = request_error(changed, 409, "idempotency_key_reuse")
        after_refusals = show(url)
        summary["refusals_preserve_issue"] = (
            issue(after_refusals) == issue(selected) and after_refusals["events"] == selected["events"])

        # Populate the final union exactly to its existing bound, then prove
        # overflow refusal and overlap acceptance against the same full set.
        fill = [principal(index) for index in range(108, 116)]
        full = sorted(assigned + fill)
        filled_reply = write(url, "add-assignees", [("assignee", value) for value in fill], "fill-bound")
        filled = show(url)
        summary["exact_bound_commits"] = (bool(publication(filled_reply, "add-assignees", principal(9)))
                                          and issue(filled)["assignees"] == full
                                          and issue(filled)["version"] == 10)
        overflow = write(url, "add-assignees", {"assignee": principal(116)}, "over-bound")
        summary["overflow_refuses"] = bool(publication(
            overflow, "add-assignees", principal(9), outcome="refused", refusal_code="ResourceBudgetExceeded"))
        after_overflow = show(url)
        summary["overflow_preserves_issue"] = (
            issue(after_overflow) == issue(filled) and after_overflow["events"] == filled["events"])
        overlap = write(url, "add-assignees", {"assignee": assigned[0]}, "overlap-at-bound")
        before_removal = issue(show(url))
        summary["overlap_at_bound_commits"] = (bool(publication(overlap, "add-assignees", principal(9)))
                                               and before_removal["assignees"] == full
                                               and before_removal["version"] == 11)
        removed = write(url, "unassign", {"expected_version": str(before_removal["version"]),
                                           "assignee": assigned[0]}, "remove-after-add")
        require(publication(removed, "unassign", principal(9), expected_version=before_removal["version"]),
                f"strict removal failed: {removed}")
        retained = show(url)
        summary["removal_exact"] = (issue(retained)["assignees"] == full[1:]
                                     and issue(retained)["version"] == 12)
        summary["old_outcome_does_not_readd"] = addition(url, 0) == replies[0] and show(url) == retained

    with serve(fg, node, root, credentials, 2) as url:
        summary["restart_preserves_state"] = show(url) == retained
        summary["restart_retries_original"] = all(addition(url, index) == replies[index] for index in range(8))
        summary["restart_retries_publish_nothing"] = show(url) == retained
        summary["refused_outcome_survives_restart"] = (
            write(url, "add-assignees", {"assignee": principal(116)}, "over-bound") == overflow
        )
        summary["refused_retry_preserves_state"] = show(url) == retained
        # The earlier overflow remains refused even though one slot is free.
        allowed = write(url, "add-assignees", {"assignee": principal(116)}, "after-removal-new-key")
        final = show(url)
        summary["new_intent_uses_freed_capacity"] = (
            bool(publication(allowed, "add-assignees", principal(9)))
            and issue(final)["assignees"] == sorted(full[1:] + [principal(116)])
            and issue(final)["version"] == 13)
    summary["services_drained"] = True
    return summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    arguments = parser.parse_args()
    result = exercise(str(Path(arguments.fg).resolve()), arguments.root)
    arguments.summary.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    require(result["concurrent_additions"] == 8, "not every independent addition committed")
    require(all(value is True for key, value in result.items()
                if key not in ("artifacts", "concurrent_additions")), "one or more assignment checks failed")


if __name__ == "__main__":
    main()
