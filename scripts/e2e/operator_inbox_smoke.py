"""Shipped inbox operator over native HTTP, checked by separate Rust reads."""
from __future__ import annotations

import json
from pathlib import Path
import stat

from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, require

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/forge_inbox.mjs"


def connection(server, token):
    return ["--kind", "issue", "--url", server.url + "/ui/notifications/",
            "--tenant-id", TENANT, "--repository-id", REPOSITORY,
            "--token-file", str(token)]


def run_inbox_case(c, server, directory, root, fmt, token, incarnation, grants, issue):
    def command(action, fields=(), expected=0, *, error_reply=False):
        return c.node_command(SCRIPT, [action, *connection(server, token), *fields],
                              expected, error_reply=error_reply)

    guards = ["--expected-principal", PRINCIPAL, "--expected-incarnation", incarnation]

    def canonical(number="1", head=None):
        args = ["inbox", "show", root, TENANT, REPOSITORY, number, "--trusted-local",
                "--principal", PRINCIPAL, "--object-format", fmt,
                "--expected-incarnation", incarnation]
        if head is not None:
            args += ["--expected-head", head]
        page = json.loads(c.run(*args))
        require(page["found"] is True and page["node_closed"] is True
                and page["read_only"] is True and len(page["threads"]) == 1,
                "canonical Rust inbox lookup is incomplete")
        return page

    def compare(observed, native):
        row = dict(native["threads"][0])
        for field in ("number", "issue_version", "preference_version", "read_through", "latest_other_version"):
            if row[field] is not None:
                row[field] = int(row[field])
        # Native CLI exposes the canonical enum; HTTP names its automatic mode.
        row["mode"] = {"participating": "automatic", "subscribed": "subscribed", "muted": "muted"}[row["mode"]]
        page = observed["pages"][0]
        require(observed["complete"] is True and observed["read_only"] is True
                and observed["mutation_submitted"] is False and page["found"] is True
                and page["thread"] == row and observed["snapshot_token"] == native["snapshot_token"]
                and observed["principal_id"] == native["principal_id"] == PRINCIPAL
                and observed["repository_incarnation"] == native["repository_incarnation"] == incarnation
                and page["source_positions"] == {
                    "authority_head_generation": int(native["source_generation"]),
                    "forge_position_root": native["forge_position_root"],
                    "outbox_root": native["outbox_root"], "complete": True},
                "inbox operator disagrees with independent canonical Rust read")

    grants("issues-read,issues-write,outcomes-read,notifications-write")
    version = issue()["issue"]["version"]
    c.run("issue", "comment", root, TENANT, REPOSITORY, "1", "--trusted-local",
          "--object-format", fmt, "--principal", "44" * 16,
          "--idempotency-key", "inbox-other-activity", "--expected-version", version,
          "--body", "Activity by another authenticated fixture actor")
    native = canonical()
    require(native["threads"][0]["unread"] is True
            and int(native["threads"][0]["latest_other_version"]) == version + 1,
            "foreign issue activity did not produce canonical unread state")
    prefix = version + 1
    compare(command("show", ["--number", "1"]), native)
    first = command("list", ["--limit", "1"], 4)
    continuation = first["continuation"]
    require(first["complete"] is False and continuation["after"] == 1
            and continuation["expected_principal"] == PRINCIPAL
            and continuation["expected_incarnation"] == incarnation,
            "bounded inbox read lost its recipient-bound continuation")
    retained = canonical(head=continuation["expected_head"])

    # Newer activity must stay unread when only the earlier observed prefix is acknowledged.
    c.run("issue", "comment", root, TENANT, REPOSITORY, "1", "--trusted-local",
          "--object-format", fmt, "--principal", "44" * 16,
          "--idempotency-key", "inbox-newer-activity", "--expected-version", prefix,
          "--body", "Newer activity must remain unread")
    original_issue = issue()
    records = []
    for expected, action in enumerate(("subscribe", "mute", "automatic", "read", "unread")):
        path = directory / f"inbox-{action}.json"
        fields = ["--number", "1", "--expected-version", str(expected),
                  *guards, "--record", str(path)]
        if action == "read":
            fields += ["--read-through", str(prefix)]
        result = command(action, fields)
        require(result["state"] == "terminal_observed" and result["mutation_submitted"] is True
                and result["result"]["outcome"] == "committed", "inbox action did not canonically commit")
        native = canonical()
        row = native["threads"][0]
        require(int(row["preference_version"]) == expected + 1
                and row["mode"] == ("subscribed" if action == "subscribe" else "muted" if action == "mute" else "participating")
                and row["read_through"] == (str(prefix) if action == "read" else None)
                and row["unread"] is True, "inbox action changed mode, prefix or newer unread activity")
        compare(command("show", ["--number", "1"]), native)
        observed_issue = issue()
        require(observed_issue["issue"] == original_issue["issue"] and observed_issue["events"] == original_issue["events"],
                "inbox preference changed canonical issue content/history")
        data = path.read_bytes()
        require(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
                and token.read_bytes() not in data, "inbox custody is not private and token-free")
        records.append((path, data, result["result"]))
    before = canonical()
    for path, data, terminal in records:
        for operation in ("status", "retry"):
            result = command(operation, ["--record", str(path)])
            require(result["state"] == "terminal_observed" and result["mutation_submitted"] is False
                    and result["result"] == {"terminal": True, **terminal}
                    and path.read_bytes() == data and canonical() == before,
                    "old inbox recovery reapplied a superseded preference or changed custody")
    c.facts[f"{fmt}_inbox_actions_prefix_and_original_recovery"] = True

    tail = command("list", ["--limit", "1", "--after", str(continuation["after"]),
                            "--expected-head", continuation["expected_head"], *guards])
    require(tail["complete"] is True and tail["snapshot_token"] == continuation["expected_head"]
            and [row["number"] for page in tail["pages"] for row in page["threads"]] == [2],
            "inbox continuation silently refreshed its snapshot or lost the next thread")
    compare(command("show", ["--number", "1", "--expected-head", continuation["expected_head"], *guards]), retained)
    require(canonical() == before, "retained inbox read changed current canonical preference")
    c.facts[f"{fmt}_inbox_retained_reads_and_canonical_state"] = True

    for label, fields, code in (
        ("stale", ["--expected-version", "0", *guards], "inbox_operator_preference_moved"),
        ("identity", ["--expected-version", "5", "--expected-principal", "55" * 16,
                      "--expected-incarnation", incarnation], "inbox_operator_identity_changed"),
    ):
        path = directory / f"inbox-{label}.json"
        result = command("subscribe", ["--number", "1", "--record", str(path), *fields], 2, error_reply=True)
        require(result["code"] == code and result["state"] == "not_submitted"
                and not path.exists() and canonical() == before, "inbox preflight refusal created custody or state")
    c.facts[f"{fmt}_inbox_stale_and_identity_refusals"] = True

    path = directory / "inbox-denied.json"
    grants("issues-read,outcomes-read")
    denied = command("subscribe", ["--number", "1", "--expected-version", "5", *guards,
                                   "--record", str(path)], 2, error_reply=True)
    require(denied["state"] == "submitted_unknown" and denied["http_status"] == 403
            and canonical() == before, "missing notification-write grant changed native preference")
    data = path.read_bytes()
    unknown = command("status", ["--record", str(path)], 2)
    require(unknown["state"] == "unresolved" and unknown["mutation_submitted"] is False
            and unknown["absence_proves_non_commit"] is False and canonical() == before,
            "absent inbox outcome claimed non-commit or dispatched a preference")
    grants("issues-read,issues-write,outcomes-read,notifications-write")
    allowed = command("retry", ["--record", str(path)])
    final = canonical()
    require(allowed["mutation_submitted"] is True and allowed["result"]["outcome"] == "committed"
            and final["threads"][0]["preference_version"] == "6"
            and final["threads"][0]["mode"] == "subscribed" and path.read_bytes() == data,
            "restored grant failed the exact retained inbox request")
    compare(command("show", ["--number", "1"]), final)
    observed_issue = issue()
    require(observed_issue["issue"] == original_issue["issue"] and observed_issue["events"] == original_issue["events"],
            "inbox grant/recovery twins changed issue state")
    c.facts[f"{fmt}_inbox_independent_grant_twins"] = True

    path = directory / "inbox-current-prefix.json"
    fields = ["--number", "1", "--expected-version", "6", *guards, "--record", str(path)]
    future = command("read", [*fields, "--read-through", str(prefix + 2)], 2, error_reply=True)
    require(future["code"] == "inbox_operator_read_prefix_unobserved"
            and future["state"] == "not_submitted" and not path.exists() and canonical() == final,
            "unobserved inbox prefix created custody or changed canonical state")
    read = command("read", [*fields, "--read-through", str(prefix + 1)])
    data = path.read_bytes()
    observed = canonical()
    row = observed["threads"][0]
    require(read["result"]["outcome"] == "committed" and row["preference_version"] == "7"
            and row["mode"] == "subscribed" and row["read_through"] == str(prefix + 1)
            and row["unread"] is False, "complete observed prefix did not clear native unread state")
    compare(command("show", ["--number", "1"]), observed)
    unread = command("unread", ["--number", "1", "--expected-version", "7", *guards,
                               "--record", str(directory / "inbox-clear-prefix.json")])
    cleared = canonical()
    row = cleared["threads"][0]
    require(unread["result"]["outcome"] == "committed" and row["preference_version"] == "8"
            and row["mode"] == "subscribed" and row["read_through"] is None and row["unread"] is True,
            "explicit unread failed to clear the native prefix while preserving subscription")
    recovered = command("retry", ["--record", str(path)])
    require(recovered["mutation_submitted"] is False
            and recovered["result"] == {"terminal": True, **read["result"]}
            and path.read_bytes() == data and canonical() == cleared,
            "old full-prefix recovery marked a later explicit unread preference as read")
    compare(command("show", ["--number", "1"]), cleared)
    observed_issue = issue()
    require(observed_issue["issue"] == original_issue["issue"] and observed_issue["events"] == original_issue["events"],
            "read/unread preference toggles changed canonical issue content/history")
    c.facts[f"{fmt}_inbox_prefix_bounds_and_read_toggle"] = True


def missing_inbox_service(c, server, root, token, fmt):
    before = c.run("at", root, TENANT, REPOSITORY, "latest")
    denied = c.node_command(SCRIPT, ["list", *connection(server, token)], 2, error_reply=True)
    require(denied["state"] == "read_incomplete" and denied["operation_completed"] is False
            and denied["http_status"] == 403 and denied["record"] is None
            and denied["absence_proves_non_commit"] is False
            and c.run("at", root, TENANT, REPOSITORY, "latest") == before,
            "missing native inbox route was accepted as a complete observation")
    c.facts[f"{fmt}_inbox_missing_native_service_refusal"] = True
