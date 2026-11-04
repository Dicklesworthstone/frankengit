#!/usr/bin/env python3
"""Run the actual JS issue CLI against a prebuilt native HTTP service.

Canonical Rust reads, rather than the client's report, establish issue state.
Reuse the existing native campaign's command journal and owned service drain.
No Git subprocess, schema peer, implicit build or production credential is used.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import urlsplit

from scoped_events_smoke import Campaign, HttpServer, PRINCIPAL, REPOSITORY, TENANT, require, file_sha256

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "c" * 64


class OperatorCampaign(Campaign):
    def __init__(self, fg: Path, node: Path, work: Path) -> None:
        super().__init__(fg, work)
        self.node = node
        self.client_serial = 0

    def node_command(self, script: Path, args: list[str], expected: int = 0, *,
                     error_reply: bool = False, timeout: float = 40,
                     json_lines: bool = False, text_reply: bool = False) -> dict[str, Any] | list[dict[str, Any]] | str:
        if json_lines and text_reply:
            raise ValueError("NDJSON and text replies are mutually exclusive")
        if not 0 < timeout <= 40:
            raise ValueError("operator execution timeout must be positive and at most 40 seconds")
        self.client_serial += 1
        stem = self.work / f"operator-{self.client_serial:03d}"
        command = [str(self.node), str(script), *args]
        started = time.monotonic()
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            owner = None
            try:
                owner = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                         start_new_session=os.name == "posix")
                exit_code = owner.wait(timeout=timeout)
            except BaseException as interruption:
                if owner is None:
                    self.record(kind="operator", command=command, spawn_error=type(interruption).__name__,
                                native_effect="unknown", artifacts=str(stem))
                    raise
                # subprocess.run kills its direct child on interruption. That
                # would destroy Node's owner before it drains detached native
                # children. Request TERM and let that existing owner finalize.
                # Repeated operator signals must not interrupt this bounded drain.
                handlers = {}
                shutdown, cleanup_error = "owner_reaped_after_term", None
                try:
                    if threading.current_thread() is threading.main_thread():
                        for number in (signal.SIGTERM, signal.SIGINT):
                            handlers[number] = signal.signal(number, signal.SIG_IGN)
                    if owner.poll() is None:
                        owner.terminate()
                    try:
                        owner.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        shutdown = "forced_owner_termination"
                        owner.kill()
                        owner.wait(timeout=2)
                except BaseException as error:
                    shutdown, cleanup_error = "owner_reap_unresolved", type(error).__name__
                finally:
                    for number, handler in handlers.items():
                        signal.signal(number, handler)
                self.record(kind="operator", command=command, exit=owner.poll(), pid=owner.pid,
                            artifacts=str(stem), interruption=type(interruption).__name__, shutdown=shutdown,
                            cleanup_error=cleanup_error, native_effect="unknown",
                            duration_ms=round((time.monotonic() - started) * 1000))
                if shutdown != "owner_reaped_after_term":
                    # Reaping a forced Node owner says nothing about detached
                    # native work or whether a repository mutation committed.
                    raise RuntimeError(f"operator_owner_containment_failed: {shutdown}; see {stem}") from interruption
                raise
        self.record(kind="operator", command=command, exit=exit_code, artifacts=str(stem))
        if exit_code != expected:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
            raise AssertionError(f"operator exit {exit_code}, expected {expected}; see {stem}")
        raw = stem.with_suffix(".stderr" if error_reply else ".stdout").read_bytes()
        if text_reply:
            return raw.decode("utf-8")
        if json_lines:
            records = [json.loads(line) for line in raw.splitlines()]
            require(bool(records) and all(isinstance(row, dict) for row in records),
                    f"operator NDJSON must contain nonempty object records; see {stem}")
            return records
        return json.loads(raw)


@contextmanager
def issue_server(campaign: OperatorCampaign, root: Path, credentials: Path, fmt: str):
    # Fetch rejects some ports even on loopback. Select only native-owned
    # listeners above the pinned runtime's highest blocked port (10080),
    # before any request. Every discarded listener must drain normally.
    for attempt in range(16):
        server = HttpServer(campaign, root, credentials, f"issue-{fmt}-{attempt}")
        server.command.append("--allow-outcomes")
        with server:
            port = urlsplit(server.url).port
            require(port is not None, "native listener omitted its port")
            if port <= 10080:
                campaign.record(kind="fetch_listener_discarded", port=port, attempt=attempt)
                continue
            yield server
            return
    raise AssertionError("native Fetch-compatible listener selection exhausted its 16-attempt budget")


def forge_case(campaign: OperatorCampaign, server: HttpServer, directory: Path, root: Path,
               fmt: str, token_path: Path, grants, canonical) -> None:
    script = ROOT / "scripts/forge_issues.mjs"
    connection = ["--url", server.url + "/ui/issues/", "--tenant-id", TENANT,
                  "--repository-id", REPOSITORY, "--token-file", str(token_path)]

    def command(operation: str, fields: list[str], expected: int = 0, *,
                error_reply: bool = False) -> dict[str, Any]:
        return campaign.node_command(script, [operation, *connection, *fields], expected,
                                     error_reply=error_reply)

    def submit(action: str, version: int, fields: list[str]) -> dict[str, Any]:
        record = directory / f"forge-{action}.json"
        result = command(action, ["--number", "2", "--expected-version", str(version),
                                  "--record", str(record), *fields])
        require(result["state"] == "terminal_observed" and result["result"]["outcome"] == "committed",
                f"forge {action} did not observe native commitment")
        before, original = canonical("2"), record.read_bytes()
        for operation in ("status", "retry"):
            recovered = command(operation, ["--record", str(record)])
            require(recovered["state"] == "terminal_observed" and recovered["mutation_submitted"] is False
                    and recovered["result"]["tx"] == result["result"]["tx"]
                    and recovered["result"]["rcr"] == result["result"]["rcr"],
                    f"forge {operation} changed or resubmitted {action}")
            require(record.read_bytes() == original and canonical("2") == before,
                    "recovery changed the exact record or canonical state")
        require(before["issue"]["version"] == version + 1, "forge mutation lost its canonical version")
        return before

    page = submit("open", 0, ["--title", "Forge native issue", "--body", f"shipped client {fmt}",
                             "--label", "native", "--label", "operator"])
    require(page["issue"]["body"] == f"shipped client {fmt}"
            and page["issue"]["labels"] == ["native", "operator"], "forge open fields differ in Rust")
    page = submit("comment", 1, ["--body", "forge canonical comment"])
    require("forge canonical comment" in json.dumps(page["events"]), "forge comment is absent in Rust")
    page = submit("edit", 2, ["--title", "Forge native edited", "--body", "forge edited body", "--label", "edited"])
    require(page["issue"]["title"] == "Forge native edited" and page["issue"]["body"] == "forge edited body"
            and page["issue"]["labels"] == ["edited"], "forge edit fields differ in Rust")
    assignee = "44" * 16
    require(submit("assign", 3, ["--assignee", assignee])["issue"]["assignees"] == [assignee],
            "forge assignment differs in Rust")
    require(submit("unassign", 4, ["--assignee", assignee])["issue"]["assignees"] == [],
            "forge unassignment differs in Rust")
    require(submit("close", 5, [])["issue"]["state"] == "closed", "forge close differs in Rust")
    require(submit("reopen", 6, [])["issue"]["state"] == "open", "forge reopen differs in Rust")
    campaign.facts[f"{fmt}_forge_all_actions_and_recovery"] = True

    stale_record = directory / "forge-stale.json"
    before = canonical("2")
    stale = command("comment", ["--number", "2", "--expected-version", "6", "--body", "must not appear",
                                "--record", str(stale_record)], 2, error_reply=True)
    require(stale["code"] == "issue_operator_version_moved" and stale["state"] == "not_submitted"
            and not stale_record.exists() and canonical("2") == before,
            "forge stale preflight created a record or changed canonical state")

    # Denial after receipt sync preserves uncertainty and the exact retry key.
    record = directory / "forge-grant.json"
    grants("issues-read,outcomes-read")
    denied = command("comment", ["--number", "2", "--expected-version", "7", "--body", "restored grant comment",
                                 "--record", str(record)], 2, error_reply=True)
    require(denied["state"] == "submitted_unknown" and denied["http_status"] == 403
            and canonical("2") == before, "denied forge write changed canonical issue state")
    original = record.read_bytes()
    unresolved = command("status", ["--record", str(record)], 2)
    require(unresolved["state"] == "unresolved" and unresolved["mutation_submitted"] is False
            and unresolved["absence_proves_non_commit"] is False and canonical("2") == before,
            "missing forge outcome claimed non-commit or dispatched a mutation")
    grants("issues-read,issues-write,outcomes-read")
    retried = command("retry", ["--record", str(record)])
    require(retried["mutation_submitted"] is True and retried["result"]["outcome"] == "committed"
            and record.read_bytes() == original, "forge retry replaced the original exact receipt")
    page = canonical("2")
    require(page["issue"]["version"] == 8 and "restored grant comment" in json.dumps(page["events"]),
            "permitted forge retry is absent from Rust")
    require(command("status", ["--record", str(record)])["result"]["tx"] == retried["result"]["tx"]
            and canonical("2") == page, "forge recovery changed the permitted retry")
    campaign.facts[f"{fmt}_forge_stale_and_grant_twins"] = True

    listing = command("list", ["--limit", "1", "--max-pages", "2"])
    require(listing["complete"] is True and listing["page_count"] == 2
            and [row["number"] for part in listing["pages"] for row in part["issues"]] == [1, 2],
            "forge list lost native page order")
    history = command("show", ["--number", "2", "--limit", "3"], 4)
    continuation = history["continuation"]
    require(history["complete"] is False and continuation["after"] == 3, "forge history lost its bounded prefix")
    tail = command("show", ["--number", "2", "--limit", "3", "--max-pages", "3", "--after", "3",
                            "--expected-head", continuation["expected_head"]])
    events = [event for part in [*history["pages"], *tail["pages"]] for event in part["events"]]
    # The native CLI repeats the issue number on every event; HTTP binds it
    # through the requested issue and enclosing history row instead.
    require(all(event["number"] == 2 for event in page["events"]), "native history mixed issue numbers")
    native_events = [{key: value for key, value in event.items() if key != "number"} for event in page["events"]]
    require(tail["complete"] is True and events == native_events, "forge history continuation lost native events")
    search = command("search", ["--query", "Forge native", "--label", "edited", "--limit", "1",
                                "--max-scan", "1", "--max-pages", "3"])
    require(search["complete"] is True and [len(part["issues"]) for part in search["pages"]] == [0, 1]
            and search["pages"][-1]["issues"][0] == page["issue"], "forge search lost a zero-hit continuation")
    require(canonical("2") == page, "forge reads changed canonical state")
    campaign.issue(root, fmt, 10, "forge-cursor-successor", "move the repository snapshot")
    retained = command("show", ["--number", "2", "--limit", "100", "--after", "3",
                                "--expected-head", continuation["expected_head"]])
    require(retained["complete"] is True and retained["snapshot_token"] == continuation["expected_head"]
            and retained["pages"][0]["events"] == native_events[3:],
            "ordinary publication changed the retained forge history")
    unknown = command("show", ["--number", "2", "--after", "3", "--expected-head", "alg:2:" + "00" * 32],
                      2, error_reply=True)
    require(unknown["state"] == "read_incomplete" and unknown["http_status"] == 409 and "pages" not in unknown,
            "unknown forge snapshot returned an apparently complete prefix")
    fresh = command("show", ["--number", "2", "--limit", "100"])
    require(fresh["complete"] is True and fresh["pages"][0]["events"] == native_events,
            "fresh forge snapshot did not preserve canonical events")
    campaign.facts[f"{fmt}_forge_retained_reads_and_unknown_pin_refusal"] = True

    # Exercise the existing predecessor-independent assignment intent through
    # the shipped CLI. Keep all prior history/pagination assertions above.
    def metadata_change(action: str, name: str, fields: list[str], version=None):
        record = directory / f"forge-additive-{name}.json"
        arguments = ["--number", "2", "--record", str(record), *fields]
        if version is not None:
            arguments += ["--expected-version", str(version)]
        result = command(action, arguments)
        require(result["state"] == "terminal_observed" and result["result"]["outcome"] == "committed",
                f"forge additive counterpart {name} did not commit")
        return result, record

    a, b, c, d = (value * 16 for value in ("41", "52", "63", "74"))
    metadata_change("assign", "existing", ["--assignee", a], 8)
    metadata_change("close", "close", [], 9)
    metadata_change("lock", "lock", [], 10)
    before = canonical("2")
    added, record = metadata_change("add-assignees", "add", ["--assignee", c, "--assignee", b])
    original = record.read_bytes()
    request = json.loads(original)["receipt"]["request"]
    require(request["action"] == "add-assignees" and request["expected_version"] is None
            and request["fields"] == {"assignees": [b, c]}
            and request["body"] == f"assignee={b}&assignee={c}",
            "additive operator invented a predecessor or changed its exact delta")
    observed = canonical("2")
    require(observed["issue"]["version"] == 12 and observed["issue"]["assignees"] == [a, b, c]
            and {k: v for k, v in observed["issue"].items() if k not in ("version", "assignees")}
            == {k: v for k, v in before["issue"].items() if k not in ("version", "assignees")}
            and observed["issue"]["state"] == "closed" and observed["issue"]["locked"] is True
            and observed["events"][-1]["action"] == {"name": "assign", "assignees": [b, c]},
            "Rust did not retain the additive union and unrelated locked/closed metadata")
    campaign.facts[f"{fmt}_forge_additive_assignees"] = True

    metadata_change("unassign", "remove", ["--assignee", b], 12)
    removed = canonical("2")
    require(removed["issue"]["version"] == 13 and removed["issue"]["assignees"] == [a, c],
            "strict removal did not select its exact Rust predecessor")
    for operation in ("status", "retry"):
        recovered = command(operation, ["--record", str(record)])
        require(recovered["state"] == "terminal_observed" and recovered["mutation_submitted"] is False
                and recovered["result"]["tx"] == added["result"]["tx"]
                and recovered["result"]["rcr"] == added["result"]["rcr"]
                and record.read_bytes() == original and canonical("2") == removed,
                "old additive recovery reapplied a removed assignee or changed its original request")
    campaign.facts[f"{fmt}_forge_additive_recovery"] = True

    denied_record = directory / "forge-additive-grant.json"
    grants("issues-read,outcomes-read")
    denied = command("add-assignees", ["--number", "2", "--assignee", d,
                                       "--record", str(denied_record)], 2, error_reply=True)
    require(denied["state"] == "submitted_unknown" and denied["http_status"] == 403
            and canonical("2") == removed, "denied additive write changed native state")
    saved = denied_record.read_bytes()
    unknown = command("status", ["--record", str(denied_record)], 2)
    require(unknown["state"] == "unresolved" and unknown["mutation_submitted"] is False
            and unknown["absence_proves_non_commit"] is False and canonical("2") == removed,
            "missing additive outcome claimed non-commit or reapplied a request")
    grants("issues-read,issues-write,outcomes-read")
    permitted = command("retry", ["--record", str(denied_record)])
    final = canonical("2")
    require(permitted["mutation_submitted"] is True and permitted["result"]["outcome"] == "committed"
            and denied_record.read_bytes() == saved and final["issue"]["version"] == 14
            and final["issue"]["assignees"] == [a, c, d], "restored grant lost the original additive delta")
    campaign.facts[f"{fmt}_forge_additive_grant_twins"] = True


def run_case(campaign: OperatorCampaign, fmt: str) -> None:
    directory = campaign.work / fmt
    directory.mkdir(mode=0o700)
    root = directory / "repository"
    campaign.run("init", root, TENANT, REPOSITORY, fmt)
    credentials, incarnation = campaign.credentials(root, directory)
    header = credentials.read_text(encoding="utf-8").splitlines()[0]

    def grants(scopes: str) -> None:
        # Publish each complete private table before the next bounded request.
        pending = directory / "credentials.next"
        with pending.open("x", encoding="utf-8") as out:
            out.write(f"{header}\n{hashlib.sha256(TOKEN.encode()).hexdigest()} {PRINCIPAL} {scopes}\n")
        pending.replace(credentials)

    grants("issues-read,issues-write,outcomes-read")
    token_path = directory / "token"
    with token_path.open("x", encoding="ascii") as out:
        out.write(TOKEN)
    script = ROOT / "scripts/remote_issue.mjs"

    def canonical(number: str = "1") -> dict[str, Any]:
        page = json.loads(campaign.run("issue", "show", root, TENANT, REPOSITORY, number,
                                       "--trusted-local", "--object-format", fmt))
        require(page["found"] is True and page["node_closed"] is True, "native canonical issue read incomplete")
        return page

    with issue_server(campaign, root, credentials, fmt) as server:
        scope = {"tenant_id": TENANT, "repository_id": REPOSITORY,
                 "repository_incarnation": incarnation, "principal_id": PRINCIPAL}

        def prepare(name: str, version: int | None, action: str, fields: dict[str, Any]) -> tuple[Path, str]:
            source, slot = directory / f"{name}.json", directory / f"{name}.slot"
            with source.open("x", encoding="utf-8") as out:
                json.dump({"endpoint": server.url, "scope": scope, "number": "1", "action": action,
                           "expected_version": None if version is None else str(version), "fields": fields}, out)
            prepared = campaign.node_command(script, ["prepare", "--input", str(source), "--token-file",
                                                     str(token_path), "--request-dir", str(slot)])
            require(prepared["network_contacted"] is False and prepared["published"] is False,
                    "prepare must not claim native publication")
            return slot, prepared["key"]

        def recover(slot: Path, expected: int = 0) -> dict[str, Any]:
            return campaign.node_command(script, ["recover", "--request-dir", str(slot),
                                                  "--token-file", str(token_path)], expected)

        def send(slot: Path, key: str, expected: int = 0) -> dict[str, Any]:
            return campaign.node_command(script, ["send", "--request-dir", str(slot), "--token-file",
                                                  str(token_path), "--confirm-key", key], expected)

        def submit(name: str, version: int | None, action: str, fields: dict[str, Any],
                   expected: int = 0) -> dict[str, Any]:
            slot, key = prepare(name, version, action, fields)
            sent = send(slot, key, expected)
            recovered = recover(slot, expected)
            require(recovered["dispatched_this_call"] is False, "recovery resubmitted a mutation")
            require(recovered["outcome"]["state"] == sent["outcome"]["state"]
                    and recovered["outcome"]["transaction"] == sent["outcome"]["transaction"],
                    "original-key recovery changed the native transaction")
            return sent

        opened = submit("open", 0, "open", {"title": "Native operator issue", "body": f"opened via JS {fmt}"})
        require(opened["outcome"]["state"] == "committed", "native open did not commit")
        require(canonical()["issue"]["body"] == f"opened via JS {fmt}", "Rust read missed the JS-created issue")
        campaign.issue(root, fmt, 1, "independent-successor", "independent canonical successor")
        before = canonical()
        stale = submit("stale", 1, "comment", {"body": "stale comment must not appear"}, expected=1)
        require(stale["outcome"]["state"] == "refused", "stale predecessor did not receive terminal refusal")
        after = canonical()
        # Publishing the terminal refusal advances the enclosing head; the
        # complete issue state and event history must remain identical.
        changed = {key for key in before.keys() | after.keys() if before.get(key) != after.get(key)}
        require(changed == {"source_head", "snapshot_token"}, "stale refusal changed canonical issue/event state")
        require(after["issue"] == before["issue"] and after["events"] == before["events"], "refused comment leaked")
        submit("current", 2, "comment", {"body": "current permitted comment"})
        current = canonical()
        require(current["issue"]["version"] == 3 and "current permitted comment" in json.dumps(current["events"]),
                "Rust read missed the current-predecessor permitted twin")
        campaign.facts[f"{fmt}_stale_refusal_and_current_twin"] = True

        submit("edit", 3, "edit", {"title": "Edited natively", "body": "edited through the operator"})
        page = canonical()
        require(page["issue"]["version"] == 4 and page["issue"]["title"] == "Edited natively"
                and page["issue"]["body"] == "edited through the operator", "Rust edit readback differs")
        assignee = "44" * 16
        submit("assign", 4, "assign", {"assignees": [assignee]})
        require(canonical()["issue"]["assignees"] == [assignee], "Rust assignment readback differs")
        submit("unassign", 5, "unassign", {"assignees": [assignee]})
        require(canonical()["issue"]["assignees"] == [], "Rust unassignment readback differs")
        submit("close", 6, "close", {})
        require(canonical()["issue"]["state"] == "closed", "Rust close readback differs")
        submit("reopen", 7, "reopen", {})
        require(canonical()["issue"]["state"] == "open", "Rust reopen readback differs")
        submit("append", None, "append-comment", {"body": "explicit predecessor-independent append"})
        page = canonical()
        require(page["issue"]["version"] == 9 and "explicit predecessor-independent append" in json.dumps(page["events"]),
                "Rust append readback differs")
        campaign.facts[f"{fmt}_all_actions_and_original_key_recovery"] = True

        # Native issue-write and outcome-read are independent grants. The
        # client's original-key preflight requires the read grant before send.
        slot, key = prepare("outcome-unavailable", 9, "comment", {"body": "recover with independent outcome read"})
        before = canonical()
        grants("issues-read,issues-write")
        unknown = send(slot, key, expected=3)
        require(unknown["absence_proves_non_commit"] is False, "unavailable outcome claimed non-commit")
        require(unknown["dispatched_this_call"] is False and canonical() == before,
                "failed outcome preflight dispatched or changed canonical state")
        grants("issues-read,issues-write,outcomes-read")
        sent = send(slot, key)
        require(sent["outcome"]["state"] == "committed", "restored grants did not permit the original exact request")
        page = canonical()
        require(page["issue"]["version"] == 10
                and "recover with independent outcome read" in json.dumps(page["events"]),
                "the granted issue write did not reach canonical Rust state")
        grants("issues-read,issues-write")
        unknown = recover(slot, expected=3)
        require(unknown["absence_proves_non_commit"] is False and unknown["dispatched_this_call"] is False,
                "revoked outcome read claimed non-commit or resubmitted")
        require(canonical() == page, "failed outcome recovery changed canonical issue state")
        grants("issues-read,issues-write,outcomes-read")
        recovered = recover(slot)
        require(recovered["dispatched_this_call"] is False and recovered["outcome"]["state"] == "committed",
                "restored outcome grant did not recover the original committed operation")
        require(canonical() == page, "outcome recovery changed canonical issue state")
        campaign.facts[f"{fmt}_independent_outcome_grant"] = True
        forge_case(campaign, server, directory, root, fmt, token_path, grants, canonical)
    campaign.facts[f"{fmt}_owned_service_drained"] = True
    print(f"OPERATOR_ISSUE {fmt}: both real CLI/HTTP/native paths, all supported actions, recovery, retained reads and drain", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--node", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    fg, node = args.fg.resolve(strict=True), args.node.resolve(strict=True)
    require(all(path.is_file() and os.access(path, os.X_OK) for path in (fg, node)), "prebuilt executables required")
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()), "--work must be an empty retained artifact directory")
    require(args.work.stat().st_mode & 0o077 == 0, "operator artifacts must be private")
    campaign = OperatorCampaign(fg, node, args.work.resolve())
    summary: dict[str, Any] = {"complete": False, "facts": campaign.facts,
        "binary_sha256": file_sha256(fg), "node_sha256": file_sha256(node), "artifacts": str(campaign.work),
        "entrypoints": ["scripts/remote_issue.mjs", "scripts/forge_issues.mjs"],
        "non_claim": "Two real issue entrypoints; not every operator, same-source build qualification, browser UI, TLS or D10 acceptance."}

    def stop(_signum: int, _frame: Any) -> None:
        raise InterruptedError("operator campaign interrupted; draining owned children")

    signal.signal(signal.SIGTERM, stop)
    try:
        # The existing verifier owns the sole runtime pin and typed refusal.
        runtime = campaign.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(runtime.get("type") == "js_runtime_identity" and runtime.get("corpus_started") is False,
                "runtime probe did not return its explicit identity-only result")
        summary["node_version"] = runtime["node"]
        for fmt in ("sha1", "sha256"):
            run_case(campaign, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
