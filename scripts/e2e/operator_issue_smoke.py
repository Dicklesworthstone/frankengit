#!/usr/bin/env python3
"""Run the actual JS issue CLI against a prebuilt native HTTP service.

Canonical Rust reads, rather than the client's report, establish issue state.
Reuse the existing native campaign's command journal and owned service drain.
No Git subprocess, schema peer, implicit build or production credential is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any

from scoped_events_smoke import Campaign, HttpServer, PRINCIPAL, REPOSITORY, TENANT, require, file_sha256

ROOT = Path(__file__).resolve().parents[2]
TOKEN = "c" * 64


class OperatorCampaign(Campaign):
    def __init__(self, fg: Path, node: Path, work: Path) -> None:
        super().__init__(fg, work)
        self.node = node
        self.client_serial = 0

    def node_command(self, script: Path, args: list[str], expected: int = 0) -> dict[str, Any]:
        self.client_serial += 1
        stem = self.work / f"operator-{self.client_serial:03d}"
        command = [str(self.node), str(script), *args]
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                    timeout=40, check=False)
        self.record(kind="operator", command=command, exit=result.returncode, artifacts=str(stem))
        if result.returncode != expected:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
            raise AssertionError(f"operator exit {result.returncode}, expected {expected}; see {stem}")
        return json.loads(stem.with_suffix(".stdout").read_bytes())


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
    server = HttpServer(campaign, root, credentials, f"issue-{fmt}")
    server.command.append("--allow-outcomes")
    script = ROOT / "scripts/remote_issue.mjs"

    def canonical() -> dict[str, Any]:
        page = json.loads(campaign.run("issue", "show", root, TENANT, REPOSITORY, "1",
                                       "--trusted-local", "--object-format", fmt))
        require(page["found"] is True and page["node_closed"] is True, "native canonical issue read incomplete")
        return page

    with server:
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
    campaign.facts[f"{fmt}_owned_service_drained"] = True
    print(f"OPERATOR_ISSUE {fmt}: real CLI/HTTP/native readback, all actions, stale refusal, recovery and drain", flush=True)


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
        "entrypoint": "scripts/remote_issue.mjs",
        "non_claim": "One real operator entrypoint; not every operator, same-source build qualification, browser, TLS or D10 acceptance."}

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
