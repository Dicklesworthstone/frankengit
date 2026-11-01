#!/usr/bin/env python3
"""Run form-only remote PR commands against native HTTP and canonical Rust reads.

The existing pinned Git sandbox checks the source fixture. Git never supplies
production behavior. Candidate review and reviewed merge are separate profiles.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from typing import Any

from operator_issue_smoke import OperatorCampaign
from pull_request_smoke import fixture, SOURCE, TARGET
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
ORACLE = ROOT / "scripts/e2e/oracle/oracle.sh"
PIN = "git-2.54.0"
TOKEN = "c" * 64
FF_TARGET = "refs/heads/ff-base"


def check_fixture(campaign: OperatorCampaign, oracle_run: Path, source: Path, objects: dict[str, Any]) -> None:
    relative = source.relative_to(oracle_run / "work")
    for label, expected, arguments in [
        ("fsck", 0, ["fsck", "--full", "--strict", "--no-reflogs"]),
        ("ancestor", 0, ["merge-base", "--is-ancestor", objects["base"], objects["source"]]),
        ("diverged", 1, ["merge-base", "--is-ancestor", objects["target"], objects["source"]]),
    ]:
        command = [str(ORACLE), "capture", PIN, str(oracle_run), str(relative), source.parent.name + "-" + label,
                   "--", *arguments]
        stem = source.parent / ("oracle-" + label)
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
        campaign.record(kind="pinned_git_fixture_check", command=command, exit=result.returncode,
                        expected_exit=expected, artifacts=str(stem))
        if result.returncode != expected:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
        require(result.returncode == expected, "pinned sandboxed Git disagreed with fixture integrity/ancestry")


def run_case(campaign: OperatorCampaign, oracle_run: Path, fmt: str) -> None:
    directory = campaign.work / fmt
    directory.mkdir(mode=0o700)
    root, source = directory / "repository", directory / "source"
    objects = fixture(source, fmt)
    (source / FF_TARGET).write_text(objects["base"] + "\n", encoding="ascii")
    check_fixture(campaign, oracle_run, source, objects)
    campaign.facts[f"{fmt}_pinned_git_fixture"] = True
    campaign.run("init", root, TENANT, REPOSITORY, fmt)
    campaign.run("import", root, TENANT, REPOSITORY, PRINCIPAL, "operator-pr-fixture", source)
    credentials, incarnation = campaign.credentials(root, directory)
    header = credentials.read_text().splitlines()[0]

    def grants(scopes: str) -> None:
        pending = directory / "credentials.next"
        with pending.open("x", encoding="ascii") as out:
            out.write(f"{header}\n{hashlib.sha256(TOKEN.encode()).hexdigest()} {PRINCIPAL} {scopes}\n")
        pending.replace(credentials)

    full_grants = "outcomes-read,pulls-read,pulls-write,merges-write"
    grants(full_grants)
    token_path = directory / "token"
    with token_path.open("x", encoding="ascii") as out:
        out.write(TOKEN)
    server = HttpServer(campaign, root, credentials, "pull-" + fmt)
    server.command.append("--allow-outcomes")
    script = ROOT / "scripts/remote_pull.mjs"

    def readback(number: int = 1) -> dict[str, Any]:
        page = json.loads(campaign.run("pr", "show", root, TENANT, REPOSITORY, str(number),
                                      "--trusted-local", "--object-format", fmt))
        require(page["found"] is True and page["node_closed"] is True, "native PR read did not complete")
        return page["pull_request"]

    def comments() -> dict[str, Any]:
        page = json.loads(campaign.run("pr", "comments", root, TENANT, REPOSITORY, "1",
                                      "--trusted-local", "--object-format", fmt))
        require(page["node_closed"] is True, "native comments read did not close")
        return page

    def refs() -> dict[str, str]:
        lines = campaign.run("at", root, TENANT, REPOSITORY, "latest", "refs").decode("ascii").splitlines()
        header = re.fullmatch(r"references at latest \(([0-9]+) total\):", lines[0])
        require(header is not None and int(header[1]) == len(lines) - 1, "incomplete native ref read")
        answer: dict[str, str] = {}
        for line in lines[1:]:
            row = re.fullmatch(r"  (refs/heads/[a-z-]+) -> ([0-9a-f]{" + str(40 if fmt == "sha1" else 64) + r"})", line)
            require(row is not None and row[1] not in answer, "invalid or duplicate native ref row")
            answer[row[1]] = row[2]
        require(list(answer) == sorted(answer), "native ref order changed")
        return answer

    with server:
        scope = {"tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": incarnation,
                 "principal_id": PRINCIPAL, "object_format": fmt}

        def fields(version: int, name: str, target: str = TARGET, tip: str | None = None) -> dict[str, str]:
            return {"expected_version": str(version), "source_ref": SOURCE, "target_ref": target,
                    "source_tip": objects["source"], "target_tip": tip or objects["target"],
                    "title": name, "body": "Native PR operator " + fmt}

        def prepare(name: str, action: str, values: dict[str, str], number: int = 1) -> tuple[Path, str]:
            input_path, slot = directory / (name + ".json"), directory / (name + ".slot")
            with input_path.open("x", encoding="utf-8") as out:
                json.dump({"endpoint": server.url, "scope": scope, "number": str(number),
                           "action": action, "fields": values}, out)
            prepared = campaign.node_command(script, ["prepare", "--input", str(input_path), "--token-file",
                                                     str(token_path), "--request-dir", str(slot)])
            require(prepared["publication_attempted"] is False, "offline prepare claimed publication")
            inspected = campaign.node_command(script, ["inspect", "--request-dir", str(slot)])
            require(inspected["intent"]["key"] == prepared["key"], "inspect changed the saved exact key")
            return slot, prepared["key"]

        def send(slot: Path, key: str, name: str, *, ff: bool = False, expected: int = 0) -> dict[str, Any]:
            return campaign.node_command(script, ["send", "--request-dir", str(slot), "--token-file",
                str(token_path), "--confirm-key", key, "--record", str(directory / (name + ".record")),
                *(["--fast-forward-only"] if ff else [])], expected)

        def recover(slot: Path, name: str, expected: int = 0) -> dict[str, Any]:
            return campaign.node_command(script, ["recover", "--request-dir", str(slot), "--token-file",
                str(token_path), "--record", str(directory / (name + ".record"))], expected)

        def submit(name: str, action: str, values: dict[str, str], number: int = 1,
                   expected: int = 0) -> dict[str, Any]:
            slot, key = prepare(name, action, values, number)
            sent = send(slot, key, name + "-send", ff=action == "fast-forward", expected=expected)
            observed = recover(slot, name + "-recover", expected)
            replay = send(slot, key, name + "-replay", ff=action == "fast-forward", expected=expected)
            for result in (observed, replay):
                require(result["dispatched"] is False and result["outcome"] == sent["outcome"],
                        "original-key lookup/replay changed the decision or dispatched again")
            return sent

        original_refs = refs()
        require(original_refs == {FF_TARGET: objects["base"], TARGET: objects["target"], SOURCE: objects["source"]},
                "native imported refs differ from the checked Git fixture")
        submit("open", "open", fields(0, "Native open"))
        require(readback()["version"] == 1 and readback()["data"]["title"] == "Native open", "native open differs")
        submit("update", "update", fields(1, "Native update"))
        before = readback()
        require(before["version"] == 2 and before["data"]["title"] == "Native update", "native update differs")
        stale = submit("stale-close", "close", fields(1, "Native update"), expected=1)
        require(stale["outcome"]["state"] == "refused" and readback() == before and refs() == original_refs,
                "stale close changed canonical PR or references")
        submit("close", "close", fields(2, "Native update"))
        require(readback()["state"] == "closed" and readback()["version"] == 3, "exact close did not publish")
        submit("reopen", "reopen", fields(3, "Native reopen"))
        before = readback()
        require(before["state"] == "open" and before["version"] == 4, "native reopen differs")
        campaign.facts[f"{fmt}_lifecycle_and_stale_twin"] = True

        submit("comment", "comment", {"expected_version": "0", "body": "native discussion one"})
        first = comments()
        require(first["discussion_version"] == "1" and "native discussion one" in json.dumps(first),
                "comment did not reach the independent native discussion")
        refused = submit("stale-comment", "comment", {"expected_version": "0", "body": "must not appear"}, expected=1)
        require(refused["outcome"]["state"] == "refused" and comments()["comments"] == first["comments"],
                "stale comment changed native conversation")
        submit("current-comment", "comment", {"expected_version": "1", "body": "native discussion two"})
        require(comments()["discussion_version"] == "2" and readback() == before and refs() == original_refs,
                "discussion changed metadata/refs or lost its permitted successor")
        campaign.facts[f"{fmt}_discussion_and_original_recovery"] = True

        slot, key = prepare("independent-outcome", "comment", {"expected_version": "2", "body": "restored outcome grant"})
        before_comments = comments()["comments"]
        grants("pulls-read,pulls-write")
        denied = send(slot, key, "outcome-denied", expected=3)
        require(denied["dispatched"] is False and denied["error"]["status"] == 403
                and comments()["comments"] == before_comments,
                "failed outcome preflight dispatched or changed discussion")
        grants(full_grants)
        permitted = send(slot, key, "outcome-restored")
        require(permitted["outcome"]["state"] == "committed" and comments()["discussion_version"] == "3",
                "restored grant did not permit the original request")
        grants("pulls-read,pulls-write")
        unknown = recover(slot, "outcome-revoked", 3)
        require(unknown["dispatched"] is False and unknown["error"]["status"] == 403,
                "failed recovery resubmitted or hid the denied grant")
        grants(full_grants)
        recovered = recover(slot, "outcome-recovered")
        require(recovered["outcome"] == permitted["outcome"] and recovered["dispatched"] is False,
                "restored read did not recover the original native transaction")
        campaign.facts[f"{fmt}_independent_outcome_grant"] = True

        divergent = {"pull_request_version": "4", "source_ref": SOURCE, "target_ref": TARGET,
                     "source_tip": objects["source"], "target_tip": objects["target"]}
        refused = submit("divergent", "fast-forward", divergent, expected=1)
        require(refused["outcome"]["state"] == "refused" and readback() == before and refs() == original_refs,
                "divergent fast-forward changed PR/refs or selected another merge method")
        submit("ff-open", "open", fields(0, "Fast forward", FF_TARGET, objects["base"]), number=2)
        ff_before = readback(2)
        slot, key = prepare("ff", "fast-forward", {"pull_request_version": "1", "source_ref": SOURCE,
            "target_ref": FF_TARGET, "source_tip": objects["source"], "target_tip": objects["base"]}, number=2)
        grants("outcomes-read,pulls-read,pulls-write")
        denied = send(slot, key, "ff-denied", ff=True, expected=3)
        require(denied["publication"] is None and denied["error"]["status"] == 403
                and readback(2) == ff_before and refs() == original_refs,
                "metadata grant moved code or changed PR state")
        grants(full_grants)
        sent = send(slot, key, "ff-permitted", ff=True)
        require(sent["outcome"]["state"] == "committed" and readback(2)["state"] == "merged",
                "native fast-forward did not atomically mark the PR merged")
        after_refs = refs()
        require(after_refs == {**original_refs, FF_TARGET: objects["source"]},
                "fast-forward changed a different ref, lost a ref or missed the exact source tip")
        require(recover(slot, "ff-recover")["outcome"] == sent["outcome"] and refs() == after_refs,
                "fast-forward recovery changed canonical refs")
        campaign.facts[f"{fmt}_fast_forward_and_code_grant"] = True
    campaign.facts[f"{fmt}_owned_service_drained"] = True
    print(f"OPERATOR_PULL {fmt}: native lifecycle, discussion, fast-forward, recovery, grants and drain", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary", "oracle-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    fg, node = args.fg.resolve(strict=True), args.node.resolve(strict=True)
    require(all(path.is_file() and os.access(path, os.X_OK) for path in (fg, node)), "prebuilt executables required")
    oracle_run = args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle_run / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private work directory required")
    campaign = OperatorCampaign(fg, node, args.work.resolve())
    summary: dict[str, Any] = {"complete": False, "facts": campaign.facts, "binary_sha256": file_sha256(fg),
        "node_sha256": file_sha256(node), "entrypoint": "scripts/remote_pull.mjs", "oracle_pin": PIN,
        "oracle_run": str(oracle_run), "artifacts": str(campaign.work),
        "non_claim": "Six form-only PR actions; not candidate review/reviewed merge, full operator matrix, same-source qualification, TLS or deployment acceptance."}

    def stop(_signum: int, _frame: Any) -> None:
        raise InterruptedError("operator PR campaign interrupted; draining owned children")

    signal.signal(signal.SIGTERM, stop)
    try:
        identity = campaign.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity.get("type") == "js_runtime_identity" and identity.get("corpus_started") is False,
                "runtime probe did not return an identity-only result")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(campaign, oracle_run, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
