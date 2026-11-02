#!/usr/bin/env python3
"""Actual archive/migration CLIs, native HTTP and independent canonical readback.

Requires a prebuilt fg and the repository-pinned Node. Source and destination
are private local native repositories; no response-schema peer or Git is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
from typing import Any

from operator_issue_smoke import OperatorCampaign, ROOT, TOKEN, issue_server
from scoped_events_smoke import TENANT, REPOSITORY, PRINCIPAL, file_sha256, require


def seed(campaign: OperatorCampaign, root: Path, fmt: str) -> None:
    serial = 0

    def mutate(family: str, action: str, number: int, version: int, *fields: Any) -> None:
        nonlocal serial
        serial += 1
        reply = json.loads(campaign.run(
            family, action, root, TENANT, REPOSITORY, number, "--trusted-local",
            "--object-format", fmt, "--principal", PRINCIPAL,
            "--idempotency-key", f"milestone-migration-seed-{serial}",
            "--expected-version", version, *fields,
        ))
        require(reply["command_committed"] is True and reply["node_closed"] is True,
                "source fixture failed canonical publication")

    mutate("milestone", "open", 7, 0, "--title", "Release before edit", "--body", "Release notes", "--due-at", 0)
    mutate("milestone", "edit", 7, 1, "--title", "Release final", "--due-at", 1700000000)
    mutate("milestone", "open", 9, 0, "--title", "Unreferenced open", "--body", "Keep this milestone")
    mutate("milestone", "open", 11, 0, "--title", "Previously assigned", "--body", "Historical membership")
    for number in (1, 2, 3):
        mutate("issue", "open", number, 0, "--title", f"Source issue {number}",
               "--body", f"Original issue {number}\r\n<script>data only</script> 雪", "--label", "native")
    mutate("issue", "comment", 1, 1, "--body", "Source discussion\nwith 🦀")
    mutate("issue", "set-milestone", 1, 2, "--milestone", 7, "--expected-milestone-version", 2)
    mutate("issue", "close", 1, 3)
    mutate("issue", "lock", 1, 4)
    mutate("issue", "set-milestone", 2, 1, "--milestone", 11, "--expected-milestone-version", 1)
    mutate("issue", "clear-milestone", 2, 2)
    mutate("issue", "set-milestone", 3, 1, "--milestone", 7, "--expected-milestone-version", 2)
    mutate("milestone", "close", 7, 2)
    mutate("milestone", "close", 11, 1)


def run_case(campaign: OperatorCampaign, fmt: str) -> None:
    directory = campaign.work / fmt
    directory.mkdir(mode=0o700)
    source, destination = directory / "source", directory / "destination"
    for root in (source, destination):
        campaign.run("init", root, TENANT, REPOSITORY, fmt)
    seed(campaign, source, fmt)

    def connection(server, token: Path) -> list[str]:
        return ["--url", server.url + "/ui/issues/", "--tenant", TENANT,
                "--repository", REPOSITORY, "--token-file", str(token)]

    def credentials(root: Path, name: str, scopes: str) -> tuple[Path, Path]:
        private = directory / name
        private.mkdir(mode=0o700)
        credential, _incarnation = campaign.credentials(root, private)
        header = credential.read_text(encoding="utf-8").splitlines()[0]
        credential.write_text(header + "\n" + hashlib.sha256(TOKEN.encode()).hexdigest()
                              + f" {PRINCIPAL} {scopes}\n", encoding="utf-8")
        token = private / "token"
        token.write_text(TOKEN, encoding="ascii")
        return credential, token

    def canonical(root: Path, family: str, number: int | None = None) -> dict[str, Any]:
        args: list[Any] = [family, "list" if number is None else "show", root, TENANT, REPOSITORY]
        if number is not None:
            args.append(number)
        page = json.loads(campaign.run(*args, "--trusted-local", "--object-format", fmt, "--limit", 100))
        require(page["node_closed"] is True, "canonical read did not close")
        return page

    archive_script = ROOT / "scripts/archive_native_issues.mjs"
    migrate_script = ROOT / "scripts/migrate_native_issues.mjs"
    archive_dir = directory / "archive"
    source_credentials, source_token = credentials(source, "source-auth", "issues-read")
    with issue_server(campaign, source, source_credentials, "source-" + fmt) as server:
        old = campaign.node_command(archive_script, ["export", *connection(server, source_token),
            "--workdir", str(directory / "legacy-refused")], 3, error_reply=True)
        require(old["mutation_submitted"] is False and not (directory / "legacy-refused/archive.json").exists(),
                "legacy archive accepted or dropped milestone semantics")
        exported = campaign.node_command(archive_script, ["export", *connection(server, source_token),
            "--workdir", str(archive_dir), "--page-size", "1", "--include-milestones"])
        require(exported["complete"] is True and exported["issues"] == 3,
                "complete milestone archive did not retain every issue")
    pin = exported["archive_sha256"]
    inspected = campaign.node_command(archive_script, ["inspect", "--workdir", str(archive_dir), "--confirm", pin])
    require(inspected["complete"] is True and inspected["network_accessed"] is False,
            "offline inspection required the stopped source")
    campaign.facts[f"{fmt}_complete_pinned_archive_and_offline_inspection"] = True

    mapping = directory / "milestone-map.json"
    mapping.write_text(json.dumps({"schema": "frankengit-native-milestone-map-v1", "mappings": [
        {"source": 7, "destination": 107}, {"source": 9, "destination": 109},
        {"source": 11, "destination": 111},
    ]}, separators=(",", ":")) + "\n", encoding="utf-8")
    destination_credentials, destination_token = credentials(destination, "destination-auth", "issues-read,issues-write,outcomes-read")
    workdir = directory / "prepared"
    with issue_server(campaign, destination, destination_credentials, "destination-" + fmt) as server:
        common = [*connection(server, destination_token), "--workdir", str(workdir)]
        prepare = ["prepare", *common, "--archive", str(archive_dir), "--archive-sha256", pin, "--offset", "1000"]
        before = canonical(destination, "milestone")
        campaign.node_command(migrate_script, prepare, 2, error_reply=True)
        require(not workdir.exists(), "missing map created runnable custody")
        prepared = campaign.node_command(migrate_script, [*prepare, "--milestone-map", str(mapping)])
        require(canonical(destination, "milestone") == before and prepared["steps"] == 13,
                "offline preparation changed destination state or omitted steps")
        original = {str(path.relative_to(workdir)): file_sha256(path)
                    for path in workdir.rglob("*.request.json")}
        require(len(original) == 13, "not every phase has an original retained request")
        operation = [*common, "--confirm", prepared["plan_sha256"]]
        campaign.node_command(migrate_script, ["inspect", *operation])
        # A prepared migration owns its source package and map. Recovery must
        # remain possible without these external paths or the source server.
        archive_dir.rename(directory / "retained-source-archive")
        mapping.rename(directory / "retained-source-map.json")
        source_token.rename(source_token.with_name("retained-token"))
        partial = campaign.node_command(migrate_script, ["run", *operation, "--max-mutations", "1"], 3)
        require(partial["complete"] is False and partial["mutation_calls"] == 1,
                "whole-migration budget did not stop after its first command")
        require(canonical(destination, "issue")["issues"] == [], "issues started before milestone preparation")
        first = canonical(destination, "milestone")["milestones"]
        require(len(first) == 1 and first[0]["number"] == 107 and first[0]["state"] == "open",
                "source-closed milestone must start open for later membership")
        complete = campaign.node_command(migrate_script, ["run", *operation])
        require(complete["complete"] is True and complete["committed_observed"] == 13,
                "resume did not observe every original command committed")
        saved = {str(path.relative_to(workdir)): file_sha256(path)
                 for path in workdir.rglob("*.request.json")}
        require(saved == original, "resume changed an original request or key")
        campaign.facts[f"{fmt}_original_keys_and_budget_resume"] = True

        milestones = canonical(destination, "milestone")["milestones"]
        require([row["number"] for row in milestones] == [107, 109, 111], "explicit mapping lost unreferenced milestones")
        by_number = {row["number"]: row for row in milestones}
        closed = by_number[107]
        require((closed["title"], closed["due_at"], closed["state"], closed["open_issues"], closed["closed_issues"])
                == ("Release final", 1700000000, "closed", 1, 1), "closed milestone metadata/counts differ")
        require(by_number[109]["state"] == "open" and by_number[111]["state"] == "closed"
                and by_number[111]["open_issues"] == by_number[111]["closed_issues"] == 0,
                "unreferenced and previously assigned milestones were dropped")
        issue = canonical(destination, "issue", 1001)
        require(issue["issue"]["milestone"] == 107 and issue["issue"]["state"] == "closed"
                and issue["issue"]["locked"] is True and issue["issue"]["comments"] == 1,
                "closed/locked issue lost membership or discussion")
        require("Source discussion" in json.dumps(issue["events"]) and pin in issue["issue"]["body"],
                "discussion or source attribution is absent")
        require(canonical(destination, "issue", 1002)["issue"]["milestone"] is None,
                "historically cleared membership was recreated")
        require(canonical(destination, "issue", 1003)["issue"]["milestone"] == 107,
                "open issue membership was not mapped")
        campaign.facts[f"{fmt}_mapped_final_state_and_canonical_counts"] = True
        before_status = canonical(destination, "milestone")
        for name in ("status", "run"):
            recovered = campaign.node_command(migrate_script, [name, *operation])
            require(recovered["complete"] is True and recovered["mutation_calls"] == 0,
                    "completed recovery dispatched another mutation")
        require(canonical(destination, "milestone") == before_status, "completed recovery changed native history")
        campaign.facts[f"{fmt}_terminal_recovery_without_mutation"] = True
    campaign.facts[f"{fmt}_owned_services_drained"] = True
    print(f"NATIVE_MILESTONE_MIGRATION {fmt}: archive, explicit mapping, phased import, resume, canonical readback", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("fg", "node", "work", "summary"):
        parser.add_argument("--" + flag, required=True, type=Path)
    args = parser.parse_args()
    fg, node = args.fg.resolve(strict=True), args.node.resolve(strict=True)
    require(all(path.is_file() and os.access(path, os.X_OK) for path in (fg, node)), "prebuilt executables required")
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0,
            "--work must be an empty private artifact directory")
    campaign = OperatorCampaign(fg, node, args.work.resolve())
    summary: dict[str, Any] = {"complete": False, "facts": campaign.facts,
        "binary_sha256": file_sha256(fg), "node_sha256": file_sha256(node), "artifacts": str(campaign.work),
        "non_claim": "Bounded native issue/milestone data migration; not canonical restore, original audit replay, TLS or power-loss qualification."}

    def stop(_signum: int, _frame: Any) -> None:
        raise InterruptedError("migration campaign interrupted; draining owned services")

    signal.signal(signal.SIGTERM, stop)
    try:
        runtime = campaign.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(runtime.get("type") == "js_runtime_identity" and runtime.get("corpus_started") is False,
                "runtime probe did not return the pinned identity")
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
