#!/usr/bin/env python3
"""Run remote PR commands against native HTTP and canonical Rust reads.

The existing pinned Git sandbox checks the source fixture. Git never supplies
production behavior. Reviews and merges retain exact candidate/principal bounds.
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
REVIEWER, MERGER = "44" * 16, "55" * 16
TOKENS = {PRINCIPAL: TOKEN, REVIEWER: "e" * 64, MERGER: "f" * 64}
FF_TARGET = "refs/heads/ff-base"


def check_fixture(campaign: OperatorCampaign, oracle_run: Path, source: Path, objects: dict[str, Any]) -> None:
    relative = source.relative_to(oracle_run / "work")
    for label, expected, arguments in [
        ("fsck", 0, ["fsck", "--full", "--strict", "--no-reflogs"]),
        ("ancestor", 0, ["merge-base", "--is-ancestor", objects["base"], objects["source"]]),
        ("diverged", 1, ["merge-base", "--is-ancestor", objects["target"], objects["source"]]),
        ("candidate", 0, ["bundle", "verify", "../reviewed.bundle"]),
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
    bundle = directory / "reviewed.bundle"
    bundle.write_bytes(objects["bundle"])
    check_fixture(campaign, oracle_run, source, objects)
    campaign.facts[f"{fmt}_pinned_git_fixture"] = True
    campaign.run("init", root, TENANT, REPOSITORY, fmt)
    campaign.run("import", root, TENANT, REPOSITORY, PRINCIPAL, "operator-pr-fixture", source)
    credentials, incarnation = campaign.credentials(root, directory)
    header = credentials.read_text().splitlines()[0]

    def grants(scopes: str, *, review_scopes: str = "outcomes-read,reviews-read,reviews-write") -> None:
        pending = directory / "credentials.next"
        with pending.open("x", encoding="ascii") as out:
            out.write(header + "\n")
            for principal, allowed in [(PRINCIPAL, scopes), (REVIEWER, review_scopes),
                                       (MERGER, "outcomes-read,merges-write")]:
                out.write(f"{hashlib.sha256(TOKENS[principal].encode()).hexdigest()} {principal} {allowed}\n")
        pending.replace(credentials)

    full_grants = "outcomes-read,pulls-read,pulls-write,merges-write"
    grants(full_grants)
    token_paths = {}
    for principal, token in TOKENS.items():
        path = directory / ("token" if principal == PRINCIPAL else "token-" + principal)
        with path.open("x", encoding="ascii") as out:
            out.write(token)
        token_paths[principal] = path
    token_path = token_paths[PRINCIPAL]
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

        def prepare(name: str, action: str, values: dict[str, Any], number: int = 1, *,
                    principal: str = PRINCIPAL, candidate_bundle: Path | None = None) -> tuple[Path, str]:
            input_path, slot = directory / (name + ".json"), directory / (name + ".slot")
            with input_path.open("x", encoding="utf-8") as out:
                json.dump({"endpoint": server.url, "scope": {**scope, "principal_id": principal}, "number": str(number),
                           "action": action, "fields": values}, out)
            prepared = campaign.node_command(script, ["prepare", "--input", str(input_path), "--token-file",
                                                     str(token_paths[principal]), "--request-dir", str(slot),
                                                     *(["--bundle", str(candidate_bundle)] if candidate_bundle else [])])
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
                "native fast-forward did not report commitment and a merged PR")
        after_refs = refs()
        require(after_refs == {**original_refs, FF_TARGET: objects["source"]},
                "fast-forward changed a different ref, lost a ref or missed the exact source tip")
        require(recover(slot, "ff-recover")["outcome"] == sent["outcome"] and refs() == after_refs,
                "fast-forward recovery changed canonical refs")
        campaign.facts[f"{fmt}_fast_forward_and_code_grant"] = True

        def reviews() -> dict[str, Any]:
            page = json.loads(campaign.run("pr", "reviews", root, TENANT, REPOSITORY, "1",
                                          "--trusted-local", "--object-format", fmt))
            require(page["found"] is True and page["complete"] is True and page["node_closed"] is True,
                    "native review stream is incomplete or did not close")
            return page

        inspected = json.loads(campaign.run("merge", "inspect", root, TENANT, REPOSITORY, TARGET, bundle,
            "--trusted-local", "--source-ref", SOURCE, "--expected-source", objects["source"],
            "--expected-target", objects["target"], "--merge-base", objects["base"],
            "--expected-commit", objects["candidate"]))
        require(inspected["candidate_commit"] == objects["candidate"] and inspected["node_closed"] is True
                and inspected["published_to_repository"] is False and inspected["approval_granted"] is False,
                "native inspection changed or authorized the untrusted candidate")
        initial_reviews = reviews()
        require(initial_reviews["reviews"] == [] and readback() == before and refs() == after_refs,
                "candidate inspection/review read changed canonical state")
        candidate_fields = {"pull_request_version": str(before["version"]),
            "policy_epoch": str(initial_reviews["policy_epoch"]), "source_ref": SOURCE, "target_ref": TARGET,
            "source_tip": objects["source"], "target_tip": objects["target"],
            "merge_base": objects["base"], "candidate_commit": objects["candidate"]}

        def candidate_send(slot: Path, key: str, action: str, principal: str, label: str, expected: int = 0,
                           *, method: str = "merge-commit", known: Path | None = None) -> dict[str, Any]:
            return campaign.node_command(script, ["send", "--request-dir", str(slot), "--token-file",
                str(token_paths[principal]), "--confirm-key", key, "--confirm-candidate", objects["candidate"],
                "--record", str(directory / (label + ".record")),
                *(["--confirm-merge-method", method] if action == "merge" else []),
                *(["--known", str(known)] if known else [])], expected)

        def candidate_submit(name: str, action: str, version: int = 0, *, expected: int = 0,
                             method: str = "merge-commit", lose_bundle: bool = False) -> dict[str, Any]:
            principal = MERGER if action == "merge" else REVIEWER
            values = {**candidate_fields, **({"method": method, "required_reviewers": [REVIEWER]}
                if action == "merge" else {"expected_version": str(version), "reason": "Reviewed exact native candidate"})}
            slot, key = prepare(name, action, values, principal=principal,
                                candidate_bundle=None if action == "withdraw" else bundle)
            sent = candidate_send(slot, key, action, principal, name + "-send", expected, method=method)
            require(sent["outcome"]["state"] == ("refused" if expected else "committed"),
                    "candidate action did not return the expected native terminal")
            if lose_bundle:
                (slot / "candidate.bundle").rename(slot / "candidate.retained-for-evidence")
            observed = campaign.node_command(script, ["recover", "--request-dir", str(slot), "--token-file",
                str(token_paths[principal]), "--record", str(directory / (name + "-recover.record"))], expected)
            replay = candidate_send(slot, key, action, principal, name + "-replay", expected, method=method,
                                    known=directory / (name + "-send.record"))
            for answer in (observed, replay):
                require(answer["dispatched"] is False and answer["outcome"] == sent["outcome"],
                        "candidate recovery/replay uploaded again or changed the original outcome")
            return sent

        def exact_review(decision: str, version: int) -> list[dict[str, Any]]:
            rows = reviews()["reviews"]
            require(len(rows) == 1 and rows[0]["reviewer"] == REVIEWER and rows[0]["decision"] == decision
                    and rows[0]["review_version"] == version and rows[0]["candidate_commit"] == objects["candidate"]
                    and rows[0]["source_tip"] == objects["source"] and rows[0]["target_tip"] == objects["target"]
                    and rows[0]["pull_request_version"] == before["version"]
                    and rows[0]["policy_epoch"] == initial_reviews["policy_epoch"]
                    and rows[0]["merge_base"] == objects["base"] and rows[0]["reviewer_is_opener"] is False,
                    "native review lost its independent principal, predecessor or exact candidate")
            require(readback() == before and refs() == after_refs, "review changed PR metadata or code refs")
            return rows

        candidate_submit("unapproved-merge", "merge", expected=1)
        require(reviews()["reviews"] == [] and readback() == before and refs() == after_refs,
                "missing independent approval changed canonical state")
        approval_values = {**candidate_fields, "expected_version": "0", "reason": "Reviewed exact native candidate"}
        slot, key = prepare("independent-review-grant", "approve", approval_values,
                            principal=REVIEWER, candidate_bundle=bundle)
        grants(full_grants, review_scopes="outcomes-read,reviews-read")
        denied = candidate_send(slot, key, "approve", REVIEWER, "review-grant-denied", 3)
        require(denied["publication"] is None and denied["error"]["status"] == 403
                and reviews()["reviews"] == [] and readback() == before and refs() == after_refs,
                "outcome/read grants published a candidate review")
        grants(full_grants)
        permitted = candidate_send(slot, key, "approve", REVIEWER, "review-grant-restored")
        require(permitted["outcome"]["state"] == "committed", "restored review grant lost the exact original request")
        approved = exact_review("approve", 1)
        campaign.facts[f"{fmt}_independent_review_grant"] = True
        candidate_submit("stale-changes", "request-changes", 0, expected=1)
        require(reviews()["reviews"] == approved, "stale review predecessor replaced the current approval")
        candidate_submit("current-changes", "request-changes", 1)
        exact_review("request-changes", 2)
        candidate_submit("withdraw", "withdraw", 2)
        withdrawn = exact_review("withdraw", 3)
        candidate_submit("withdrawn-merge", "merge", expected=1)
        require(reviews()["reviews"] == withdrawn and readback() == before and refs() == after_refs,
                "withdrawn approval authorized a merge or changed canonical state")
        campaign.facts[f"{fmt}_candidate_review_and_stale_twin"] = True
        candidate_submit("reapprove", "approve", 3, lose_bundle=True)
        approved = exact_review("approve", 4)
        campaign.facts[f"{fmt}_candidate_bundle_recovery"] = True
        candidate_submit("wrong-method", "merge", expected=1, method="squash")
        require(reviews()["reviews"] == approved and readback() == before and refs() == after_refs,
                "wrong merge method substituted a candidate or changed canonical state")
        published = candidate_submit("reviewed-merge", "merge")
        require(published["outcome"]["principal_id"] == MERGER
                and published["publication"]["principal_id"] == MERGER
                and published["publication"]["required_reviewers"] == [REVIEWER]
                and published["publication"]["method"] == "merge-commit",
                "reviewed publication lost its independent submitter, reviewer or selected method")
        merged = readback()
        require(merged["state"] == "merged" and merged["version"] == before["version"] + 1
                and merged["last_metadata_actor"] == before["last_metadata_actor"]
                and merged["opened_by"] == PRINCIPAL and merged["data"] == before["data"]
                and merged["merge"]["commit"] == objects["candidate"],
                "reviewed merge lost its exact candidate, opener or preceding metadata")
        require(refs() == {**after_refs, TARGET: objects["candidate"]} and readback(2)["state"] == "merged",
                "reviewed merge changed a different ref, lost the fast-forward PR or missed the exact candidate")
        campaign.facts[f"{fmt}_reviewed_merge_and_method_twin"] = True
    campaign.facts[f"{fmt}_owned_service_drained"] = True
    print(f"OPERATOR_PULL {fmt}: native lifecycle, discussion, exact reviews/merges, recovery, grants and drain", flush=True)


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
        "non_claim": "Ten PR actions with a merge-commit candidate; not native squash success, full operator matrix, same-source qualification, TLS or deployment acceptance."}

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
