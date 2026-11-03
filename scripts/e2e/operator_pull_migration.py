#!/usr/bin/env python3
"""Native PR portability through shipped CLIs and separate canonical Rust reads.

Reuse the existing command/process owners and pinned Git fixture oracle. Source
reviews are attributed comments at the destination, never imported approvals.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import signal
import traceback
from urllib.parse import urlsplit

from operator_issue_smoke import OperatorCampaign, ROOT, TOKEN
from operator_pull_smoke import check_fixture, PIN
from pull_request_smoke import fixture, SOURCE, TARGET
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

SOURCE_ACTOR, REVIEWER = "44" * 16, "55" * 16
FACTS = (
    "pinned_git_fixture", "archive_read_grant_twin", "complete_archive_and_offline_pin",
    "restartable_capture", "owned_plan_and_budget", "denied_write_and_exact_retry",
    "canonical_text_authorship_and_no_approval", "original_keys_and_offline_completion",
    "collision_refusal", "unchanged_refs_and_source", "owned_services_drained",
)


@contextmanager
def pull_server(campaign, root, credentials, label, *, omit_pulls=False):
    for attempt in range(16):
        server = HttpServer(campaign, root, credentials, f"{label}-{attempt}")
        server.command.append("--allow-outcomes")
        if omit_pulls:
            server.command.remove("--allow-pulls")
        with server:
            if urlsplit(server.url).port <= 10080:
                continue
            yield server
            return
    raise AssertionError("native Fetch-compatible listener selection exhausted")


def run_case(campaign, oracle_run, fmt, *, omit_source_pulls=False):
    home = campaign.work / fmt
    home.mkdir(mode=0o700)
    source, destination, git_source = (home / n for n in ("source", "destination", "git-source"))
    objects = fixture(git_source, fmt)
    (home / "reviewed.bundle").write_bytes(objects["bundle"])
    check_fixture(campaign, oracle_run, git_source, objects)
    campaign.facts[f"{fmt}_pinned_git_fixture"] = True
    for root in (source, destination):
        campaign.run("init", root, TENANT, REPOSITORY, fmt)
        campaign.run("import", root, TENANT, REPOSITORY, PRINCIPAL, "portability-fixture", git_source)

    def read(root, operation, number=None):
        args = ["pr", operation, root, TENANT, REPOSITORY]
        if number is not None:
            args.append(number)
        args += ["--trusted-local", "--object-format", fmt]
        if operation != "show":
            args += ["--limit", 100]
        page = json.loads(campaign.run(*args))
        require(page["node_closed"] is True, "canonical PR reader did not close")
        return page

    def refs(root):
        return campaign.run("at", root, TENANT, REPOSITORY, "latest", "refs")

    def metadata(action, number, version):
        reply = json.loads(campaign.run("pr", action, source, TENANT, REPOSITORY, number,
            "--trusted-local", "--object-format", fmt, "--principal", SOURCE_ACTOR,
            "--idempotency-key", f"source-{action}-{number}", "--expected-version", version,
            "--source-ref-hex", SOURCE.encode().hex(), "--target-ref-hex", TARGET.encode().hex(),
            "--expected-source", objects["source"], "--expected-target", objects["target"],
            "--title", f"Native portable PR {number} 雪", "--body", f"\ufeffLiteral body {number}\r\n<script>untrusted</script> 🦀\n"))
        require(reply["command_committed"] is True and reply["node_closed"] is True,
                "source metadata seed did not canonically commit")

    for number in (7, 9):
        metadata("open", number, 0)
        reply = json.loads(campaign.run("pr", "comment", source, TENANT, REPOSITORY, number,
            "--trusted-local", "--object-format", fmt, "--principal", SOURCE_ACTOR,
            "--idempotency-key", f"source-comment-{number}", "--expected-version", 0,
            "--body", f"Original discussion {number}\r\n🦀\n"))
        require(reply["command_committed"] is True and reply["node_closed"] is True,
                "source discussion seed did not canonically commit")
    epoch = read(source, "reviews", 7)["policy_epoch"]
    approval = json.loads(campaign.run("pr", "review", source, TENANT, REPOSITORY, 7,
        "--trusted-local", "--principal", REVIEWER, "--idempotency-key", "source-approval",
        "--expected-version", 1, "--review-version", 0, "--decision", "approve",
        "--source-ref", SOURCE, "--target-ref", TARGET, "--source-tip", objects["source"],
        "--target-tip", objects["target"], "--merge-base", objects["base"],
        "--candidate", objects["candidate"], "--policy-epoch", epoch,
        "--bundle", home / "reviewed.bundle", "--reason", "Source-only approval\r\n🦀"))
    require(approval["outcome"] == "committed" and approval["published_to_repository"] is True
            and approval["git_refs_changed"] is False and approval["node_closed"] is True,
            "source approval seed did not canonically commit")
    metadata("close", 9, 1)
    source_before = {n: {op: read(source, op, n) for op in ("show", "comments", "reviews")} for n in (7, 9)}
    source_refs, destination_refs = refs(source), refs(destination)

    def credentials(root, name):
        auth = home / name
        auth.mkdir(mode=0o700)
        path, incarnation = campaign.credentials(root, auth)
        header = path.read_text().splitlines()[0]
        token = auth / "token"
        token.write_text(TOKEN, encoding="ascii")

        def grants(scopes):
            pending = auth / "credentials.next"
            with pending.open("x", encoding="ascii") as out:
                out.write(f"{header}\n{hashlib.sha256(TOKEN.encode()).hexdigest()} {PRINCIPAL} {scopes}\n")
            pending.replace(path)
        return path, token, incarnation, grants

    source_credentials, source_token, _, source_grants = credentials(source, "source-auth")
    source_grants("outcomes-read")
    archive_cli, migrate_cli = ROOT / "scripts/archive_native_pulls.mjs", ROOT / "scripts/migrate_native_pulls.mjs"
    archive = home / "archive"
    with pull_server(campaign, source, source_credentials, "source-" + fmt,
                     omit_pulls=omit_source_pulls) as server:
        connection = ["--url", server.url + "/ui/pulls/", "--tenant", TENANT, "--repository", REPOSITORY,
                      "--token-file", str(source_token), "--page-size", "1"]
        denied = campaign.node_command(archive_cli, ["export", *connection, "--workdir", str(home / "denied-archive")],
                                       4, error_reply=True)
        require(denied["message"] == "Required independent scope is missing or this endpoint is disabled."
                and denied["archive_progress"]["directory_created"] is True
                and not (home / "denied-archive/archive.json").exists(),
                "read grant refusal did not preserve the incomplete archive boundary")
        source_grants("pulls-read,reviews-read")
        exported = campaign.node_command(archive_cli, ["export", *connection, "--workdir", str(archive)])
        require(exported["complete"] is True and exported["pulls"] == 2 and exported["reviews"] == 1
                and exported["comments"] == 2, "native archive omitted subjects or observations")
        campaign.facts[f"{fmt}_archive_read_grant_twin"] = True
        job = home / "capture-job"
        prepared = campaign.node_command(archive_cli, ["prepare", *connection, "--workdir", str(job)])
        capture = ["--workdir", str(job), "--confirm", prepared["selection_sha256"]]
        paused = campaign.node_command(archive_cli, ["resume", *capture, "--token-file", str(source_token),
                                                   "--page-budget", "1"], 3)
        require(paused["complete"] is False and paused["new_requests"] == 1, "capture page budget did not pause")
        status = campaign.node_command(archive_cli, ["status", *capture])
        require(status["network_accessed"] is False and status["checkpoint_sha256"] == paused["checkpoint_sha256"],
                "offline capture status lost the retained prefix")
        resumed = campaign.node_command(archive_cli, ["resume", *capture, "--token-file", str(source_token)])
        require(resumed["complete"] is True, "native capture did not resume to a complete archive")
        campaign.facts[f"{fmt}_restartable_capture"] = True
    pin = exported["archive_sha256"]
    inspected = campaign.node_command(archive_cli, ["inspect", "--workdir", str(archive), "--confirm", pin])
    require(inspected["complete"] is True and inspected["network_accessed"] is False,
            "inspection needed the stopped source service")
    wrong = campaign.node_command(archive_cli, ["inspect", "--workdir", str(archive), "--confirm", "0" * 64],
                                  2, error_reply=True)
    require("pin_mismatch" in wrong["message"] and file_sha256(archive / "archive.json") == pin,
            "wrong archive pin was accepted or changed retained custody")
    campaign.facts[f"{fmt}_complete_archive_and_offline_pin"] = True

    dest_credentials, dest_token, incarnation, dest_grants = credentials(destination, "destination-auth")
    dest_grants("outcomes-read,pulls-read")
    with pull_server(campaign, destination, dest_credentials, "destination-" + fmt) as server:
        selection = {"endpoint": server.url, "scope": {"tenant_id": TENANT, "repository_id": REPOSITORY,
            "repository_incarnation": incarnation, "principal_id": PRINCIPAL, "object_format": fmt}, "number_start": "100"}
        selected = home / "selection.json"
        selected.write_text(json.dumps(selection), encoding="utf-8")
        plan = home / "plan"
        prepared = campaign.node_command(migrate_cli, ["prepare", "--archive-dir", str(archive), "--archive-confirm", pin,
            "--selection", str(selected), "--token-file", str(dest_token), "--workdir", str(plan)])
        common = ["--workdir", str(plan), "--confirm", prepared["plan_sha256"]]
        originals = {str(p.relative_to(plan)): file_sha256(p) for p in (plan / "requests").rglob("*") if p.is_file()}
        require(bool(originals), "prepared original request population is empty")
        archive.rename(home / "retained-original-archive")
        campaign.node_command(migrate_cli, ["inspect", *common])
        before = read(destination, "list")
        denied = campaign.node_command(migrate_cli, ["run", *common, "--token-file", str(dest_token)], 3)
        require(denied["complete"] is False and denied["state"] == "pending" and denied["committed_steps"] == 0
                and read(destination, "list") == before, "denied migration changed canonical PR state")
        key = denied["current"]["key"]
        dest_grants("outcomes-read,pulls-read,pulls-write")
        recovered = campaign.node_command(migrate_cli, ["run", *common, "--token-file", str(dest_token)], 3)
        require(recovered["current"]["key"] == key and recovered["mutations_dispatched"] == 0
                and read(destination, "list") == before, "restoring grants silently resent an uncertain key")
        partial = campaign.node_command(migrate_cli, ["run", *common, "--token-file", str(dest_token),
            "--retry-key", key, "--max-operations", "1"], 3)
        require(partial["committed_steps"] == 1 and partial["new_operations"] == 1
                and len(read(destination, "list")["pull_requests"]) == 1,
                "exact-key retry did not preserve its one-operation prefix")
        campaign.facts[f"{fmt}_denied_write_and_exact_retry"] = True
        campaign.facts[f"{fmt}_owned_plan_and_budget"] = True
        completed = campaign.node_command(migrate_cli, ["run", *common, "--token-file", str(dest_token)])
        require(completed["complete"] is True and completed["committed_steps"] == prepared["steps"],
                "native migration did not confirm every prepared step")
        observed = {}
        for old, new in ((7, 100), (9, 101)):
            row = read(destination, "show", new)["pull_request"]
            original = source_before[old]["show"]["pull_request"]
            discussion, reviews = read(destination, "comments", new), read(destination, "reviews", new)
            require(row["data"] == original["data"] and row["state"] == original["state"]
                    and row["opened_by"] == row["last_metadata_actor"] == PRINCIPAL,
                    "native destination changed source bytes/state or impersonated source actors")
            require(all(c["actor"] == PRINCIPAL for c in discussion["comments"])
                    and any(c["body"].endswith(f"Original discussion {old}\r\n🦀\n") for c in discussion["comments"])
                    and reviews["reviews"] == [], "migration lost literal comments or imported source approvals")
            if old == 7:
                require(any("Imported review observation" in c["body"] and REVIEWER in c["body"]
                            and c["body"].endswith("Source-only approval\r\n🦀") for c in discussion["comments"]),
                        "source approval was not preserved as attributed comment data")
            observed[new] = (row, discussion, reviews)
        campaign.facts[f"{fmt}_canonical_text_authorship_and_no_approval"] = True
        after = {str(p.relative_to(plan)): file_sha256(p) for p in (plan / "requests").rglob("*") if p.is_file()}
        require(after == originals, "migration replaced an original sealed request")
        # A second independently prepared plan at occupied numbers must retain
        # the first canonical refusal; it may not renumber or run later steps.
        collision = home / "collision-plan"
        conflict = campaign.node_command(migrate_cli, ["prepare", "--archive-dir", str(home / "retained-original-archive"),
            "--archive-confirm", pin, "--selection", str(selected), "--token-file", str(dest_token), "--workdir", str(collision)])
        args = ["--workdir", str(collision), "--confirm", conflict["plan_sha256"]]
        refused = campaign.node_command(migrate_cli, ["run", *args, "--token-file", str(dest_token)], 1)
        require(refused["state"] == "refused" and refused["committed_steps"] == 0,
                "occupied PR number did not stop at the first native refusal")
        repeated = campaign.node_command(migrate_cli, ["run", *args], 1)
        require(repeated["current"]["key"] == refused["current"]["key"] and repeated["new_operations"] == 0,
                "collision recovery replaced its key or retried a mutation")
        for number, (row, discussion, reviews) in observed.items():
            require(read(destination, "show", number)["pull_request"] == row
                    and read(destination, "comments", number)["comments"] == discussion["comments"]
                    and read(destination, "reviews", number)["reviews"] == reviews["reviews"],
                    "collision changed existing PR content, discussion or approvals")
        campaign.facts[f"{fmt}_collision_refusal"] = True
    dest_token.rename(dest_token.with_name("retained-token"))
    for operation in ("inspect", "status", "recover", "run"):
        settled = campaign.node_command(migrate_cli, [operation, *common])
        require(settled.get("network_accessed") is False, "complete recovery required network or a credential")
    campaign.facts[f"{fmt}_original_keys_and_offline_completion"] = True
    for number in (7, 9):
        for operation in ("show", "comments", "reviews"):
            require(read(source, operation, number) == source_before[number][operation],
                    "read-only archive changed source canonical state")
    require(refs(source) == source_refs and refs(destination) == destination_refs,
            "PR portability moved Git references")
    campaign.facts[f"{fmt}_unchanged_refs_and_source"] = True
    campaign.facts[f"{fmt}_owned_services_drained"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "oracle-run", "summary"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--omit-source-pull-service", action="store_true",
                        help="verify the planted native route-negative control")
    args = parser.parse_args()
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=False)
    fg, node = args.fg.resolve(strict=True), args.node.resolve(strict=True)
    campaign = OperatorCampaign(fg, node, args.work.resolve())
    summary = {"complete": False, "facts": campaign.facts, "binary_sha256": file_sha256(fg),
        "node_sha256": file_sha256(node), "oracle_pin": PIN, "oracle_run": str(args.oracle_run),
        "artifacts": str(campaign.work),
        "selected_facts": [f"{fmt}_{fact}" for fmt in ("sha1", "sha256") for fact in FACTS],
        "entrypoints": [{"path": "scripts/" + name, "binary_sha256": file_sha256(fg)}
                        for name in ("archive_native_pulls.mjs", "migrate_native_pulls.mjs")],
        "negative_control": args.omit_source_pull_service,
        "negative_observed": False,
        "non_claim": "Two native PR portability entrypoints; not every operator, independent batch verification, D10, power loss or full/release qualification."}

    def stop(_number, _frame):
        raise InterruptedError("native PR portability interrupted; draining owned children")

    signal.signal(signal.SIGTERM, stop)
    try:
        identity = campaign.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity["type"] == "js_runtime_identity" and identity["corpus_started"] is False,
                "runtime identity was not checked before dispatch")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(campaign, args.oracle_run.resolve(strict=True), fmt,
                     omit_source_pulls=args.omit_source_pull_service)
        require(set(campaign.facts) == set(summary["selected_facts"]) and all(campaign.facts.values()),
                "selected native portability facts are missing")
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        if not args.omit_source_pull_service:
            raise
        # Expected failure is a test result only after checking the actual
        # entrypoint, native service ceiling and successful owner drain. An
        # oracle/setup error, cancellation or unrelated nonzero is never proof.
        require(isinstance(error, AssertionError) and "operator exit 4, expected 0" in str(error),
                "missing-route control failed for an unrelated reason")
        commands = [json.loads(line) for line in campaign.journal.read_text().splitlines()]
        operators = [row for row in commands if row.get("kind") == "operator"]
        starts = [row for row in commands if row.get("kind") == "service_start"]
        drains = [row for row in commands if row.get("kind") == "service_stop"]
        require(len(operators) == 3 and Path(operators[-1]["command"][1]) == ROOT / "scripts/archive_native_pulls.mjs"
                and operators[-1]["command"][2] == "export" and operators[-1]["exit"] == 4,
                "missing-route control did not reach the native archive entrypoint")
        require(len(starts) == len(drains) == 1 and "--allow-pulls" not in starts[0]["command"]
                and drains[0]["exit"] == 0 and drains[0]["forced"] is False,
                "missing-route control lost its native service ceiling or normal owner drain")
        require(set(campaign.facts) == {"sha1_pinned_git_fixture"}, "missing-route control ran unexpected successor work")
        summary["negative_observed"] = True
        traceback.print_exception(error)
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
