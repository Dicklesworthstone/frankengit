#!/usr/bin/env python3
"""Run the shipped JS watcher/check publisher against a supplied real native node.

Fixed, secret-free trusted-host scripts only. Canonical Rust PR reads establish
publication; schema peers, workflow success and local receipts do not.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import signal
import subprocess
import sys

from operator_issue_smoke import OperatorCampaign, issue_server, TOKEN
from operator_workspace_smoke import file_tree
from patch_smoke import loose
from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
SOURCE, TARGET = "refs/heads/feature", "refs/heads/main"
CONCLUSIONS = {"a_success": "success", "b_failure": "failure", "c_skipped": "action_required"}


def check_id(job):
    preimage = (b"frankengit/trusted-workflow-check/v1\0" + bytes.fromhex(PRINCIPAL)
                + bytes.fromhex(job["run_id"]) + bytes.fromhex(job["attempt_id"])
                + hashlib.sha256(job["job"].encode()).digest())
    return "check/" + base64.b32hexencode(hashlib.sha256(preimage).digest()).decode().lower().rstrip("=")


def node_rows(c, script, arguments, expected=0, *, error_reply=False):
    """Retain the publisher's NDJSON observations as well as its final summary."""
    c.client_serial += 1
    stem = c.work / f"operator-{c.client_serial:03d}"
    command = [str(c.node), str(script), *arguments]
    with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                timeout=90, check=False)
    c.record(kind="operator", command=command, exit=result.returncode, artifacts=str(stem))
    if result.returncode != expected:
        sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
    require(result.returncode == expected, f"publisher exit {result.returncode}, expected {expected}; see {stem}")
    channel = "stderr" if error_reply else "stdout"
    rows = [json.loads(line) for line in stem.with_suffix("." + channel).read_bytes().splitlines()]
    require(bool(rows), "publisher omitted its result")
    return rows


def run_case(c, oracle_run, fmt, nested):
    home = c.work / fmt
    home.mkdir(mode=0o700)
    source, repository = home / "source", home / "repository"
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_text(f"ref: {TARGET}\n")
    (source / "config").write_text("[core]\nbare=true\nrepositoryformatversion=" +
        ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"))
    workflow_dir, inputs = ("ci/workflows", "inputs/selected") if nested else ("ci", "inputs")
    marker = home / "executions"
    log = shlex.quote(str(marker))
    workflow = ("name: native-operator\non: push\njobs:\n"
        "  a_success:\n    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: test \"$(cat {inputs}/message.txt)\" = 'selected native workflow input'; test ! -e elsewhere/secret; "
        f"test ! -e inputs/omitted; printf s >> {log}; printf workflow-ok\n"
        "  b_failure:\n    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: printf f >> {log}; printf workflow-failed; exit 7\n"
        "  c_skipped:\n    needs: b_failure\n    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: printf x >> {log}\n").encode()
    files = {(workflow_dir + "/workflow.yml").encode(): (b"100644", workflow),
             (inputs + "/message.txt").encode(): (b"100644", b"selected native workflow input\n"),
             b"elsewhere/secret": (b"100644", b"unselected fixture, not a credential\n")}
    if nested:
        files[b"inputs/omitted"] = (b"100644", b"unselected nested sibling\n")
    tree, _ = file_tree(fmt, files, lambda kind, body: loose(source, fmt, kind, body))

    def commit(parents, message):
        body = (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents) +
                "author Workflow Fixture <workflow@example.invalid> 1 +0000\n"
                "committer Workflow Fixture <workflow@example.invalid> 1 +0000\n\n" + message + "\n").encode()
        return loose(source, fmt, "commit", body)

    target = commit([], "target")
    tip = commit([target], "source")
    for ref, value in ((TARGET, target), (SOURCE, tip)):
        (source / ref).write_text(value + "\n")
    command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
               str(source.relative_to(oracle_run / "work")), fmt + "-workflow-fsck", "--",
               "fsck", "--full", "--strict", "--no-reflogs"]
    with (home / "oracle.stdout").open("wb") as out, (home / "oracle.stderr").open("wb") as err:
        checked = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
    c.record(kind="pinned_git_fixture_check", command=command, exit=checked.returncode)
    if checked.returncode:
        sys.stderr.write((home / "oracle.stderr").read_text(errors="replace"))
    require(checked.returncode == 0, "pinned sandboxed Git rejected workflow objects")
    c.run("init", repository, TENANT, REPOSITORY, fmt)
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "operator-workflow-fixture", source)
    credentials, incarnation = c.credentials(repository, home)
    header = credentials.read_text().splitlines()[0]

    def grants(scopes):
        pending = home / "credentials.next"
        pending.write_text(f"{header}\n{hashlib.sha256(TOKEN.encode()).hexdigest()} {PRINCIPAL} {scopes}\n")
        pending.replace(credentials)

    token = home / "token"
    token.write_text(TOKEN)
    watch_state, run_parent, pub_state = (home / name for name in ("watch", "runs", "publisher"))
    for directory in (watch_state, run_parent, pub_state):
        directory.mkdir(mode=0o700)
    config = dict(schema="frankengit-workflow-watch-v1", fg=str(c.fg), storage_root=str(repository),
        tenant_id=TENANT, repository_id=REPOSITORY, repository_incarnation=incarnation, object_format=fmt,
        ref_hex=SOURCE.encode().hex(), workflow_directory_hex=workflow_dir.encode().hex(),
        input_prefixes_hex=[workflow_dir.encode().hex(), inputs.encode().hex()], event="push",
        state_directory=str(watch_state), run_parent=str(run_parent), max_runs=16,
        trust="selected-branch-host-execution")
    config_path = home / "watch.json"
    config_path.write_text(json.dumps(config))
    watch_cli, check_cli = ROOT / "scripts/fg_workflow_watch.mjs", ROOT / "scripts/fg_workflow_checks.mjs"
    watch_args = ["--config", str(config_path), "--trusted-local"]
    before = c.run("at", repository, TENANT, REPOSITORY, "latest")
    watched = c.node_command(watch_cli, ["once", *watch_args], 1)
    require(watched["outcome"] == "observed_failed" and marker.read_bytes() == b"sf",
            "watcher did not observe exactly the real success/failure/skip execution")
    require(c.run("at", repository, TENANT, REPOSITORY, "latest") == before,
            "job execution published canonical repository state")
    c.facts[f"{fmt}_watch_execution_and_input_selection"] = True
    status = c.node_command(watch_cli, ["status", *watch_args])
    require(len(status["records"]) == 1 and status["records"][0]["state"] == "observed_failed",
            "watch status lost its exact failed run")
    c.node_command(watch_cli, ["reconcile", *watch_args])
    c.node_command(watch_cli, ["once", *watch_args], 1)
    require(marker.read_bytes() == b"sf" and c.run("at", repository, TENANT, REPOSITORY, "latest") == before,
            "watch status/reconcile/dedup reran jobs or published state")
    c.facts[f"{fmt}_watch_dedup_and_reconcile"] = True
    opened = json.loads(c.run("pr", "open", repository, TENANT, REPOSITORY, "7", "--trusted-local",
        "--principal", PRINCIPAL, "--idempotency-key", "operator-workflow-pr", "--expected-version", "0",
        "--source-ref", SOURCE, "--target-ref", TARGET, "--expected-source", tip, "--expected-target", target,
        "--title", "Native workflow operator", "--body", "Fixed trusted fixture", "--object-format", fmt))
    require(opened["command_committed"] is True and opened["node_closed"] is True, "PR did not commit and close")

    def canonical():
        page = json.loads(c.run("pr", "checks", repository, TENANT, REPOSITORY, "7", "--trusted-local", "--object-format", fmt))
        require(page["type"] == "pull_request_checks" and page["schema_version"] == 1
                and page["tenant_id"] == TENANT and page["repository_id"] == REPOSITORY
                and page["repository_incarnation"] == incarnation and page["object_format"] == fmt
                and page["found"] is True and page["number"] == "7" and page["pull_request_version"] == "1"
                and page["node_closed"] is True and page["source_current"] is True and page["source_tip"] == tip
                and page["target_tip"] == target and page["source_ref_hex"] == SOURCE.encode().hex()
                and page["target_ref_hex"] == TARGET.encode().hex() and page["complete"] is True
                and page["scope"] == "trusted_workflow_observations" and page["merge_permission"] is None,
                "canonical check scope or source/cleanup changed")
        return page

    require(canonical()["checks"] == [], "execution was presented as check publication")
    pub_args = ["--watch-config", str(config_path), "--state", str(pub_state), "--principal-id", PRINCIPAL, "--trusted-local"]
    published = node_rows(c, check_cli, ["once", *pub_args])
    require(published[-1]["publications"] == 3 and published[-1]["runs"][0]["committed"] == 3
            and published[-1]["runs"][0]["pending"] == 0, "publisher did not commit exactly three jobs")
    plans = list(pub_state.glob("plan-*.json"))
    require(len(plans) == 1, "one original watcher plan required")
    plan = json.loads(plans[0].read_bytes())
    jobs = {row["job"]: row for row in plan["jobs"]}
    page = canonical()
    checks = {row["job"]: row for row in page["checks"]}
    require(len(page["checks"]) == len(plan["jobs"]) == 3 and set(jobs) == set(checks) == set(CONCLUSIONS),
            "canonical checks missing, duplicate or unexpected")
    for name, conclusion in CONCLUSIONS.items():
        row, job = checks[name], jobs[name]
        require(row["conclusion"] == conclusion and row["publisher"] == PRINCIPAL
                and row["id"] == check_id(job)
                and all(row[field] == job[field] for field in ("run_id", "attempt_id", "graph_root"))
                and row["evidence_sha256"] == job["evidence_sha256"], "canonical job identity/conclusion differs")
    c.facts[f"{fmt}_canonical_success_failure_and_skip"] = True
    retained = {p.name: p.read_bytes() for p in pub_state.iterdir() if p.name.startswith(("plan-", "started-"))}
    authority = c.run("at", repository, TENANT, REPOSITORY, "latest")
    for operation in ("once", "resume", "status"):
        rows = node_rows(c, check_cli, [operation, *pub_args])
        require(rows[-1]["runs"][0]["committed"] == 3 and rows[-1].get("publications", 0) == 0,
                "settled check publication was dispatched again")
    c.facts[f"{fmt}_publisher_dedup_and_original_keys"] = True
    saved = home / "retained-terminals"
    saved.mkdir(mode=0o700)
    terminals = list(pub_state.glob("terminal-*.json"))
    require(len(terminals) == 3, "three terminal receipts required before recovery exercise")
    for terminal in terminals:
        terminal.rename(saved / terminal.name)
    grants("pulls-read")
    with issue_server(c, repository, credentials, "workflow-" + fmt) as server:
        recovery = ["recover", *pub_args, "--endpoint", server.url, "--token-file", str(token)]
        denied = node_rows(c, check_cli, recovery, 3, error_reply=True)[-1]
        require(denied["type"] == "workflow_check_error" and denied["message"] == "outcome_http_refused"
                and denied["publication_unknown"] is True and denied["retained_recovery"]["runs"][0]["pending"] == 3
                and not list(pub_state.glob("observed-*.json")),
                "outcomes denial invented a terminal observation")
        grants("outcomes-read")
        recovered = node_rows(c, check_cli, recovery)[-1]
        require(recovered["remote_read_only"] is True and recovered["request_reexecuted"] is False
                and recovered["lookups"] == 3 and recovered["runs"][0]["committed"] == 3,
                "original-key outcome recovery lost terminal identity or resubmitted")
    c.facts[f"{fmt}_outcome_grant_twins_and_service_drain"] = True
    require(all((pub_state / name).read_bytes() == data for name, data in retained.items())
            and marker.read_bytes() == b"sf" and canonical() == page
            and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority,
            "recovery changed keys, reran execution or changed canonical state")
    c.facts[f"{fmt}_recovery_no_execution_or_publication"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary", "oracle-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--nested-inputs", action="store_true",
                        help="require native nested inputs; never falls back to broader selection")
    args = parser.parse_args()
    os.umask(0o077)
    fg, node, oracle = args.fg.resolve(strict=True), args.node.resolve(strict=True), args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private work directory required")
    c = OperatorCampaign(fg, node, args.work.resolve())
    summary = dict(complete=False, facts=c.facts, binary_sha256=file_sha256(fg), node_sha256=file_sha256(node),
        entrypoints=["scripts/fg_workflow_watch.mjs", "scripts/fg_workflow_checks.mjs"],
        nested_inputs=args.nested_inputs, oracle_pin="git-2.54.0", oracle_run=str(oracle), artifacts=str(c.work),
        non_claim="Fixed trusted-host scripts, not hostile-code isolation, every operator, same-source native qualification, TLS, required-check policy or deployment.")

    def stop(_signum, _frame):
        raise InterruptedError("workflow campaign interrupted; retain original custody and drain owned service")

    signal.signal(signal.SIGTERM, stop)
    try:
        identity = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity.get("type") == "js_runtime_identity" and identity.get("corpus_started") is False, "pinned runtime required")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, oracle, fmt, args.nested_inputs)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
