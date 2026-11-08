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
from operator_artifact_smoke import artifact_case
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
    """Use the shared request/drain owner for every retained NDJSON command."""
    return c.node_command(script, arguments, expected, error_reply=error_reply, json_lines=True)


def verify_fixture(c, source, oracle_run, fmt, label, *arguments):
    command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
               str(source.relative_to(oracle_run / "work")), fmt + "-workflow-" + label, "--",
               *(arguments or ("fsck", "--full", "--strict", "--no-reflogs"))]
    with (source.parent / (label + ".oracle.stdout")).open("wb") as out, (source.parent / (label + ".oracle.stderr")).open("wb") as err:
        checked = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
    c.record(kind="pinned_git_fixture_operation", command=command, exit=checked.returncode)
    if checked.returncode:
        sys.stderr.write((source.parent / (label + ".oracle.stderr")).read_text(errors="replace"))
    require(checked.returncode == 0, "pinned sandboxed Git rejected workflow objects")


def supervisor_case(c, home, repository, config, canonical, next_revision):
    fmt = config["object_format"]
    watch, publisher, state = Path(config["state_directory"]), home / "publisher", home / "supervisor"
    state.mkdir(mode=0o700)
    selected = dict(schema="frankengit-workflow-supervisor-v1", state_directory=str(state), lanes=[dict(
        name="selected", publisher=dict(schema="frankengit-workflow-check-publisher-v1", watch=config,
                                       state_directory=str(publisher), principal_id=PRINCIPAL))])
    selection = home / "supervisor.json"
    selection.write_text(json.dumps(selected))
    script = ROOT / "scripts/fg_workflow_supervisor.mjs"

    def call(action, *extra, expected=0):
        return node_rows(c, script, [action, "--config", str(selection),
                         *([] if action == "status" else ["--trusted-local"]), *extra], expected)

    def settled_status(value, failed, succeeded, committed):
        require(value["type"] == "workflow_supervisor_status" and value["read_only"] is True
                and value["owner_present"] is False and len(value["lanes"]) == 1, "supervisor status owner/scope changed")
        lane = value["lanes"][0]
        require("error" not in lane and lane["watcher"]["observed_failed"] == failed
                and lane["watcher"]["observed_succeeded"] == succeeded
                and lane["watcher"]["execution_unknown"] == lane["watcher"]["queued"] == 0
                and lane["watcher"]["owner_present"] is False
                and lane["publication"]["committed"] == committed
                and lane["publication"]["pending"] == lane["publication"]["unknown"] == lane["publication"]["refused"] == 0
                and lane["publication_owner_present"] is lane["recovery_owner_present"] is False,
                "supervisor lost settled watcher/publication custody")

    def checks(page, conclusions):
        jobs = {check_id(job): job for path in publisher.glob("plan-*.json")
                for job in json.loads(path.read_bytes())["jobs"]}
        require(len(page["checks"]) == 3 and {row["job"] for row in page["checks"]} == set(conclusions),
                "canonical check set incomplete or duplicated")
        for row in page["checks"]:
            job = jobs[row["id"]]
            require(row["publisher"] == PRINCIPAL and row["conclusion"] == conclusions[row["job"]]
                    and all(row[key] == job[key] for key in ("run_id", "attempt_id", "graph_root", "evidence_sha256")),
                    "canonical supervisor publication identity or conclusion changed")

    initial_status = call("status")[-1]
    settled_status(initial_status, 0, 0, 0)
    require(initial_status["bound"] is False and canonical()["checks"] == [], "unstarted supervisor published state")
    first = call("once", expected=1)[-1]
    lane = first["lanes"][0]
    require(first["failed"] is True and first["pending"] is first["containment_unknown"] is False
            and "error" not in lane and lane["execution"]["outcome"] == "observed_failed"
            and lane["before"]["committed"] == 0 and lane["after"]["committed"] == 3,
            "real workflow failure was hidden or did not reach publication")
    marker = home / "executions"
    require(marker.read_bytes() == b"sf", "supervisor did not execute exactly success/failure/skip")
    page = canonical()
    checks(page, CONCLUSIONS)
    c.facts[fmt + "_failed_execution_still_publishes"] = True
    c.facts[fmt + "_exact_native_job_identities"] = True

    authority = c.run("at", repository, TENANT, REPOSITORY, "latest")
    settled_status(call("status")[-1], 1, 0, 3)
    again = call("once", expected=1)[-1]
    require(again["lanes"][0]["execution"]["type"] == "workflow_watch_idle"
            and again["lanes"][0]["execution"]["reason"] == "commit_already_observed"
            and marker.read_bytes() == b"sf" and canonical() == page
            and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority,
            "new supervisor process reran or republished an observed failed workflow")
    c.facts[fmt + "_status_restart_dedup"] = True

    tip = next_revision()
    require(canonical(8, tip)["checks"] == [], "new revision inherited old success")
    service = call("serve", "--max-cycles", "2", "--interval-ms", "1")
    require(len(service) == 3 and [row["type"] for row in service] ==
            ["workflow_supervisor_cycle", "workflow_supervisor_cycle", "workflow_supervisor_service"]
            and [row["cycle"] for row in service[:2]] == [1, 2] and service[-1]["cycles"] == 2
            and service[0]["lanes"][0]["execution"]["outcome"] == "observed_succeeded"
            and service[1]["lanes"][0]["execution"]["type"] == "workflow_watch_idle"
            and service[-1]["quarantined"] == [] and marker.read_bytes() == b"sfsfx",
            "bounded supervisor service did not execute the new permitted revision exactly once")
    require(all(row["failed"] is row["pending"] is row["stopped"] is row["containment_unknown"] is False
                and row["authoritative_check"] is row["execution_retried"] is False for row in service),
            "service scope or terminal flags changed")
    current = canonical(8, tip)
    checks(current, {name: "success" for name in CONCLUSIONS})
    settled_status(call("status")[-1], 1, 1, 6)
    c.facts[fmt + "_permitted_revision_and_bounded_service"] = True

    authority = c.run("at", repository, TENANT, REPOSITORY, "latest")
    original = next(watch.glob("result-*.json"))
    saved = home / "retained-summary"
    saved.mkdir(mode=0o700)
    original.rename(saved / original.name)
    retained = {str(path.relative_to(home)): path.read_bytes() for directory in [watch, publisher, state]
                for path in directory.iterdir() if path.is_file()}
    missing_status = call("status", expected=2)[-1]
    require(missing_status["lanes"][0]["watcher"]["execution_unknown"] == 1,
            "missing completed summary was treated as permission to rerun")
    unavailable = home / "retained-native-store"
    repository.rename(unavailable)
    try:
        repaired = call("reconcile")[-1]
        require(repaired["type"] == "workflow_supervisor_reconciliation" and repaired["failed"] is repaired["pending"] is False
                and repaired["execution_retried"] is repaired["publication_submitted"] is repaired["locks_removed"] is False,
                "offline reconciliation executed, published or erased an owner")
        settled_status(call("status")[-1], 1, 1, 6)
    finally:
        unavailable.rename(repository)
    require(original.read_bytes() == (saved / original.name).read_bytes()
            and all((home / name).read_bytes() == data for name, data in retained.items())
            and canonical(8, tip) == current and marker.read_bytes() == b"sfsfx"
            and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority,
            "reconciliation changed original custody, repeated execution or canonical state")
    c.facts[fmt + "_offline_summary_reconciliation"] = True
    for directory in [watch, publisher, state]:
        require(not (directory / "owner.lock").exists() and not (directory / "recovery.lock").exists(), "completed owner lock remains")
        for path in [directory, *directory.iterdir()]:
            require(path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0, "public or foreign workflow custody")
    c.facts[fmt + "_original_custody_and_owners"] = True
    require(first["authoritative_check"] is first["execution_retried"] is False
            and repaired["authoritative_check"] is False and current["merge_permission"] is None,
            "local workflow observation became merge authority")
    c.facts[fmt + "_native_authority_and_scope"] = True
    print(f"OPERATOR_SUPERVISOR {fmt}: actual execution/publication, bounded service, dedup and offline reconciliation", flush=True)


def run_case(c, oracle_run, fmt, nested, supervised=False):
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
    artifact_build = "" if supervised else "; printf 'artifact\\000bytes\\377' > result.bin; chmod +x result.bin; printf 'log\\000bytes\\377' >&2"
    artifact_check = "" if supervised else ("set -eu; printf 'artifact\\000bytes\\377' > expected.bin; "
        "test -x .fgit-artifacts/result.bin; cmp expected.bin .fgit-artifacts/result.bin; "
        f"printf verified > {shlex.quote(str(home / 'artifact-delivery-verified'))}; ")
    dependency = "" if supervised else "    needs: a_success\n"
    workflow = ("name: native-operator\non: push\njobs:\n"
        "  a_success:\n    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: test \"$(cat {inputs}/message.txt)\" = 'selected native workflow input'; test ! -e elsewhere/secret; "
        f"test ! -e inputs/omitted; printf s >> {log}; printf workflow-ok{artifact_build}\n"
        f"  b_failure:\n{dependency}    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: {artifact_check}printf f >> {log}; printf workflow-failed; exit 7\n"
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
    verify_fixture(c, source, oracle_run, fmt, "initial")
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
    if not supervised:
        artifact_root = home / "artifacts"
        artifact_root.mkdir(mode=0o700)
        config["artifacts"] = dict(root=str(artifact_root), maximum_file_mib=1, total_payload_mib=2,
            capture_logs=True, selections=[dict(workflow_path_hex=(workflow_dir + "/workflow.yml").encode().hex(),
                job_id="a_success", output_path_hex=b"result.bin".hex())], total_delivery_mib=1,
            inputs=[dict(workflow_path_hex=(workflow_dir + "/workflow.yml").encode().hex(),
                consumer_job_id="b_failure", producer_job_id="a_success", output_path_hex=b"result.bin".hex(),
                destination_hex=b"result.bin".hex())])
    config_path = home / "watch.json"
    config_path.write_text(json.dumps(config))
    watch_cli, check_cli = ROOT / "scripts/fg_workflow_watch.mjs", ROOT / "scripts/fg_workflow_checks.mjs"
    watch_args = ["--config", str(config_path), "--trusted-local"]

    def open_pull(number, selected_tip):
        opened = json.loads(c.run("pr", "open", repository, TENANT, REPOSITORY, str(number), "--trusted-local",
            "--principal", PRINCIPAL, "--idempotency-key", "operator-workflow-pr" if number == 7 else "operator-workflow-pr-" + str(number), "--expected-version", "0",
            "--source-ref", SOURCE, "--target-ref", TARGET, "--expected-source", selected_tip, "--expected-target", target,
            "--title", "Native workflow operator", "--body", "Fixed trusted fixture", "--object-format", fmt))
        require(opened["command_committed"] is True and opened["node_closed"] is True, "PR did not commit and close")

    def canonical(number=7, selected_tip=tip):
        page = json.loads(c.run("pr", "checks", repository, TENANT, REPOSITORY, str(number), "--trusted-local", "--object-format", fmt))
        require(page["type"] == "pull_request_checks" and page["schema_version"] == 1
                and page["tenant_id"] == TENANT and page["repository_id"] == REPOSITORY
                and page["repository_incarnation"] == incarnation and page["object_format"] == fmt
                and page["found"] is True and page["number"] == str(number) and page["pull_request_version"] == "1"
                and page["node_closed"] is True and page["source_current"] is True and page["source_tip"] == selected_tip
                and page["target_tip"] == target and page["source_ref_hex"] == SOURCE.encode().hex()
                and page["target_ref_hex"] == TARGET.encode().hex() and page["complete"] is True
                and page["scope"] == "trusted_workflow_observations" and page["merge_permission"] is None,
                "canonical check scope or source/cleanup changed")
        return page

    if supervised:
        def next_revision():
            # A distinct permitted fixture revision; the original failing input,
            # execution and receipts remain retained and keep their conclusions.
            permitted = {**files, (workflow_dir + "/workflow.yml").encode(): (b"100644", workflow.replace(b"exit 7", b"exit 0"))}
            next_tree, _ = file_tree(fmt, permitted, lambda kind, body: loose(source, fmt, kind, body))
            body = (f"tree {next_tree}\nparent {tip}\nauthor Workflow Fixture <workflow@example.invalid> 2 +0000\n"
                    "committer Workflow Fixture <workflow@example.invalid> 2 +0000\n\nPermitted workflow twin\n").encode()
            next_tip = loose(source, fmt, "commit", body)
            (source / SOURCE).write_text(next_tip + "\n")
            verify_fixture(c, source, oracle_run, fmt, "permitted")
            verify_fixture(c, source, oracle_run, fmt, "permitted-bundle", "bundle", "create", "../permitted.bundle", SOURCE)
            c.run("bundle", "sync-import", repository, TENANT, REPOSITORY, home / "permitted.bundle",
                  "--trusted-local", "--object-format", fmt, "--principal", PRINCIPAL, "--key-stdin",
                  "--allow-ref-updates", "--expect", SOURCE + "=" + tip, input_bytes=b"operator-supervisor-permitted-fixture")
            open_pull(8, next_tip)
            return next_tip
        open_pull(7, tip)
        supervisor_case(c, home, repository, config, canonical, next_revision)
        return

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
    artifact_case(c, home, repository, config, credentials, incarnation, token, grants, before)
    open_pull(7, tip)

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
    # Actual complete entrypoints on a prefilled unread stdout pipe. Their
    # original ten-second writer deadline must not leave a Node owner alive.
    def custody_bytes():
        return {str(directory): {p.name: p.read_bytes() if p.is_file() else None
                                 for p in directory.iterdir()} for directory in (watch_state, pub_state)}

    original_custody = custody_bytes()
    watch_status = c.node_command(watch_cli, ["status", *watch_args])
    publication_status = node_rows(c, check_cli, ["status", *pub_args])[-1]
    watch_error = c.node_command(watch_cli, ["status", *watch_args], 2,
                                 error_reply=True, block_stdout=True)
    require(watch_error["type"] == "workflow_watch_error"
            and watch_error["retained_observation"] == watch_status
            and watch_error["execution_retried"] is False,
            "watcher output loss did not retain the original read-only observation")
    require(custody_bytes() == original_custody and marker.read_bytes() == b"sf"
            and canonical() == page and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority,
            "watcher output failure changed custody, execution or canonical state")
    c.facts[f"{fmt}_watch_output_failure_no_execution"] = True
    publication_error = c.node_command(check_cli, ["status", *pub_args], 4,
                                       error_reply=True, block_stdout=True)
    require(publication_error["type"] == "workflow_check_error"
            and publication_error["retained_operation"] == publication_status
            and publication_error["publication_unknown"] is False
            and publication_error["execution_retried"] is False,
            "publisher output loss changed a known completed observation to unknown")
    require(custody_bytes() == original_custody and marker.read_bytes() == b"sf"
            and canonical() == page and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority,
            "publisher output failure changed original keys, terminal custody or canonical state")
    c.facts[f"{fmt}_publication_output_failure_retains_terminal"] = True
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
    parser.add_argument("--supervisor", action="store_true", help="exercise the shipped supervisor over the same native fixture")
    args = parser.parse_args()
    os.umask(0o077)
    fg, node, oracle = args.fg.resolve(strict=True), args.node.resolve(strict=True), args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private work directory required")
    c = OperatorCampaign(fg, node, args.work.resolve())
    summary = dict(complete=False, facts=c.facts, binary_sha256=file_sha256(fg), node_sha256=file_sha256(node),
        entrypoints=["scripts/fg_workflow_supervisor.mjs"] if args.supervisor else
                    ["scripts/fg_workflow_watch.mjs", "scripts/fg_workflow_checks.mjs"],
        supervisor=args.supervisor,
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
            run_case(c, oracle, fmt, args.nested_inputs, args.supervisor)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
