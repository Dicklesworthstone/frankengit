#!/usr/bin/env python3
"""Exercise a stock fast-forward push, HTTP-owned CI and a checked queue landing."""

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

from workflow_http_service import Server, credentials, event_directories
from workflow_watch_continuous import Campaign, Fixture, PRINCIPAL, REF, REPOSITORY, TARGET, TENANT, read_rows

PIN = "git-2.54.0"
ORACLE = Path(__file__).resolve().parents[1] / "oracle/oracle.sh"
PR_SYNC = Path(__file__).resolve().parents[2] / "fg_pull_sync_watch.mjs"


def upstream(*args, data=None):
    result = subprocess.run([ORACLE, *map(str, args)], input=data, stdout=subprocess.PIPE,
                            timeout=60, check=True)
    return result.stdout.decode().strip()


def fresh_push_source(f):
    run = Path(upstream("create-run", PIN, "workflow-landing-" + f.format))
    client = run / "work/client"
    shutil.copytree(f.source, client)
    old = f.tips[f.current]
    stream = (f"commit {REF}\ncommitter CI Source <source@example.test> 1720000000 +0000\n"
              f"data 12\nactual push!\nfrom {old}\nM 100644 inline pushed.txt\n"
              "data 9\nnew bytes\n\ndone\n").encode()
    upstream("run", PIN, run, "client", "--", "fast-import", "--quiet", data=stream)
    tip = upstream("run", PIN, run, "client", "--", "rev-parse", REF)
    parent = upstream("run", PIN, run, "client", "--", "rev-parse", REF + "^")
    assert parent == old and tip not in f.tips + [f.base], (old, parent, tip)
    assert not (f.source / "objects" / tip[:2] / tip[2:]).exists()
    return run, tip


@contextmanager
def receive_listener(f):
    stop = f.root / "receive.stop"
    out = f.root / "receive.out"
    err = f.root / "receive.err"
    args = [f.campaign.binary, "serve", *f.scope, "127.0.0.1:0", "--continuous",
            "--stop-file", stop, "--receive-principal", PRINCIPAL]
    with out.open("wb") as stdout, err.open("wb") as stderr:
        process = subprocess.Popen(list(map(str, args)), stdout=stdout, stderr=stderr)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert process.poll() is None, err.read_bytes()
            row = next((r for r in read_rows(out) if r["type"] == "git_daemon_listening"), None)
            if row is not None:
                break
            time.sleep(0.025)
        else:
            raise TimeoutError("receive listener readiness")
        address = row["address"]
        assert address.startswith("127.0.0.1:") and int(address.split(":")[1]) > 0
        yield address
    finally:
        stop.touch()
        try:
            code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise
        if err.stat().st_size:
            sys.stderr.buffer.write(err.read_bytes())
        assert code == 0, (code, out.read_bytes(), err.read_bytes())


def refs(f):
    raw = f.campaign.invoke("canonical-refs", ["at", *f.scope, "latest", "refs"]).decode(errors="surrogateescape")
    return dict(line.strip().split(" -> ", 1) for line in raw.splitlines() if " -> " in line)


def grant_tip_sync(f):
    token = secrets.token_hex(32)
    with f.credentials.open("a") as grants:
        digest = hashlib.sha256(token.encode()).hexdigest()
        grants.write(f"{digest} {PRINCIPAL} read,pulls-read,pulls-write\n")
    return token


@contextmanager
def tip_sync_command(f, server, token):
    state = f.root / "pr-sync"
    state.mkdir(mode=0o700)
    destination = dict(endpoint=server.endpoint.geturl(), tenant_id=TENANT, repository_id=REPOSITORY,
                       repository_incarnation=f.incarnation, principal_id=PRINCIPAL, object_format=f.format)
    config = dict(schema="frankengit-pr-sync-watch-v1", destination=destination, selected=[1],
                  state_directory=str(state), max_batches=2, state_bytes=1048576, policy="recorded-tips-only")
    with tempfile.TemporaryDirectory() as private:
        config_path, token_path = (Path(private) / name for name in ("watch.json", "token"))
        for path, value in ((config_path, json.dumps(config)), (token_path, token)):
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
                out.write(value)
        yield [os.environ.get("FGE_NODE", "node"), PR_SYNC, "serve", "--config", config_path,
               "--token-file", token_path, "--allow-tip-updates", "--poll-millis", "100"]


def watch_pushed_tip(f, server, token):
    with tip_sync_command(f, server, token) as command:

        def run(label, polls):
            log = f.root / f"pr-sync-{label}.ndjson"
            with log.open("xb") as out:
                subprocess.run([*command, "--max-polls", str(polls)], stdout=out, timeout=45, check=True)
            return read_rows(log)

        published, first, idle, summary = run("after-push", 2)
        assert published["type"] == "pull_sync_observed" and published["outcome"] == "committed"
        assert published["number"] == 1 and published["tx_id"]
        assert first["type"] == "pull_sync_watch_sweep" and first["updates"] == first["committed"] == 1
        assert idle["unchanged"] == [1] and idle["updates"] == 0
        assert summary["updates"] == 1 and summary["refused"] == summary["read_failures"] == 0
        assert not summary["refs_changed"] and not summary["approvals_carried_forward"]
        resumed, finish = run("restart", 1)
        assert resumed["unchanged"] == [1] and resumed["updates"] == finish["updates"] == 0
        assert resumed["batches"] == idle["batches"] and finish["read_failures"] == 0
        return published


def policy(f, graph, job, version, epoch):
    pub = f.campaign.invoke("require-" + job, [
        "protection", "set", *f.scope, "--trusted-local", "--principal", PRINCIPAL,
        "--admin", PRINCIPAL, "--idempotency-key", "require-" + str(version),
        "--expected-version", version, "--expected-epoch", epoch, "--object-format", f.format,
        "--require-merge-queue", TARGET, "--require-check", f"{TARGET}:{REF}:{PRINCIPAL}:{graph}:{job}",
    ])
    result = json.loads(pub)
    assert result["committed"] and result["committed_policy_epoch"] == epoch + 1, result
    return result["committed_policy_epoch"]


def queue(f, action, version, key, flags, expected):
    result = json.loads(f.campaign.invoke(key, [
        "queue", action, *f.scope, 1, "--trusted-local", "--expected-incarnation", f.incarnation,
        "--object-format", f.format, "--principal", PRINCIPAL, "--idempotency-key", key,
        "--expected-version", version, "--target-ref", TARGET, "--source-ref", REF,
        "--pull-request", 1, "--expected-pull-version", 2,
        "--expected-source-tip", f.tips[f.current], "--expected-target-tip", f.base, *flags,
    ], 0 if expected else 3))
    assert result["node_closed"] and result["cleanup_error"] is None
    assert result["committed"] is expected and result["refs_changed"] is (expected and action == "land"), result
    if not expected:
        assert result["refusal_code"] == "ProtectedRefTransitionDenied", result
    return result


def lifecycle(campaign, fmt):
    f = Fixture(campaign, fmt, "push-landing")
    credentials(f)
    sync_token = grant_tip_sync(f)
    f.open_pull()
    run, tip = fresh_push_source(f)
    initial = refs(f)
    assert initial[REF] == f.tips[0] and initial[TARGET] == f.base and tip not in initial.values()
    browse = [*f.scope, "--trusted-local", "--object-format", fmt]
    tree = json.loads(campaign.invoke("pre-push-tree", ["tree", *browse, "--ref", REF]))
    assert tree["source_commit"] == initial[REF] and not tree["has_more"]
    assert b"pushed.txt" not in [bytes.fromhex(row["name_hex"]) for row in tree["entries"]]
    with Server(f, "before-push", publish=True) as server:
        server.ready()
        prior = server.check()
        server.wait(lambda _: any((e / "reported").is_file() for e in event_directories(f)))
        server.stop()
    graph = prior["graph_root"]
    epoch = policy(f, graph, "a", 0, 1)
    with Server(f, "receive-with-publication-disabled", source_reads=True) as server:
        server.ready()
        with receive_listener(f) as address:
            upstream("push-loopback", PIN, run, "push", address, f"/{REPOSITORY}.git",
                     "client", "plain", f"{REF}:{REF}")
        transcript = run / "transcripts/push"
        porcelain = (transcript / "stdout.bin").read_text()
        assert f"{REF}:{REF}" in porcelain and "[up to date]" not in porcelain, porcelain
        shutil.copyfile(transcript / "receipt.tsv", f.root / "pinned-push.tsv")
        assert refs(f) == {**initial, REF: tip}
        # The push must run CI while the PR still records its original tip.
        server.wait(lambda _: f.effects_count() == 2 and len(event_directories(f)) == 2 and all(
            (event / "settled").is_file() for event in event_directories(f)))
        reports = []
        for event in event_directories(f):
            report_path, = event.glob("dispatch-*/workflow-*/report.json")
            report = json.loads(report_path.read_bytes())
            assert report["type"] == "trusted_workflow_run" and report["workspaces_closed"], report
            assert not report["request_interrupted"], report
            reports.append(report["executed_commit"])
        assert sorted(reports) == sorted([initial[REF], tip]), reports
        status, body = server.request("GET", "/api/v1/pulls/1/checks")
        former = json.loads(body)
        assert status == 200 and former["source_current"] is False, former
        assert former["source_tip"] == f.tips[0] and int(former["pull_request_version"]) == 1, former
        assert former["complete"] and former["checks"] == [], former
        stale_detail = json.loads(campaign.invoke("stale-pr-with-checks", [
            "pr", "show", *f.scope, 1, "--trusted-local", "--checks", "--object-format", fmt,
            "--expected-head", former["snapshot_token"]]))
        stale_page = stale_detail["workflow_checks"]
        assert stale_detail["source_head"] == stale_page["source_head"] == former["source_head"]
        assert stale_detail["pull_request"]["version"] == int(stale_page["pull_request_version"]) == 1
        assert stale_page["source_tip"] == former["source_tip"] and not stale_page["source_current"]
        assert stale_page["complete"] and stale_page["checks"] == []
        updated = watch_pushed_tip(f, server, sync_token)
        assert refs(f) == {**initial, REF: tip} and f.effects_count() == 2
        f.tips[0] = tip
        status, body = server.request("GET", "/api/v1/pulls/1/checks")
        empty = json.loads(body)
        assert status == 200 and empty["source_current"] and empty["source_tip"] == tip, empty
        assert int(empty["pull_request_version"]) == 2 and empty["complete"] and empty["checks"] == [], empty
        detail_args = ["pr", "show", *f.scope, 1, "--trusted-local", "--checks", "--object-format", fmt]
        synced = json.loads(campaign.invoke("auto-refreshed-pr", [
            *detail_args, "--expected-head", empty["snapshot_token"]]))["pull_request"]
        assert synced["version"] == 2 and synced["state"] == "open"
        assert synced["data"] == {**stale_detail["pull_request"]["data"], "source_tip": tip}
        historical = json.loads(campaign.invoke("prior-pr-with-checks", [
            *detail_args, "--expected-head", former["snapshot_token"]]))
        assert historical == stale_detail, historical
        queue(f, "enqueue", 0, "enqueue-pushed-tip", ["--priority", 0], True)
        stale = queue(f, "land", 1, "prior-success-cannot-land", ["--expected-policy-epoch", epoch], False)
        assert refs(f)[TARGET] == f.base
        server.stop()
    with Server(f, "publish-pushed-tip", publish=True) as server:
        server.ready()
        checked = server.check()
        assert checked["graph_root"] == graph and checked["id"] != prior["id"], checked
        assert f.effects_count() == 2
        epoch = policy(f, graph, "missing", 1, epoch)
        wrong = queue(f, "land", 1, "wrong-job-cannot-land", ["--expected-policy-epoch", epoch], False)
        assert refs(f)[TARGET] == f.base
        epoch = policy(f, graph, "a", 2, epoch)
        landed = queue(f, "land", 1, "exact-job-lands", ["--expected-policy-epoch", epoch], True)
        assert landed["proposed_action"]["method"] == "fast-forward-only", landed
        assert refs(f) == {**initial, REF: tip, TARGET: tip}
        file = json.loads(campaign.invoke("landed-file", [
            "show", *browse, "--ref", TARGET, "--path", "pushed.txt", "--expected-commit", tip,
        ]))
        assert file["source_commit"] == tip and bytes.fromhex(file["bytes_hex"]) == b"new bytes"
        pull = json.loads(campaign.invoke("merged-pr", [
            "pr", "show", *f.scope, 1, "--trusted-local", "--object-format", fmt]))
        assert pull["pull_request"]["state"] == "merged" and pull["pull_request"]["version"] == 3, pull
        checks = json.loads(campaign.invoke("merged-pr-checks", [
            "pr", "checks", *f.scope, 1, "--trusted-local", "--object-format", fmt,
            "--expected-head", pull["snapshot_token"]]))
        assert checks["source_head"] == pull["source_head"] and checks["node_closed"], checks
        assert int(checks["pull_request_version"]) == 3 and checks["source_current"], checks
        assert checks["source_tip"] == tip and checks["complete"] and checks["checks"] == [checked], checks
        joined = json.loads(campaign.invoke("merged-pr-with-checks", detail_args))
        joined_page = joined.pop("workflow_checks")
        assert joined == pull and joined_page["checks"] == [checked], joined
        fields = ("found", "source_head", "snapshot_token", "pull_request_version", "source_ref_hex",
                  "target_ref_hex", "source_tip", "target_tip", "source_current", "next_after",
                  "complete", "checks")
        assert joined_page == {field: checks[field] for field in fields}, joined_page
        missing = json.loads(campaign.invoke("absent-pr-with-checks", [
            "pr", "show", *f.scope, 99, "--trusted-local", "--checks", "--object-format", fmt], code=4))
        assert not missing["found"] and missing["pull_request"] is None and missing["workflow_checks"] is None
        drained, _ = server.stop()
        assert not drained["requires_reconciliation"] and not drained["execution_retried"], drained
    campaign.record(fmt, "stock-push-http-check-protected-fast-forward", source=tip,
                    executed_before_pr_refresh=sorted(reports), merged_check_snapshot=pull["snapshot_token"],
                    former_target=f.base, pull_request=1, refreshed_version=2,
                    sync_transaction=updated["tx_id"], sync_decision_sequence=updated["decision_sequence"],
                    former_check=prior["id"], check=checked["id"],
                    workflow_graph=graph, publisher=checked["publisher"], job=checked["job"],
                    old_tip_refusal=stale["refusal_code"],
                    wrong_job_refusal=wrong["refusal_code"], oracle_pin=PIN,
                    landing_sequence=landed["decision_sequence"], executions=f.effects_count())


def push_with_both_services_running(campaign, fmt):
    boundary = b"refs/heads/01-\xff"
    packed = [f"refs/heads/00-{i:02d}".encode("ascii") for i in range(49)]
    f = Fixture(campaign, fmt, "live-push", packed_refs=packed)
    created = json.loads(campaign.invoke("byte-named-branch", [
        "branch", "create", *f.scope, "--trusted-local", "--object-format", fmt,
        "--principal", PRINCIPAL, "--idempotency-key", "byte-branch", "--ref-hex", boundary.hex(),
        "--target", f.base]))
    assert created["command_committed"], created
    credentials(f)
    sync_token = grant_tip_sync(f)
    f.open_pull()
    run, tip = fresh_push_source(f)
    initial = refs(f)
    log = f.root / "live-pr-sync.ndjson"
    with Server(f, "live-push", publish=True, source_reads=True) as server:
        server.ready()
        prior = server.check()
        query = dict(object_format=fmt, namespace="branches", limit=50, cursor_encoding="hex")
        status, body = server.request("POST", "/api/v1/source/refs", fields=query)
        inventory = json.loads(body)
        assert status == 200 and inventory["next_after"] == boundary.hex()
        assert inventory["refs"][-1]["ref"] is None and len(inventory["refs"]) == 50
        with tip_sync_command(f, server, sync_token) as command, log.open("xb") as output:
            watcher = subprocess.Popen([*command, "--max-polls", "600"], stdout=output)
            try:
                def watch_observed(_):
                    assert watcher.poll() is None, read_rows(log)
                    return any(row.get("unchanged") == [1] for row in read_rows(log))

                server.wait(watch_observed)
                with receive_listener(f) as address:
                    upstream("push-loopback", PIN, run, "push", address, f"/{REPOSITORY}.git",
                             "client", "plain", f"{REF}:{REF}")

                def has_check_at_new_tip(_):
                    assert watcher.poll() is None, read_rows(log)
                    status, body = server.request("GET", "/api/v1/pulls/1/checks")
                    page = json.loads(body)
                    assert status == 200, page
                    return page["source_current"] and page["source_tip"] == tip and bool(page["checks"])

                server.wait(has_check_at_new_tip)
            finally:
                if watcher.poll() is None:
                    watcher.terminate()
                try:
                    watcher.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    watcher.kill()
                    watcher.wait(timeout=5)
                    raise
        assert watcher.returncode == 0
        observations = read_rows(log)
        update, = [row for row in observations if row["type"] == "pull_sync_observed"]
        assert update["outcome"] == "committed" and update["number"] == 1
        summary = observations[-1]
        assert summary["type"] == "pull_sync_watch_service" and summary["stopped"]
        assert summary["updates"] == 1 and summary["refused"] == 0
        status, body = server.request("GET", "/api/v1/pulls/1/checks")
        page = json.loads(body)
        assert status == 200 and int(page["pull_request_version"]) == 2 and page["complete"], page
        assert page["source_current"] and page["source_tip"] == tip and page["target_tip"] == f.base
        check, = page["checks"]
        assert check["id"] != prior["id"] and check["job"] == "a" and check["conclusion"] == "success"
        assert check["publisher"] == PRINCIPAL and check["graph_root"] == prior["graph_root"]
        assert refs(f) == {**initial, REF: tip} and f.effects_count() == 2
        drained, _ = server.stop()
        assert not drained["requires_reconciliation"] and drained["checks_committed"] == 2
    campaign.record(fmt, "unattended-stock-push-visible-on-existing-pr", source=tip,
                    sync_transaction=update["tx_id"], before_push=prior["id"], check=check["id"],
                    pull_request_version=2, executions=f.effects_count(), oracle_pin=PIN,
                    branch_page_boundary=boundary.hex())


def check_pagination(campaign, fmt):
    jobs = [f"job-{index:02}" for index in range(21)]
    workflow = "name: paginated-checks\non: push\njobs:\n" + "".join(
        f"  {job}:\n    runs-on: fgit-trusted-local\n    steps:\n      - run: printf {job}\n"
        for job in jobs)
    f = Fixture(campaign, fmt, "check-pages", workflow_source=workflow)
    credentials(f)
    f.open_pull()
    args = [*f.scope, 1, "--trusted-local", "--object-format", fmt]
    with Server(f, "check-pages", publish=True) as server:
        server.ready()
        server.wait(lambda _: any((e / "reported").is_file() for e in event_directories(f)))
        status, body = server.request("GET", "/api/v1/pulls/1/checks?limit=100")
        whole = json.loads(body)
        assert status == 200 and whole["complete"] and len(whole["checks"]) == len(jobs), whole
        rows = whole["checks"]
        assert {row["job"] for row in rows} == set(jobs)
        assert all(row["conclusion"] == "success" and row["publisher"] == PRINCIPAL for row in rows)
        assert len({row["id"] for row in rows}) == len(jobs)
        detail = json.loads(campaign.invoke("first-twenty-checks", [
            "pr", "show", *args, "--checks", "--expected-head", whole["snapshot_token"]]))
        page = detail["workflow_checks"]
        assert detail["source_head"] == page["source_head"] == whole["source_head"]
        assert page["checks"] == rows[:20] and not page["complete"]
        assert page["next_after"] == rows[19]["id"] and page["snapshot_token"] == whole["snapshot_token"]
        last = json.loads(campaign.invoke("remaining-checks", [
            "pr", "checks", *args, "--after", page["next_after"], "--expected-head", page["snapshot_token"]]))
        assert last["source_head"] == page["source_head"] and last["checks"] == rows[20:]
        assert last["complete"] and last["next_after"] is None
        drained, _ = server.stop()
        assert drained["checks_committed"] == len(jobs) and drained["checks_refused"] == 0, drained
    campaign.record(fmt, "pr-detail-check-continuation", first_page=len(page["checks"]),
                    final_page=len(last["checks"]), published=len(rows), snapshot=page["snapshot_token"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    campaign = Campaign(args.binary.resolve(), args.output.resolve())
    for fmt in ("sha1", "sha256"):
        lifecycle(campaign, fmt)
        push_with_both_services_running(campaign, fmt)
        check_pagination(campaign, fmt)
