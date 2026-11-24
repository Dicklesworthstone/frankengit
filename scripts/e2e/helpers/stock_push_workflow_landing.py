#!/usr/bin/env python3
"""Exercise a stock fast-forward push, HTTP-owned CI and a checked queue landing."""

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

from workflow_http_service import Server, credentials, event_directories
from workflow_watch_continuous import Campaign, Fixture, PRINCIPAL, REF, REPOSITORY, TARGET, read_rows

PIN = "git-2.54.0"
ORACLE = Path(__file__).resolve().parents[1] / "oracle/oracle.sh"


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
    raw = f.campaign.invoke("canonical-refs", ["at", *f.scope, "latest", "refs"]).decode()
    return dict(line.strip().split(" -> ", 1) for line in raw.splitlines() if " -> " in line)


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
    with Server(f, "receive-with-publication-disabled") as server:
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
        updated = json.loads(campaign.invoke("refresh-existing-pull", [
            "pr", "update", *f.scope, 1, "--trusted-local", "--principal", PRINCIPAL,
            "--idempotency-key", "refresh-pushed-subject", "--expected-version", 1,
            "--source-ref", REF, "--target-ref", TARGET, "--expected-source", tip,
            "--expected-target", f.base, "--title", "Continuous native check",
            "--body", "Actual retained workflow evidence", "--object-format", fmt,
        ]))
        assert updated["command_committed"] and not updated["refs_changed"], updated
        f.tips[0] = tip
        status, body = server.request("GET", "/api/v1/pulls/1/checks")
        empty = json.loads(body)
        assert status == 200 and empty["source_current"] and empty["source_tip"] == tip, empty
        assert int(empty["pull_request_version"]) == 2 and empty["complete"] and empty["checks"] == [], empty
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
        drained, _ = server.stop()
        assert not drained["requires_reconciliation"] and not drained["execution_retried"], drained
    campaign.record(fmt, "stock-push-http-check-protected-fast-forward", source=tip,
                    executed_before_pr_refresh=sorted(reports), merged_check_snapshot=pull["snapshot_token"],
                    former_target=f.base, pull_request=1, refreshed_version=2,
                    former_check=prior["id"], check=checked["id"],
                    workflow_graph=graph, publisher=checked["publisher"], job=checked["job"],
                    old_tip_refusal=stale["refusal_code"],
                    wrong_job_refusal=wrong["refusal_code"], oracle_pin=PIN,
                    landing_sequence=landed["decision_sequence"], executions=f.effects_count())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    campaign = Campaign(args.binary.resolve(), args.output.resolve())
    for fmt in ("sha1", "sha256"):
        lifecycle(campaign, fmt)
