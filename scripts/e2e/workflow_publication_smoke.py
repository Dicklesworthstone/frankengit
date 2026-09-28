#!/usr/bin/env python3
"""Real trusted workflow -> saved evidence -> canonical check -> PR read campaign.

The self-test validates only fixture bytes and result checkers. The --fg mode
runs the actual binary in a fresh process for every operation, using independently
encoded native Git objects; no stock Git, simulated runner, or fabricated journal.
"""

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import zlib

from pull_request_smoke import (
    PRINCIPAL, REPOSITORY, SOURCE, TARGET, TENANT,
    commit, data_for, document, identity, invoke, publication, require, sha256_stream,
)

RUN_ID = "61" * 16
JOBS = {"a_success": ("succeeded", "action_required", 0, b"workflow-ok"),
        "b_failure": ("failed", "failure", 7, b"workflow-failed")}


def fixture(root, algorithm, execution_log):
    """Create real loose objects including a reachable future source commit."""
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n", encoding="ascii")
    (root / "config").write_text(
        "[core]\nbare = true\nrepositoryformatversion = " +
        ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"),
        encoding="ascii")

    def store(kind, body):
        oid = identity(algorithm, kind, body)
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid

    # The private, caller-owned log makes any accidental execution retry visible
    # even after the job workspaces have been closed and removed.
    log = shlex.quote(str(execution_log))
    workflow = (
        "name: publication\non: push\njobs:\n"
        "  a_success:\n    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: printf s >> {log}; printf workflow-ok\n"
        "  b_failure:\n    runs-on: fgit-trusted-local\n    steps:\n"
        f"      - run: printf f >> {log}; printf workflow-failed; exit 7\n"
    ).encode()
    blob = store("blob", workflow)
    tree = store("tree", b"100644 workflow.yml\0" + bytes.fromhex(blob))
    target = store("commit", commit(tree, [], "target"))
    source = store("commit", commit(tree, [target], "workflow input"))
    advanced = store("commit", commit(tree, [source], "later source"))
    for name, tip in [(TARGET, target), (SOURCE, source), ("refs/heads/advanced", advanced),
                      ("refs/heads/same-tip", source)]:
        (root / name).write_text(tip + "\n", encoding="ascii")
    return dict(blob=blob, tree=tree, target=target, source=source, advanced=advanced)


def check_id(entry, fact):
    # fgit-forge's native workflow-check identity v1, independently encoded.
    preimage = (b"frankengit/trusted-workflow-check/v1\0" + bytes.fromhex(PRINCIPAL)
                + bytes.fromhex(entry["run_sha256"]) + bytes.fromhex(entry["attempt_sha256"])
                + hashlib.sha256(fact["job"].encode()).digest())
    return "check/" + base64.b32hexencode(hashlib.sha256(preimage).digest()).decode().lower().rstrip("=")


def expected_observation(entry, fact, evidence):
    require(hashlib.sha256(evidence).hexdigest() == fact["evidence_sha256"], "evidence commitment")
    return dict(id=check_id(entry, fact), publisher=PRINCIPAL, run_id=entry["run_sha256"],
                attempt_id=entry["attempt_sha256"], graph_root=entry["workflow_graph_sha256"],
                job=fact["job"], conclusion=JOBS[fact["job"]][1],
                evidence_sha256=fact["evidence_sha256"], evidence_bytes=str(len(evidence)))


def check_publication(report, algorithm, f, incarnation, journal, entry, index,
                      observation, committed=True, refusal=None):
    require(report["type"] == "workflow_check_publication" and report["schema_version"] == 1,
            "workflow publication schema")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY
            and report["repository_incarnation"] == incarnation, "publication repository scope")
    require(report["principal_id"] == PRINCIPAL and report["object_format"] == algorithm,
            "publication principal/hash domain")
    require(report["source_ref_hex"] == SOURCE.encode().hex()
            and report["source_commit"] == f["source"], "publication exact executed source")
    require(report["journal_id"] == journal and report["batch_sha256"] == entry["batch_sha256"]
            and type(report["fact_index"]) is int and report["fact_index"] == index,
            "publication exact saved fact")
    require(report["check_id"] == observation["id"], "independently derived check identity")
    for key in ["job", "conclusion", "run_id", "attempt_id", "graph_root", "evidence_sha256"]:
        require(report[key] == observation[key], f"publication {key} binding")
    require(type(report["evidence_bytes"]) is int
            and str(report["evidence_bytes"]) == observation["evidence_bytes"], "publication evidence size")
    require(report["command_committed"] is committed
            and report["outcome"] == ("committed" if committed else "refused"), "terminal outcome")
    require(report["historical_outcome"] is True and report["current_refs_asserted"] is False,
            "historical receipt claims")
    require(report["trusted_local"] is True and report["scope"] == "trusted_workflow_observations"
            and report["merge_permission"] is None and report["authoritative_check"] is False,
            "local observation authority boundary")
    require(report["execution_retried"] is False and report["journal_acknowledged"] is False
            and report["refs_changed"] is False and report["delivery_acknowledged"] is None
            and report["evidence_payload_included"] is False, "publication effect/disclosure claims")
    require(report["node_closed"] is True and report["cleanup_error"] is None, "publisher cleanup")
    require(isinstance(report["decision_sequence"], str)
            and re.fullmatch(r"[1-9][0-9]*", report["decision_sequence"]) is not None, "decision position")
    require(report["tx_id"].startswith("frankengit/ref-txn/v2/"), "canonical transaction ID")
    if committed:
        require(report["repository_commit_id"].startswith("frankengit/rcr/v1/")
                and report["refusal_code"] is None and report["refusal_record_id"] is None,
                "committed repository decision")
    else:
        require(report["repository_commit_id"] is None and report["refusal_code"] == refusal
                and report["refusal_record_id"].startswith("frankengit/refusal-record/v1/"),
                "canonical refusal decision")
    require(not {"evidence", "stdout_hex", "stderr_hex", "idempotency_key"}.intersection(report),
            "publisher disclosed raw evidence or the scoped key")


def check_page(report, algorithm, f, incarnation, observations, current=True, after=None, limit=20,
               continuation=None):
    require(report["type"] == "pull_request_checks" and report["schema_version"] == 1, "PR check schema")
    require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY
            and report["repository_incarnation"] == incarnation and report["object_format"] == algorithm,
            "PR check repository scope")
    require(report["number"] == "7" and report["pull_request_version"] == "1" and report["found"] is True,
            "PR check exact aggregate")
    require(report["source_ref_hex"] == SOURCE.encode().hex() and report["target_ref_hex"] == TARGET.encode().hex()
            and report["source_tip"] == f["source"] and report["target_tip"] == f["target"],
            "PR check exact recorded branches and commits")
    require(report["scope"] == "trusted_workflow_observations" and report["merge_permission"] is None,
            "local job observation was promoted to merge permission")
    require(report["source_current"] is current and report["node_closed"] is True, "PR source/cleanup state")
    require(report["source_head"].startswith("frankengit/authority-head/v1/")
            and re.fullmatch(r"alg:[1-9][0-9]*:[0-9a-f]{64}", report["snapshot_token"]) is not None,
            "authenticated check snapshot")
    require(report["checks"] == observations, "PR exposed wrong, reordered, missing or duplicate observations")
    require(report["after"] == after and report["limit"] == limit and report["next_after"] == continuation
            and report["complete"] is (continuation is None), "PR check page window")


def changed(arguments, flag, value):
    result = arguments.copy()
    result[result.index(flag) + 1] = str(value)
    return result


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-workflow-publication-") as temporary:
        root = Path(temporary).resolve()
        node, source, runs = root / "node", root / "source", root / "runs"
        runs.mkdir(mode=0o700)
        executions = root / "executions.log"
        f = fixture(source, algorithm, executions)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "workflow-publication-fixture", source])
        refs = ["at", node, TENANT, REPOSITORY, "latest", "refs"]
        original_refs = invoke(binary, refs).stdout
        listing = ["pr", "list", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm]
        initial = document(invoke(binary, listing))
        run = ["workflow", "run", node, TENANT, REPOSITORY, SOURCE, "--trusted-local",
               "--workflow", "workflow.yml", "--input", "workflow.yml", "--run-parent", runs,
               "--run-id", RUN_ID, "--expected-commit", f["source"], "--object-format", algorithm]
        untrusted = run.copy(); untrusted.remove("--trusted-local")
        require(not invoke(binary, untrusted, 2).stdout and not executions.exists(), "untrusted execution ran code")
        result = document(invoke(binary, run, 1))
        require(result["type"] == "workflow_result" and result["node_closed"] is True, "real workflow result")
        report = result["run"]
        require(report["source_commit"] == f["source"] and report["executed_commit"] == f["source"]
                and report["authoritative_check"] is False and report["published"] is False
                and report["succeeded"] is False and report["workspaces_closed"] is True
                and report["request_interrupted"] is False, "execution/source/publication boundary")
        incarnation = report["repository_incarnation"]
        jobs = {job["id"]: job for job in report["execution"]["jobs"]}
        require(set(jobs) == set(JOBS), "both independent real jobs must execute")
        for name, (outcome, _, code, output) in JOBS.items():
            job = jobs[name]
            require(job["outcome"] == outcome and len(job["steps"]) == 1, "real job outcome")
            require(job["steps"][0]["exit_code"] == code and job["steps"][0]["stdout_hex"] == output.hex(),
                    "actual shell exit/output")
        require(executions.read_bytes() == b"sf", "each job must execute exactly once")
        require(not invoke(binary, run, 2).stdout and executions.read_bytes() == b"sf",
                "occupied run was executed again")
        require(document(invoke(binary, listing)) == initial, "execution published repository state")
        directory = runs / f"workflow-{RUN_ID}"
        require(Path(os.fsdecode(bytes.fromhex(report["run_directory_hex"]))) == directory, "run directory binding")
        require(json.loads((directory / "report.json").read_text()) == report, "saved final run report")
        # Retain the original marker commitment before exercising hostile input.
        # This trusted fixture capture is not a claim that hashing unknown storage authenticates it.
        marker = hashlib.sha256((directory / "attempt.json").read_bytes()).hexdigest()
        retained = {name: (directory / name).read_bytes()
                    for name in ["attempt.json", "execution.owner", "check-proposals.journal"]}
        recovery = ["workflow", "recover", directory, TENANT, REPOSITORY, "--journal-id", marker]
        history = document(invoke(binary, recovery))
        require(history["type"] == "workflow_custody_history" and history["authoritative_check"] is False
                and history["execution_retried"] is False and history["next_after"] is None
                and history["scope"] == dict(tenant=TENANT, repository=REPOSITORY, journal_id=marker),
                "exact offline custody scope")
        completed, unfinished = {}, []
        for entry in history["entries"]:
            require(entry["source_commit"] == f["source"] and entry["object_format"] == algorithm
                    and entry["delivery"] == "pending" and entry["delivery_receipt_sha256"] is None,
                    "custody source/unacknowledged state")
            for index, fact in enumerate(entry["facts"]):
                if fact["status"] == "completed":
                    require(fact["job"] not in completed, "duplicate terminal job fact")
                    require(fact["conclusion"] == JOBS[fact["job"]][1], "job conclusion in retained evidence")
                    completed[fact["job"]] = (entry, index, fact)
                else:
                    unfinished.append((entry, index))
        require(set(completed) == set(JOBS) and unfinished, "recover terminal and nonterminal facts")
        observations, commands, receipts = {}, {}, {}
        for name, (entry, index, fact) in completed.items():
            exported = root / f"evidence-{name}.bin"
            exported_meta = document(invoke(binary, recovery + ["--batch", entry["batch_sha256"],
                                     "--evidence", fact["evidence_sha256"], "--output", exported]))
            evidence = exported.read_bytes()
            require(exported_meta["artifact"]["sha256"] == fact["evidence_sha256"]
                    and exported_meta["artifact"]["bytes"] == len(evidence), "exact exported evidence body")
            observations[name] = expected_observation(entry, fact, evidence)
            commands[name] = ["workflow", "publish", node, TENANT, REPOSITORY, SOURCE, "--trusted-local",
                              "--run-directory", directory, "--journal-id", marker,
                              "--batch", entry["batch_sha256"], "--fact-index", index,
                              "--principal-id", PRINCIPAL, "--idempotency-key", f"publish-{name}",
                              "--minimum-pin", history["snapshot"], "--object-format", algorithm,
                              "--expected-incarnation", incarnation]

        # A final report and the external import directory are not evidence inputs.
        # Keep the original run slot, marker, owner and journal intact.
        (directory / "report.json").unlink()
        shutil.rmtree(source)
        valid = commands["a_success"]
        no_trust = valid.copy(); no_trust.remove("--trusted-local")
        unknown = "ff" * 32
        negatives = [no_trust, changed(valid, "--journal-id", unknown), changed(valid, "--batch", unknown),
                     changed(valid, "--fact-index", 127), changed(valid, "--expected-incarnation", "ff" * 16),
                     changed(valid, "--minimum-pin", history["snapshot"].split(":")[0] + ":" + unknown)]
        wrong_scope = valid.copy(); wrong_scope[3] = "ee" * 16; negatives.append(wrong_scope)
        first, fact_index = unfinished[0]
        negatives.append(changed(changed(valid, "--batch", first["batch_sha256"]), "--fact-index", fact_index))
        corrupt = root / "corrupt-run"
        shutil.copytree(directory, corrupt)
        damaged = bytearray((corrupt / "check-proposals.journal").read_bytes()); damaged[-1] ^= 1
        (corrupt / "check-proposals.journal").write_bytes(damaged)
        negatives.append(changed(valid, "--run-directory", corrupt))
        for arguments in negatives:
            require(not invoke(binary, arguments, 2).stdout, "invalid evidence produced a terminal publication receipt")
        require(document(invoke(binary, listing)) == initial, "invalid evidence changed repository authority")

        output_fault = False
        for name in JOBS:
            entry, index, _ = completed[name]
            if name == "b_failure" and Path("/dev/full").exists():
                with open("/dev/full", "wb") as full:
                    failed = subprocess.run([str(binary), *map(str, commands[name])], stdout=full,
                                            stderr=subprocess.PIPE, timeout=120)
                require(failed.returncode == 2 and b"is committed" in failed.stderr,
                        "receipt-output failure lost its known terminal commit")
                before_retry = document(invoke(binary, listing))
                output_fault = True
            receipt = document(invoke(binary, commands[name]))
            check_publication(receipt, algorithm, f, incarnation, marker, entry, index, observations[name])
            receipts[name] = receipt
            if name == "b_failure" and output_fault:
                require(document(invoke(binary, listing)) == before_retry, "output-failure retry published twice")
        require(invoke(binary, refs).stdout == original_refs, "workflow publication changed code refs")
        published = document(invoke(binary, listing))
        require(published["source_head"] != initial["source_head"], "completed checks never entered authority")
        require(document(invoke(binary, recovery)) == history, "publication acknowledged or rewrote custody")

        metadata = data_for(f, "Review actual local job observations", "Local outcomes do not grant merge permission.")
        opened = document(invoke(binary, ["pr", "open", node, TENANT, REPOSITORY, "7", "--trusted-local",
                          "--principal", PRINCIPAL, "--idempotency-key", "workflow-pr-open", "--expected-version", "0",
                          "--source-ref", SOURCE, "--target-ref", TARGET, "--expected-source", f["source"],
                          "--expected-target", f["target"], "--title", metadata["title"], "--body", metadata["body"],
                          "--object-format", algorithm]))
        publication(opened, algorithm, 7, "open", 0, metadata)
        checks = ["pr", "checks", node, TENANT, REPOSITORY, "7", "--trusted-local", "--object-format", algorithm]
        ordered = sorted(observations.values(), key=lambda row: row["id"])
        page = document(invoke(binary, checks))
        check_page(page, algorithm, f, incarnation, ordered)
        require(document(invoke(binary, checks)) == page, "fresh-process reopen changed canonical observations")
        first_page = document(invoke(binary, checks + ["--limit", 1, "--expected-head", page["snapshot_token"]]))
        check_page(first_page, algorithm, f, incarnation, ordered[:1], limit=1, continuation=ordered[0]["id"])
        second_page = document(invoke(binary, checks + ["--limit", 1, "--after", first_page["next_after"],
                                "--expected-head", first_page["snapshot_token"]]))
        check_page(second_page, algorithm, f, incarnation, ordered[1:], after=ordered[0]["id"], limit=1)
        require(second_page["source_head"] == first_page["source_head"] == page["source_head"], "mixed check page heads")
        for name in JOBS:
            require(document(invoke(binary, commands[name])) == receipts[name], "same publication retry changed terminal")
        require(document(invoke(binary, checks)) == page, "same publication retry created duplicate checks")
        reused_key = changed(commands["b_failure"], "--idempotency-key", "publish-a_success")
        require(not invoke(binary, reused_key, 2).stdout, "same key accepted different job semantics")
        changed_subject = valid.copy(); changed_subject[5] = "refs/heads/same-tip"
        require(not invoke(binary, changed_subject, 2).stdout,
                "same key accepted a different branch at the exact same commit")
        require(document(invoke(binary, checks)) == page, "key-reuse mismatch changed authority")

        moved = document(invoke(binary, ["branch", "update", node, TENANT, REPOSITORY, "--trusted-local",
                         "--principal", PRINCIPAL, "--idempotency-key", "advance-workflow-source", "--ref", SOURCE,
                         "--expected-tip", f["source"], "--target", f["advanced"], "--object-format", algorithm]))
        require(moved["command_committed"] is True, "advance exact canonical source")
        stale = document(invoke(binary, checks))
        check_page(stale, algorithm, f, incarnation, [], current=False)
        for name in JOBS:
            require(document(invoke(binary, commands[name])) == receipts[name], "source movement erased historical terminal")
        require(document(invoke(binary, checks)) == stale, "historical retry republished after source movement")
        require(document(invoke(binary, checks + ["--expected-head", page["snapshot_token"]])) == page,
                "retained source snapshot lost its exact historical observations")
        new_attempt = changed(valid, "--idempotency-key", "new-request-old-workflow-source")
        rejected = document(invoke(binary, new_attempt, 3))
        entry, index, _ = completed["a_success"]
        check_publication(rejected, algorithm, f, incarnation, marker, entry, index,
                          observations["a_success"], False, "TargetRefMoved")
        refused_head = document(invoke(binary, checks))
        require(document(invoke(binary, new_attempt, 3)) == rejected, "canonical refusal retry changed terminal")
        require(document(invoke(binary, checks)) == refused_head, "canonical refusal retry published again")
        require(executions.read_bytes() == b"sf", "recovery/publication/retry reran a shell command")
        require(document(invoke(binary, recovery)) == history, "lifecycle consumed or acknowledged saved proposals")
        for name, original in retained.items():
            require((directory / name).read_bytes() == original, f"lifecycle rewrote original {name}")
        print(json.dumps(dict(type="workflow_publication_smoke", format=algorithm, passed=True,
                              rust_executed=True, fresh_processes=True, native_fixture=True, real_jobs=2,
                              invalid_evidence_requests=len(negatives), output_failure_exercised=output_fault,
                              no_execution_retry=True, historical_terminal_after_source_move=True)))


def self_test():
    """Fixture/checker tests do not stand in for the Rust executable campaign."""
    rejected = 0
    for algorithm in ["sha1", "sha256"]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            f = fixture(root / "source", algorithm, root / "executions.log")
            for path in (root / "source/objects").glob("*/*"):
                raw = zlib.decompress(path.read_bytes())
                header, body = raw.split(b"\0", 1)
                kind, length = header.split(b" ", 1)
                require(int(length) == len(body) and identity(algorithm, kind.decode(), body) == path.parent.name + path.name,
                        "independently encoded loose object framing/identity")
            incarnation, marker = "71" * 16, "72" * 32
            evidence = b"synthetic checker input, never passed to the fg executable"
            entry = dict(batch_sha256="73" * 32, run_sha256="74" * 32, attempt_sha256="75" * 32,
                         workflow_graph_sha256="76" * 32)
            fact = dict(job="a_success", evidence_sha256=hashlib.sha256(evidence).hexdigest())
            observation = expected_observation(entry, fact, evidence)
            require(re.fullmatch(r"check/[0-9a-v]{51}[0g]", observation["id"]) is not None, "base32 check label/padding")
            sample = dict(type="workflow_check_publication", schema_version=1, tenant_id=TENANT,
                          repository_id=REPOSITORY, repository_incarnation=incarnation, principal_id=PRINCIPAL,
                          object_format=algorithm, source_ref_hex=SOURCE.encode().hex(), source_commit=f["source"],
                          journal_id=marker, batch_sha256=entry["batch_sha256"], fact_index=1,
                          check_id=observation["id"], **{key: value for key, value in observation.items()
                                                       if key not in ["id", "publisher"]},
                          command_committed=True, outcome="committed", historical_outcome=True,
                          current_refs_asserted=False, node_closed=True, cleanup_error=None,
                          trusted_local=True, scope="trusted_workflow_observations", merge_permission=None,
                          authoritative_check=False, execution_retried=False, journal_acknowledged=False,
                          refs_changed=False, delivery_acknowledged=None, evidence_payload_included=False,
                          decision_sequence="2", tx_id="frankengit/ref-txn/v2/synthetic",
                          repository_commit_id="frankengit/rcr/v1/synthetic", refusal_code=None, refusal_record_id=None)
            sample["evidence_bytes"] = len(evidence)
            check_publication(sample, algorithm, f, incarnation, marker, entry, 1, observation)
            for key, value in [("repository_id", "wrong"), ("repository_incarnation", "wrong"), ("principal_id", "wrong"),
                               ("source_commit", f["advanced"]), ("source_ref_hex", TARGET.encode().hex()),
                               ("conclusion", "success"), ("evidence_sha256", "00" * 32), ("evidence_bytes", "0"),
                               ("journal_id", "00" * 32), ("batch_sha256", "00" * 32), ("fact_index", True),
                               ("check_id", "check/wrong"), ("job", "b_failure"), ("run_id", "00" * 32),
                               ("command_committed", False), ("historical_outcome", False), ("current_refs_asserted", True),
                               ("authoritative_check", True), ("merge_permission", True), ("execution_retried", True),
                               ("journal_acknowledged", True), ("refs_changed", True), ("evidence_payload_included", True),
                               ("decision_sequence", 2), ("node_closed", False), ("cleanup_error", "lost"),
                               ("evidence", "raw evidence must not appear")]:
                damaged = copy.deepcopy(sample); damaged[key] = value
                try:
                    check_publication(damaged, algorithm, f, incarnation, marker, entry, 1, observation)
                except (AssertionError, KeyError, TypeError):
                    rejected += 1
                else:
                    raise AssertionError(f"publication checker accepted damaged {key}")
            page = dict(type="pull_request_checks", schema_version=1, tenant_id=TENANT, repository_id=REPOSITORY,
                        repository_incarnation=incarnation, object_format=algorithm, number="7", pull_request_version="1",
                        found=True, source_ref_hex=SOURCE.encode().hex(), target_ref_hex=TARGET.encode().hex(),
                        source_tip=f["source"], target_tip=f["target"], scope="trusted_workflow_observations",
                        merge_permission=None, source_current=True, node_closed=True,
                        source_head="frankengit/authority-head/v1/synthetic", snapshot_token="alg:2:" + "aa" * 32,
                        checks=[observation], after=None, limit=20, next_after=None, complete=True)
            check_page(page, algorithm, f, incarnation, [observation])
            for key, value in [("checks", []), ("checks", [observation, observation]), ("source_tip", f["advanced"]),
                               ("merge_permission", True), ("source_current", False), ("node_closed", False),
                               ("snapshot_token", "latest"), ("next_after", observation["id"]), ("complete", False)]:
                damaged = copy.deepcopy(page); damaged[key] = value
                try:
                    check_page(damaged, algorithm, f, incarnation, [observation])
                except (AssertionError, KeyError, TypeError):
                    rejected += 1
                else:
                    raise AssertionError(f"check-page checker accepted damaged {key}")
    print(json.dumps(dict(type="workflow_publication_checker_self_test", checker_passed=True,
                          damaged_reports_rejected=rejected, rust_executed=False,
                          native_campaign_executed=False, synthetic_checker_inputs=True)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fg", type=Path)
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    binary = args.fg.resolve()
    require(binary.is_file() and os.access(binary, os.X_OK), "an executable built fg is required; no skipped success")
    with binary.open("rb") as executable:
        print(json.dumps(dict(type="binary_identity", sha256=sha256_stream(executable))))
    for algorithm in ["sha1", "sha256"]:
        run_format(binary, algorithm)


if __name__ == "__main__":
    main()
