#!/usr/bin/env python3
"""Signed job/replenishment CLIs joined to real native backup and restore.

Original bytes remain in separate diagnostic custody after their input paths
disappear. Local copies do not prove independent storage or power-loss safety.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from operator_backup_smoke import FILES, KEYGEN, REF
from operator_issue_smoke import OperatorCampaign
from operator_workspace_smoke import file_tree
from patch_smoke import loose, oid
from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINTS = ("repository_backup_job.mjs", "replenish_repository_backups.mjs")
PROPERTIES = (
    "signed_native_archive", "immutable_seal_without_replicas",
    "witness_and_budget_refusal_twins", "original_approval_loss",
    "source_loss_replica_failover_and_resume", "corrupt_output_preserved",
    "replenishment_budget_and_checkpoint_twins", "replenishment_exact_resume",
    "native_restore_exact_git_and_forge", "newer_witness_blocks_older_job",
)
FACTS = tuple(f"{fmt}_{name}" for fmt in ("sha1", "sha256") for name in PROPERTIES)


def snapshot(paths):
    return {str(path): (path.stat().st_dev, path.stat().st_ino, file_sha256(path)) for path in paths}


def run_case(c, oracle_run, fmt):
    home = c.work / fmt
    home.mkdir(mode=0o700)
    source, repository, exports, retained = (home / name for name in ("git-source", "repository", "exports", "retained"))
    exports.mkdir(mode=0o700)
    retained.mkdir(mode=0o700)
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_text(f"ref: {REF}\n")
    (source / "config").write_text("[core]\nbare=true\nrepositoryformatversion=" +
        ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"))
    tree, _ = file_tree(fmt, FILES, lambda kind, body: loose(source, fmt, kind, body))
    tip = loose(source, fmt, "commit", (f"tree {tree}\n"
        "author Backup Job <backup@example.invalid> 1 +0000\n"
        "committer Backup Job <backup@example.invalid> 1 +0000\n\nbackup job\n").encode())
    (source / REF).write_text(tip + "\n")
    command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
        str(source.relative_to(oracle_run / "work")), fmt + "-job-fsck", "--", "fsck", "--full", "--strict", "--no-reflogs"]
    with (home / "oracle.stdout").open("wb") as out, (home / "oracle.stderr").open("wb") as err:
        checked = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
    c.record(kind="pinned_git_fixture_check", command=command, exit=checked.returncode)
    if checked.returncode:
        sys.stderr.write((home / "oracle.stderr").read_text(errors="replace"))
    require(checked.returncode == 0, "pinned Git rejected independently framed source")
    c.run("init", repository, TENANT, REPOSITORY, fmt)
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "backup-job-import", source)
    c.issue(repository, fmt, 0, "backup-job-open", "native job recovery issue")
    c.issue(repository, fmt, 1, "backup-job-comment", "literal native history before source loss")
    canonical_issue = json.loads(c.run("issue", "show", repository, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))
    private, public = home / "private.pem", home / "public.pem"
    require(c.node_command(Path("-e"), [KEYGEN, str(private), str(public)])["fixture_keys_created"] is True,
            "fixture key generation did not finish")

    def operator(name, args, expected=0):
        return c.node_command(ROOT / "scripts" / name, list(map(str, args)), expected, error_reply=expected != 0)

    def export(root, directory, label):
        control = json.loads(c.run("backup", "export", root, directory / (label + "-control.fg"),
            TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt))
        require(control["node_closed"] is True and control["complete"] is True, "native export failed to close")
        identity = ["--tenant-id", TENANT, "--repository-id", REPOSITORY, "--incarnation-id", control["incarnation_id"],
                    "--object-format", fmt]
        archive, approval = directory / (label + ".fg"), directory / (label + ".approval")
        signed = operator("attest_repository_backup.mjs", ["export-sign", root, archive, approval,
            "--fg", c.fg, "--trusted-local", "--verification-instance", "93001", "--private-key", private,
            *identity, "--head-generation", control["head_generation"]])
        require(signed["state"] == "complete" and signed["approval_result"]["native_content_verified"] is True
                and signed["native"]["sha256"] == file_sha256(archive)
                and str(signed["native"]["head_generation"]) == str(control["head_generation"]),
                "signed native export disagrees with independent checkpoint selection")
        return archive, approval, identity, str(control["head_generation"])

    archive, approval, identity, generation = export(repository, exports, "current")
    archive_hash, approval_bytes, size = file_sha256(archive), approval.read_bytes(), archive.stat().st_size
    policy = [*identity, "--minimum-head-generation", generation, "--trust-key", public]
    limits = ["--max-archive-bytes", str(size), "--timeout-secs", "20"]
    c.facts[f"{fmt}_signed_native_archive"] = True
    witness, jobs = home / "witness", home / "jobs"
    jobs.mkdir(mode=0o700)
    destinations = [home / "a-job-copy", home / "b-job-copy"]
    for path in destinations:
        path.mkdir(mode=0o700)
    operator("repository_backup_witness.mjs", ["init", witness, *policy])
    seal = ["seal", "--trusted-local", *policy, *limits, "--witness", witness, "--job-directory", jobs,
        "--candidate", archive, approval, *[part for path in reversed(destinations) for part in ("--replica-directory", path)]]
    job = operator(ENTRYPOINTS[0], seal)
    controls = list(jobs.iterdir())
    saved_controls = snapshot(controls)
    again = operator(ENTRYPOINTS[0], seal)
    require(job["state"] == "sealed" and job["approval_preserved"] is True and job == again
            and len(controls) == 2 and snapshot(list(jobs.iterdir())) == saved_controls
            and all(not list(path.iterdir()) for path in destinations), "seal changed immutable controls or copied archives")
    preserved = jobs / f"checkpoint-sha256-{job['checkpoint']['approval_sha256']}.approval.json"
    require(preserved.read_bytes() == approval_bytes, "seal did not retain original signed envelope bytes")
    c.facts[f"{fmt}_immutable_seal_without_replicas"] = True

    base_run = ["run", "--trusted-local", *policy, *limits, "--intent", job["intent"]]
    refused = operator(ENTRYPOINTS[0], base_run, 1)
    require(refused["code"] == "backup_job_witness_required", "run silently dropped its sealed witness")
    run = [*base_run, "--witness", witness]
    refused = operator(ENTRYPOINTS[0], [*run, "--max-total-read-bytes", str(9 * size - 1)], 1)
    require(refused["code"] == "backup_replenishment_read_budget"
            and all(not list(path.iterdir()) for path in destinations), "known insufficient job budget published outputs")
    # Preserve diagnostic originals, but remove the original approval input before
    # the first run. The immutable job's retained envelope is the only control.
    approval.rename(retained / "original.approval")
    require(not approval.exists(), "original approval path still exists")
    completed = operator(ENTRYPOINTS[0], [*run, "--max-total-read-bytes", str(9 * size)])
    require(completed["state"] == "complete" and completed["job"]["job_id"] == job["job_id"]
            and completed["result"]["all_destinations_verified"] is True
            and completed["result"]["native_content_verified"] is False,
            "job lost its approval, exact intent or byte/native verification distinction")
    replicas = [{key: Path(value) for key, value in row["receipt"]["candidate"].items()}
                for row in completed["result"]["completed_replicas"]]
    require(len(replicas) == 2 and all(file_sha256(row["input"]) == archive_hash
            and row["approval"].read_bytes() == approval_bytes for row in replicas), "job changed native payload or signature")
    c.facts[f"{fmt}_witness_and_budget_refusal_twins"] = True
    c.facts[f"{fmt}_original_approval_loss"] = True

    for path in (source, repository, exports):
        path.rename(retained / path.name)
    require(not any(path.exists() for path in (source, repository, archive, approval)), "original command inputs remain available")
    survivor_paths = [replicas[1][key] for key in ("input", "approval")]
    survivor = snapshot(survivor_paths)
    replicas[0]["input"].rename(retained / "first-designated-copy.fg")
    resumed = operator(ENTRYPOINTS[0], [*run, "--max-total-read-bytes", str(24 * size)])
    all_paths = [row[key] for row in replicas for key in ("input", "approval")]
    stable = snapshot(all_paths)
    repeated = operator(ENTRYPOINTS[0], [*run, "--max-total-read-bytes", str(24 * size)])
    require(resumed["state"] == repeated["state"] == "complete" and snapshot(survivor_paths) == survivor
            and snapshot(all_paths) == stable and snapshot(controls) == saved_controls
            and all(file_sha256(row["input"]) == archive_hash for row in replicas),
            "replica failover/retry rewrote controls, intact files or native bytes")
    c.facts[f"{fmt}_source_loss_replica_failover_and_resume"] = True

    # Corruption is deliberate fixture damage, never an automatic operator repair.
    # Keep the exact original in diagnostic custody and do not hide the bad output.
    replicas[1]["input"].rename(retained / "second-designated-copy.fg")
    damaged = bytearray(replicas[0]["input"].read_bytes()); damaged[-1] ^= 1
    replicas[1]["input"].write_bytes(damaged)
    damaged_before = snapshot([replicas[1]["input"], replicas[1]["approval"]])
    good_before = snapshot([replicas[0]["input"], replicas[0]["approval"]])
    refused = operator(ENTRYPOINTS[0], [*run, "--max-total-read-bytes", str(24 * size)], 1)
    require(refused["code"] == "backup_replica_digest_mismatch"
            and len(refused["replenishment"]["completed_replicas"]) == 1
            and refused["replenishment"]["all_destinations_verified"] is False
            and snapshot([replicas[1]["input"], replicas[1]["approval"]]) == damaged_before
            and snapshot([replicas[0]["input"], replicas[0]["approval"]]) == good_before,
            "conflict was overwritten or confirmed partial completion was hidden")
    c.facts[f"{fmt}_corrupt_output_preserved"] = True

    fresh = [home / "c-replenished", home / "d-replenished"]
    for path in fresh:
        path.mkdir(mode=0o700)
    replenish = [*policy, *limits, "--witness", witness, "--candidate", replicas[0]["input"], replicas[0]["approval"],
        *[part for path in reversed(fresh) for part in ("--replica-directory", path)]]
    checkpoint = job["checkpoint"]
    pins = ["--checkpoint", checkpoint["approval_sha256"], checkpoint["trusted_key_id"]]
    refused = operator(ENTRYPOINTS[1], [*replenish, "--checkpoint", "0" * 64, checkpoint["trusted_key_id"]], 1)
    require(refused["code"] == "backup_replication_checkpoint_mismatch" and all(not list(p.iterdir()) for p in fresh),
            "wrong checkpoint pin staged a replica")
    refused = operator(ENTRYPOINTS[1], [*replenish, *pins, "--max-total-read-bytes", str(9 * size - 1)], 1)
    require(refused["code"] == "backup_replenishment_read_budget" and all(not list(p.iterdir()) for p in fresh),
            "insufficient replenishment budget staged a replica")
    result = operator(ENTRYPOINTS[1], [*replenish, *pins, "--max-total-read-bytes", str(9 * size)])
    require(result["state"] == "complete" and result["checkpoint"] == checkpoint
            and result["all_destinations_verified"] is True and result["native_content_verified"] is False
            and result["final_scrub"]["distinct_authenticated_files"] == 2,
            "pinned replenishment did not scrub distinct native-byte replicas")
    copies = [{key: Path(value) for key, value in row["receipt"]["candidate"].items()}
              for row in result["completed_replicas"]]
    paths = [row[key] for row in copies for key in ("input", "approval")]
    original = snapshot(paths)
    require(len(copies) == 2 and all(file_sha256(row["input"]) == archive_hash
            and row["approval"].read_bytes() == approval_bytes for row in copies), "replenishment changed signed native bytes")
    retried = operator(ENTRYPOINTS[1], [*replenish, *pins, "--max-total-read-bytes", str(9 * size)])
    require(retried["state"] == "complete" and snapshot(paths) == original
            and snapshot([replicas[1]["input"], replicas[1]["approval"]]) == damaged_before,
            "exact replenishment retry rewrote healthy copies or repaired corrupt originals")
    c.facts[f"{fmt}_replenishment_budget_and_checkpoint_twins"] = True
    c.facts[f"{fmt}_replenishment_exact_resume"] = True

    restored, record = home / "restored", home / "restore-record"
    result = operator("restore_repository_backup_native.mjs", ["restore", copies[0]["input"],
        "--approval", copies[0]["approval"], *policy, "--fg", c.fg, "--trusted-local",
        "--verification-instance", "93002", "--destination", restored, "--destination-instance", "93003",
        "--approval-record", record, *limits])
    require(result["state"] == "complete" and result["native"]["signature_verified"] is True
            and result["native"]["node_closed"] is True, "replenished archive failed actual signed native restore")
    issue = json.loads(c.run("issue", "show", restored, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))
    require(issue["node_closed"] is True and issue["issue"] == canonical_issue["issue"]
            and issue["events"] == canonical_issue["events"], "canonical forge state/history changed across job recovery")
    for path, (mode, body) in FILES.items():
        page = json.loads(c.run("show", restored, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
            "--ref", REF, "--path-hex", path.hex(), "--max-bytes", "4096"))
        require(page["node_closed"] is True and page["source_commit"] == tip and page["root_tree"] == tree
                and page["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(page["bytes_hex"]) == body
                and page["has_more"] is False and page["next_offset"] is None
                and page["kind"] == ("executable" if mode == b"100755" else "file"),
                "restored native Git identity, mode or exact binary bytes differ from fixture")
    c.run("doctor", restored, TENANT, REPOSITORY)
    c.facts[f"{fmt}_native_restore_exact_git_and_forge"] = True

    # Give anti-rollback its own healthy exact job, so a damaged output cannot
    # explain the refusal. Run it successfully before retaining newer evidence.
    rollback_jobs = home / "rollback-jobs"
    rollback_jobs.mkdir(mode=0o700)
    rollback_destinations = [home / "e-witness-copy", home / "f-witness-copy"]
    for path in rollback_destinations:
        path.mkdir(mode=0o700)
    rollback_job = operator(ENTRYPOINTS[0], ["seal", "--trusted-local", *policy, *limits, "--witness", witness,
        "--job-directory", rollback_jobs, "--candidate", copies[0]["input"], copies[0]["approval"],
        *[part for path in rollback_destinations for part in ("--replica-directory", path)]])
    rollback_run = ["run", "--trusted-local", *policy, *limits, "--witness", witness,
        "--intent", rollback_job["intent"], "--max-total-read-bytes", str(24 * size)]
    allowed = operator(ENTRYPOINTS[0], rollback_run)
    require(allowed["state"] == "complete" and allowed["result"]["all_destinations_verified"] is True,
            "permitted witness twin did not complete its exact healthy job")
    rollback_paths = [Path(value) for row in allowed["result"]["completed_replicas"]
                      for value in row["receipt"]["candidate"].values()] + list(rollback_jobs.iterdir())
    # Observe a real later native checkpoint, then remove its original paths.
    # The same healthy job must now refuse solely on retained newer evidence.
    c.issue(restored, fmt, 2, "backup-job-later", "later native authority after recovery")
    newer = home / "newer"
    newer.mkdir(mode=0o700)
    later_archive, later_approval, later_identity, later_generation = export(restored, newer, "later")
    require(later_identity == identity and int(later_generation) > int(generation), "restored native generation did not advance")
    operator("repository_backup_witness.mjs", ["select", witness, *policy, "--candidate", later_archive, later_approval])
    newer.rename(retained / "newer")
    before = snapshot(all_paths + paths + controls + rollback_paths)
    refused = operator(ENTRYPOINTS[0], rollback_run, 1)
    require(refused["code"] == "backup_below_witness" and snapshot(all_paths + paths + controls + rollback_paths) == before
            and not later_archive.exists() and not later_approval.exists(), "older job bypassed retained newer evidence")
    c.facts[f"{fmt}_newer_witness_blocks_older_job"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary", "oracle-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    fg, node, oracle = args.fg.resolve(strict=True), args.node.resolve(strict=True), args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private artifact directory required")
    c = OperatorCampaign(fg, node, args.work.resolve())
    digest = file_sha256(fg)
    summary = dict(complete=False, facts=c.facts, selected_facts=FACTS, binary_sha256=digest,
        node_sha256=file_sha256(node), entrypoints=[dict(path="scripts/" + name, binary_sha256=digest) for name in ENTRYPOINTS],
        oracle_pin="git-2.54.0", artifacts=str(c.work),
        non_claim="Retained diagnostic originals and local copies; not destructive crash, independent storage, full capsule, HTTPS, current-main native or full operator qualification.")

    def stop(_signum, _frame):
        raise InterruptedError("backup job campaign interrupted; retain original custody")

    signal.signal(signal.SIGTERM, stop)
    try:
        runtime = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(runtime.get("type") == "js_runtime_identity" and runtime.get("corpus_started") is False, "pinned Node runtime required")
        summary["node_version"] = runtime["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, oracle, fmt)
        require(set(c.facts) == set(FACTS) and all(value is True for value in c.facts.values()), "selected fact population incomplete")
        require(file_sha256(fg) == digest, "native executable changed during campaign")
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
