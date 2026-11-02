#!/usr/bin/env python3
"""Seven shipped backup CLIs joined to real native Git/forge recovery.

Private local replicas are not independent failure domains. Original sources
are retained outside every command input after the source-loss boundary; this
is not a destructive power-loss, hosted-storage or complete-capsule drill.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

from operator_issue_smoke import OperatorCampaign
from operator_workspace_smoke import file_tree
from patch_smoke import loose, oid
from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
REF = "refs/heads/main"
FILES = {b"src/kept.bin": (b"100644", b"\0\xffnative backup bytes\r\n"),
         b"bin/tool": (b"100755", b"#!/bin/sh\nprintf restored\n")}
ENTRYPOINTS = ["attest_repository_backup.mjs", "repository_backup_witness.mjs",
    "select_repository_backup_native.mjs", "replicate_repository_backup_native.mjs",
    "scrub_repository_backups.mjs", "restore_repository_backup_native.mjs", "recover_repository_backup.mjs"]
KEYGEN = """const {generateKeyPairSync}=require('node:crypto'),{writeFileSync}=require('node:fs');
const keys=generateKeyPairSync('ed25519');
writeFileSync(process.argv[1],keys.privateKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
writeFileSync(process.argv[2],keys.publicKey.export({format:'pem',type:'spki'}),{mode:0o600,flag:'wx'});
console.log(JSON.stringify({fixture_keys_created:true}));"""


def run_case(c, oracle_run, fmt):
    home = c.work / fmt
    home.mkdir(mode=0o700)
    source, repository, exports = (home / name for name in ("git-source", "repository", "exports"))
    exports.mkdir(mode=0o700)
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_text(f"ref: {REF}\n")
    (source / "config").write_text("[core]\nbare=true\nrepositoryformatversion=" +
        ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"))
    tree, _ = file_tree(fmt, FILES, lambda kind, body: loose(source, fmt, kind, body))
    tip = loose(source, fmt, "commit", (f"tree {tree}\n"
        "author Backup Fixture <backup@example.invalid> 1 +0000\n"
        "committer Backup Fixture <backup@example.invalid> 1 +0000\n\nbackup\n").encode())
    (source / REF).write_text(tip + "\n")
    command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
        str(source.relative_to(oracle_run / "work")), fmt + "-backup-fsck", "--", "fsck", "--full", "--strict", "--no-reflogs"]
    with (home / "oracle.stdout").open("wb") as out, (home / "oracle.stderr").open("wb") as err:
        checked = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
    c.record(kind="pinned_git_fixture_check", command=command, exit=checked.returncode)
    if checked.returncode:
        sys.stderr.write((home / "oracle.stderr").read_text(errors="replace"))
    require(checked.returncode == 0, "pinned Git rejected independently framed backup source")
    c.run("init", repository, TENANT, REPOSITORY, fmt)
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "backup-import", source)
    c.issue(repository, fmt, 0, "backup-open", "original native backup issue")
    private, public = home / "private.pem", home / "public.pem"
    # Fixed fixture-only key generation; the runner retains no private key bytes
    # in command output. Production signing goes through the shipped CLI below.
    require(c.node_command(Path("-e"), [KEYGEN, str(private), str(public)])["fixture_keys_created"] is True,
            "fixture keys were not created")

    def operator(name, args, expected=0, error=False):
        return c.node_command(ROOT / "scripts" / name, list(map(str, args)), expected, error_reply=error)

    def export(label):
        control = json.loads(c.run("backup", "export", repository, exports / (label + "-control.fg"),
            TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt))
        require(control["node_closed"] is True and control["complete"] is True, "native export did not close")
        identity = ["--tenant-id", TENANT, "--repository-id", REPOSITORY, "--incarnation-id", control["incarnation_id"],
                    "--object-format", fmt]
        archive, approval = exports / (label + ".fg"), exports / (label + ".approval")
        result = operator("attest_repository_backup.mjs", ["export-sign", repository, archive, approval,
            "--fg", c.fg, "--trusted-local", "--verification-instance", "91001", "--private-key", private,
            *identity, "--head-generation", str(control["head_generation"])])
        require(result["state"] == "complete" and result["approval_result"]["native_content_verified"] is True
                and result["native"]["sha256"] == file_sha256(archive)
                and str(result["native"]["head_generation"]) == str(control["head_generation"]),
                "shipped exporter did not verify/sign the independently selected native state")
        return archive, approval, identity, str(control["head_generation"])

    old, old_approval, identity, floor = export("old")
    c.issue(repository, fmt, 1, "backup-comment", "later native comment must survive recovery")
    archive, approval, current_identity, generation = export("current")
    require(identity == current_identity and int(generation) > int(floor), "native checkpoints did not advance in one incarnation")
    policy = [*identity, "--minimum-head-generation", floor, "--trust-key", public]
    too_high = [*identity, "--minimum-head-generation", str(int(generation) + 1), "--trust-key", public]
    checked = operator("attest_repository_backup.mjs", ["check", archive, approval, *policy])
    require(checked["archive_bytes_authenticated"] is True and checked["native_content_verified"] is False,
            "signature check confused archive bytes with native verification")
    refused = operator("attest_repository_backup.mjs", ["check", archive, approval, *too_high], 1, True)
    require(refused["code"] == "backup_approval_below_floor", "approval ignored independent checkpoint floor")
    c.facts[f"{fmt}_native_export_sign_and_floor"] = True
    native_issue = json.loads(c.run("issue", "show", repository, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))

    witness = home / "witness"
    operator("repository_backup_witness.mjs", ["init", witness, *policy])
    selected = operator("repository_backup_witness.mjs", ["select", witness, *policy,
        "--candidate", old, old_approval, "--candidate", archive, approval])
    checkpoint = selected["checkpoint"]
    require(checkpoint["approval_sha256"] == file_sha256(approval)
            and selected["selected"]["head_generation"] == generation, "witness selected wrong signed generation")
    selected_native = operator("select_repository_backup_native.mjs", ["verify", *policy, "--witness", witness,
        "--candidate", old, old_approval, "--candidate", archive, approval, "--fg", c.fg,
        "--trusted-local", "--verification-instance", "91002"])
    require(selected_native["result"]["native"]["signature_verified"] is True, "selected native preflight did not verify original signature")
    direct = operator("restore_repository_backup_native.mjs", ["verify", archive, "--approval", approval,
        *policy, "--fg", c.fg, "--trusted-local", "--verification-instance", "91003"])
    require(direct["destination_changed"] is False and direct["native"]["node_closed"] is True,
            "verify-only native adapter changed a destination or failed to close")
    refused = operator("restore_repository_backup_native.mjs", ["verify", archive, "--approval", approval,
        *too_high, "--fg", c.fg, "--trusted-local", "--verification-instance", "91003"], 1, True)
    require(refused["code"] == "backup_approval_below_floor", "native adapter ignored independent floor")
    c.facts[f"{fmt}_selected_and_direct_native_preflight"] = True
    for name, args in [("repository_backup_witness.mjs", ["select", witness, *policy, "--candidate", old, old_approval]),
                       ("select_repository_backup_native.mjs", ["select", *policy, "--witness", witness, "--candidate", old, old_approval])]:
        require(operator(name, args, 1, True)["code"] == "backup_below_witness", "older supplied checkpoint bypassed retained higher evidence")
    inspection = operator("repository_backup_witness.mjs", ["inspect", witness, *policy])
    require(inspection["witness"]["highest_observed_generation"] == generation, "witness lost higher checkpoint across processes")
    c.facts[f"{fmt}_witness_rejects_omitted_newer_checkpoint"] = True

    size = archive.stat().st_size
    replicas = []
    for name in ("media-a", "media-b"):
        destination = home / name
        destination.mkdir(mode=0o700)
        result = operator("replicate_repository_backup_native.mjs", [*policy, "--candidate", archive, approval,
            "--candidate", old, old_approval, "--replica-directory", destination, "--max-archive-bytes", str(size),
            "--max-total-read-bytes", str(4 * size)])
        candidate = {key: Path(value) for key, value in result["candidate"].items()}
        require(result["archive_readback_verified"] is True and result["files_and_directory_synced"] is True
                and file_sha256(candidate["input"]) == file_sha256(archive)
                and candidate["approval"].read_bytes() == approval.read_bytes(), "replica is not exact original signed bytes")
        replicas.append(candidate)
    refuse_dir = home / "refused-replica"
    refuse_dir.mkdir(mode=0o700)
    refused = operator("replicate_repository_backup_native.mjs", [*too_high, "--candidate", archive, approval,
        "--replica-directory", refuse_dir], 1, True)
    require(refused["code"] == "backup_approval_below_floor" and not list(refuse_dir.iterdir()), "refused replication staged files")
    candidates = [part for row in replicas for part in ("--candidate", row["input"], row["approval"])]
    scrub_args = [*policy, "--witness", witness, "--max-archive-bytes", str(size), "--max-replica-bytes", str(2 * size), "--minimum-distinct-files", "2"]
    healthy = operator("scrub_repository_backups.mjs", [*scrub_args, *candidates])
    require(healthy["healthy"] is True and healthy["distinct_authenticated_files"] == 2
            and healthy["native_content_verified"] is False, "byte scrub exaggerated health or native verification")
    c.facts[f"{fmt}_exact_replicas_and_healthy_scrub"] = True
    corrupt = home / "00-corrupt.fg"
    damaged = bytearray(archive.read_bytes()); damaged[-1] ^= 1
    corrupt.write_bytes(damaged)
    degraded = operator("scrub_repository_backups.mjs", [*scrub_args, "--candidate", corrupt, approval,
        "--candidate", replicas[0]["input"], replicas[0]["approval"]], 2)
    require(degraded["healthy"] is False and degraded["authenticated_candidates"] == 1
            and degraded["unavailable_candidates"] == 1, "corrupt replica became healthy or hid its permitted twin")
    c.facts[f"{fmt}_corruption_is_degraded_not_native_success"] = True

    independent_approval = home / "independent.approval"
    independent_approval.write_bytes(approval.read_bytes())
    # Retain exact original diagnostic material, but make every original source
    # and export pathname unavailable. No command receives the retained paths.
    retained = home / "retained-originals"
    retained.mkdir(mode=0o700)
    for path in (source, repository, exports):
        path.rename(retained / path.name)
    require(not any(path.exists() for path in (source, repository, archive)), "original source/export remains at its command path")
    cache, restored, record = home / "cache", home / "restored", home / "restore-record"
    cache.mkdir(mode=0o700)
    recovery = ["restore", *policy, "--approval", independent_approval, "--witness", witness,
        "--cache-directory", cache, "--fg", c.fg, "--trusted-local", "--verification-instance", "91004",
        "--destination", restored, "--destination-instance", "91005", "--approval-record", record,
        "--max-archive-bytes", str(size), "--max-acquisition-bytes", str(4 * size)]
    result = operator("recover_repository_backup.mjs", [*recovery, "--input", corrupt, "--input", replicas[0]["input"]])
    require(result["state"] == "complete" and result["acquisition"]["mode"] == "local"
            and result["native"]["native"]["signature_verified"] is True
            and result["native"]["native"]["node_closed"] is True, "local media did not enter actual signed native restore")
    restored_issue = json.loads(c.run("issue", "show", restored, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))
    require(restored_issue["node_closed"] is True and restored_issue["issue"] == native_issue["issue"]
            and restored_issue["events"] == native_issue["events"], "canonical issue or history differs after restore")
    for path, (mode, body) in FILES.items():
        page = json.loads(c.run("show", restored, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
            "--ref", REF, "--path-hex", path.hex(), "--max-bytes", "4096"))
        require(page["node_closed"] is True and page["source_commit"] == tip and page["root_tree"] == tree
                and page["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(page["bytes_hex"]) == body
                and page["has_more"] is False and page["next_offset"] is None
                and page["kind"] == ("executable" if mode == b"100755" else "file"),
                "restored Git identity, mode or bytes differ from independent fixture")
    c.run("doctor", restored, TENANT, REPOSITORY)
    c.facts[f"{fmt}_native_git_and_forge_recovery_without_original_paths"] = True
    original_record = record.read_bytes()
    authority = c.run("at", restored, TENANT, REPOSITORY, "latest")
    for row in replicas:
        row["input"].rename(retained / row["input"].parent.name)
    resumed = operator("recover_repository_backup.mjs", [*recovery, "--resume", "--checkpoint",
        checkpoint["approval_sha256"], checkpoint["trusted_key_id"]])
    require(resumed["acquisition"]["mode"] == "cached" and resumed["native"]["native"]["already_published"] is True
            and record.read_bytes() == original_record and c.run("at", restored, TENANT, REPOSITORY, "latest") == authority,
            "cache-only resume changed original approval or native authority")
    c.facts[f"{fmt}_cache_only_exact_resume_without_republication"] = True
    changed = home / "changed.approval"
    changed.write_bytes(independent_approval.read_bytes() + b"\n")
    wrong = recovery.copy(); wrong[wrong.index("--approval") + 1] = changed
    refused = operator("recover_repository_backup.mjs", [*wrong, "--resume", "--checkpoint",
        checkpoint["approval_sha256"], checkpoint["trusted_key_id"]], 1, True)
    require(refused["code"] == "backup_recovery_checkpoint_mismatch" and record.read_bytes() == original_record
            and c.run("at", restored, TENANT, REPOSITORY, "latest") == authority, "changed envelope reused original restore identity")
    c.facts[f"{fmt}_changed_envelope_refuses_without_native_change"] = True


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
    summary = dict(complete=False, facts=c.facts, binary_sha256=file_sha256(fg), node_sha256=file_sha256(node),
        entrypoints=["scripts/" + name for name in ENTRYPOINTS], oracle_pin="git-2.54.0", artifacts=str(c.work),
        non_claim="Original source paths unavailable but retained elsewhere; local inode copies, not independent failure domains, destructive power loss, full capsule, HTTPS, current-source native or every operator qualification.")
    def stop(_signum, _frame):
        raise InterruptedError("backup campaign interrupted; retain all original custody")
    signal.signal(signal.SIGTERM, stop)
    try:
        runtime = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(runtime.get("type") == "js_runtime_identity" and runtime.get("corpus_started") is False, "pinned Node runtime required")
        summary["node_version"] = runtime["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, oracle, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
