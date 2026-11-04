"""Actual source-bundle CLIs joined to the existing independent Git fixture."""
from pathlib import Path
import json
import os

from full_bundle_smoke import decode_export
from patch_smoke import oid
from operator_remote_bundle_smoke import run_remote_bundle_case
from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
REF = "refs/heads/main"


def run_native_bundle_case(c, home, fmt, source, base, base_tree, objects, files, oracle):
    work = home / "native-bundle"
    work.mkdir(mode=0o700)
    donor, destination, bundle = work / "donor", work / "destination", work / "source.bundle"

    def operator(script, args, expected=0, error=False):
        return c.node_command(ROOT / "scripts" / script, list(map(str, args)), expected, error_reply=error)

    def initialize(node):
        c.run("init", node, TENANT, REPOSITORY, fmt)
        node.chmod(0o700)

    def authority(node):
        return c.run("at", node, TENANT, REPOSITORY, "latest")

    def canonical(node, expected_refs=None):
        expected_refs = {REF.encode(): base} if expected_refs is None else expected_refs
        refs = json.loads(c.run("refs", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt))
        require(refs["node_closed"] is True and refs["has_more"] is False
                and {bytes.fromhex(r["reference_hex"]): r["tip"] for r in refs["references"]}
                == expected_refs, "source import/recovery changed independently selected refs")
        for path, (mode, body) in files.items():
            row = json.loads(c.run("show", node, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
                "--ref", REF, "--path-hex", path.hex(), "--max-bytes", "4096"))
            require(row["node_closed"] is True and row["source_commit"] == base and row["root_tree"] == base_tree
                    and row["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(row["bytes_hex"]) == body
                    and row["kind"] == ("executable" if mode == b"100755" else "file") and row["has_more"] is False,
                    "source import/recovery lost canonical bytes, object identity or file mode")

    initialize(donor)
    c.run("import", donor, TENANT, REPOSITORY, PRINCIPAL, "native-bundle-donor", source)
    before = authority(donor)
    exported = json.loads(c.run("bundle", "export", donor, TENANT, REPOSITORY, bundle,
        "--trusted-local", "--object-format", fmt))
    raw = bundle.read_bytes()
    digest = file_sha256(bundle)
    require(exported["node_closed"] is True and exported["repository_changed"] is False
            and exported["includes_forge_metadata"] is False and authority(donor) == before,
            "portable bundle export changed authority or claimed forge metadata")
    require(decode_export(raw, fmt) == ({b"HEAD": base, REF.encode(): base}, objects),
            "native export differs from independent objects and selected HEAD")
    oracle("native-source-bundle", "bundle", "verify", "../native-bundle/source.bundle")
    pins = ["--expect-sha256", digest, "--expect-ref", REF + "=" + base, "--exact-refs"]
    verify = [bundle, "--fg", c.fg, "--expect-format", fmt, *pins]
    wrong = verify.copy()
    wrong[wrong.index("--expect-ref") + 1] = REF + "=" + "f" * len(base)
    refused = operator("verify_git_bundle_native.mjs", wrong, 1, True)
    require(refused["verified"] is False and bool(refused["error"]), "wrong independent verifier pin was accepted")
    refused = operator("verify_git_bundle_native.mjs", [*verify, "--max-objects", "1"], 1, True)
    require(refused["verified"] is False and refused["details"]["exit_code"] == 2,
            "native object-count ceiling did not refuse the valid larger graph")
    for profile in ([], ["--file-backed"]):
        report = operator("verify_git_bundle_native.mjs", [*verify, *profile])
        require(report["object_format"] == fmt and report["object_count"] == len(objects)
                and report["bundle_bytes"] == len(raw) and report["artifact_sha256"] == digest
                and report["references"] == [{"ref_hex": REF.encode().hex(), "object_id": base}]
                and all(report[k] is True for k in ("objects_verified", "object_graph_verified", "pack_checksum_verified"))
                and report["repository_changed"] is False and report["forge_state_verified"] is False,
                "actual native verifier CLI changed content identities or claimed publication")
        if profile:
            require(report["scratch_removed"] is True and report["storage_profile"] == "file-backed-native-full-bundle-v1",
                    "file-backed verifier did not finalize its native scratch")
    c.facts[f"{fmt}_native_bundle_cli_verification"] = True

    initialize(destination)
    before = authority(destination)
    importer = "import_git_bundle_native.mjs"
    recovery = work / "import-custody"
    initial = ["import", bundle, "--trusted-local", "--fg", c.fg, "--storage", destination,
        "--tenant", TENANT, "--repository-id", REPOSITORY, "--principal", PRINCIPAL, "--object-format", fmt]
    wrong = pins.copy()
    wrong[wrong.index("--expect-ref") + 1] = REF + "=" + "f" * len(base)
    refused = operator(importer, [*initial, "--recovery-directory", work / "bad-custody", *wrong], 2, True)
    require(refused["type"] == "native_source_import_error" and refused["automatic_retry"] is False
            and not (work / "bad-custody").exists() and authority(destination) == before,
            "bad import pin created custody or changed canonical authority")
    terminal = operator(importer, [*initial, "--recovery-directory", recovery, *pins])
    require(terminal["outcome"] == "committed" and terminal["node_closed"] is True
            and terminal["submission_attempted"] is True and terminal["artifact_sha256"] == digest
            and terminal["forge_state_restored"] is False and terminal["capsule_restored"] is False,
            "actual source import CLI failed canonical source-only admission")
    canonical(destination)
    before = authority(destination)
    intent = (recovery / "intent.json").read_bytes()
    bundle.rename(work / "source.retained")
    (recovery / "source.bundle").rename(recovery / "source.retained")
    original = [recovery, "--trusted-local", "--fg", c.fg, "--intent-sha256", terminal["intent_sha256"]]
    for action in ("status", "retry"):
        found = operator(importer, [action, *original])
        require(found["node_closed"] is True and found["outcome"] == "committed"
                and found["submission_attempted"] is False and found["transaction_id"] == terminal["transaction_id"]
                and found["terminal"] == terminal["terminal"] and found["key_digest"] == terminal["key_digest"]
                and found["intent_sha256"] == terminal["intent_sha256"] and authority(destination) == before,
                "historical source import lookup/retry changed identity, read lost source or republished")
    wrong = original.copy()
    wrong[-1] = "0" * 64
    refused = operator(importer, ["status", *wrong], 2, True)
    require(refused["error"] == "native_import_intent_pin_mismatch" and (recovery / "intent.json").read_bytes() == intent
            and authority(destination) == before, "wrong retained intent pin was accepted or changed authority")
    (work / "source.retained").rename(bundle)
    collision = operator(importer, [*initial, "--recovery-directory", work / "collision-custody", *pins], 3)
    require(collision["outcome"] == "refused" and collision["node_closed"] is True
            and collision["key_digest"] != terminal["key_digest"], "fresh existing-ref import did not canonically refuse")
    canonical(destination)
    c.facts[f"{fmt}_native_bundle_cli_import_custody"] = True

    uncertain, custody = work / "uncertain-node", work / "uncertain-custody"
    initialize(uncertain)
    # Explicit test-only observation fault. The real Rust import executes and
    # exits; only its owner's group-liveness probe is denied. Signals and reaping
    # remain real. This is not a missing native route or hostile-child sandbox.
    hook = work / "deny-import-observation.mjs"
    hook.write_text("""import childProcess from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
let importedPid;
const spawn = childProcess.spawn, kill = process.kill;
childProcess.spawn = function (...args) {
  const child = Reflect.apply(spawn, this, args);
  if (args[1]?.[0] === 'bundle' && args[1]?.[1] === 'import' && child.pid) {
    importedPid = child.pid;
    writeFileSync(new URL('./owner-child.pid', import.meta.url), String(child.pid), { mode: 0o600 });
  }
  return child;
};
syncBuiltinESMExports();
process.kill = function (pid, signal) {
  if (importedPid && pid === -importedPid && signal === 0) {
    throw Object.assign(new Error('planted liveness observation failure'), { code: 'EPERM' });
  }
  return Reflect.apply(kill, this, [pid, signal]);
};
""", encoding="utf-8")
    hook.chmod(0o600)
    uncertain_args = initial.copy()
    uncertain_args[uncertain_args.index("--storage") + 1] = uncertain
    failed = c.node_command(Path("--import"), list(map(str, [hook, ROOT / "scripts" / importer,
        *uncertain_args, "--recovery-directory", custody, *pins])), 2, error_reply=True)
    details = failed["details"]
    require(failed["error"] == "native_import_containment_failed" and details["process_failure"] == {
        "reason": "native_process_descendants_remaining", "leader_exited": True, "output_closed": True,
        "process_group": "unknown", "scope": "posix-process-group"}, "CLI erased native owner containment facts")
    require(details["outcome"] == "unknown_pending" and details["submission_attempted"] is True
            and details["absence_proves_non_commit"] is False and details["automatic_retry"] is False
            and details["recovery_directory"] == str(custody)
            and details["intent_sha256"] == file_sha256(custody / "intent.json"),
            "containment diagnostics lost retained request identity or claimed rollback")
    pid = int((work / "owner-child.pid").read_text())
    dead = False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        dead = True
    require(dead, "faulted native import child was not actually reaped")
    canonical(uncertain)
    before = authority(uncertain)
    found = operator(importer, ["status", custody, "--trusted-local", "--fg", c.fg,
        "--intent-sha256", details["intent_sha256"]])
    require(found["outcome"] == "committed" and found["node_closed"] is True
            and found["submission_attempted"] is False and authority(uncertain) == before,
            "original-key lookup failed to resolve an actual committed import after containment ambiguity")
    c.facts[f"{fmt}_native_bundle_cli_containment_diagnostics"] = True

    recovered = work / "recovered.git"
    restore = [bundle, recovered, "--native-fg", c.fg, "--head", REF, "--expect-format", fmt, *pins]
    wrong = restore.copy()
    wrong[wrong.index("--expect-ref") + 1] = REF + "=" + "f" * len(base)
    refused = operator("recover_git_bundle.mjs", wrong, 1, True)
    require(refused["state"] == "not_created" and not recovered.exists(), "bad recovery pin published source HEAD")
    report = operator("recover_git_bundle.mjs", [*restore, "--native-file-backed"])
    require(report["state"] == "complete" and report["files_synced"] is True and report["directories_synced"] is True
            and report["head_ref_hex"] == REF.encode().hex() and report["verification"]["object_graph_verified"] is True
            and report["forge_state_restored"] is False and report["native_authority_restored"] is False,
            "native CLI recovery did not finish source-only root-last publication")
    head = recovered / "HEAD"
    identity = head.stat().st_ino, head.read_bytes()
    require(identity[1] == b"ref: refs/heads/main\n", "recovered HEAD differs from independent branch selection")
    operator("recover_git_bundle.mjs", restore, 1, True)
    resumed = operator("recover_git_bundle.mjs", [*restore, "--resume"])
    require(resumed["state"] == "complete" and resumed["resumed"] is True and resumed["already_published"] is True
            and resumed["plan_sha256"] == report["plan_sha256"] and (head.stat().st_ino, head.read_bytes()) == identity
            and bundle.read_bytes() == raw, "source recovery retry replaced HEAD, plan or original bundle")
    oracle("native-recovered-fsck", "fsck", "--strict", "--no-reflogs", directory=recovered)
    restored_node = work / "restored-node"
    initialize(restored_node)
    c.run("import", restored_node, TENANT, REPOSITORY, PRINCIPAL, "native-bundle-recovered", recovered)
    canonical(restored_node)
    c.facts[f"{fmt}_native_bundle_cli_recovery"] = True
    run_remote_bundle_case(c, home, fmt, donor, base, objects, canonical, oracle)
