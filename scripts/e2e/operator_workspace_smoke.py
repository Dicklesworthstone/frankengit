#!/usr/bin/env python3
"""Exercise the existing workspace -> authoring -> one-shot native publication join.

Python derives the expected objects independently. Pinned sandboxed Git checks
the fixture and returned bundle; Rust reads establish the canonical result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
from typing import Any

from operator_issue_smoke import OperatorCampaign
from patch_smoke import loose, oid, bundle_objects
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require
from source_browse_smoke import tree

ROOT = Path(__file__).resolve().parents[2]
REF = "refs/heads/main"
AUTHOR = "Workspace Operator <workspace@example.invalid>"
MESSAGE = "Publish the selected local edits\n"
EDIT, REMOVE, MODE, CREATE = b"dir/edit", b"dir/remove", b"dir/tool", b"new/created"
BEFORE = {EDIT: (b"100644", b"before\r\nwithout final LF"),
          REMOVE: (b"100644", b"delete exactly\n"), MODE: (b"100644", b"#!/bin/false\n"),
          b"dir/kept": (b"100644", b"unselected\0nested sibling"),
          b"keep.bin": (b"100644", b"\0unchanged\xffsibling")}
AFTER = {EDIT: (b"100755", b"\0\xffedited\r\nwithout final LF"),
         MODE: (b"100755", BEFORE[MODE][1]), CREATE: (b"100644", b"created\0binary\n"),
         b"dir/kept": BEFORE[b"dir/kept"],
         b"keep.bin": BEFORE[b"keep.bin"]}


def file_tree(fmt: str, files: dict[bytes, tuple[bytes, bytes]], emit) -> tuple[str, dict[bytes, tuple[str, bytes]]]:
    trees = {}

    def directory(prefix: bytes) -> str:
        rows = []
        for name in sorted({p[len(prefix):].split(b"/", 1)[0] for p in files if p.startswith(prefix)}):
            path = prefix + name
            if path in files:
                mode, body = files[path]
                identity = emit("blob", body)
            else:
                mode, identity = b"40000", directory(path + b"/")
            rows.append((name, mode, identity))
        body = tree(rows)
        identity = emit("tree", body)
        trees[prefix[:-1]] = identity, body
        return identity

    return directory(b""), trees


def run_case(c: OperatorCampaign, oracle_run: Path, fmt: str) -> None:
    home = c.work / fmt
    home.mkdir(mode=0o700)
    source, repository = home / "source", home / "repository"
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_text("ref: " + REF + "\n")
    (source / "config").write_text("[core]\nbare=true\nrepositoryformatversion=" +
        ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"))
    original = {}

    def store(kind, body):
        identity = loose(source, fmt, kind, body)
        original[identity] = kind, body
        return identity

    base_tree, trees = file_tree(fmt, BEFORE, store)
    base_body = f"tree {base_tree}\nauthor {AUTHOR} 1 +0000\ncommitter {AUTHOR} 1 +0000\n\nbase\n".encode()
    base = store("commit", base_body)
    (source / REF).write_text(base + "\n")
    expected_objects = {}

    def expected(kind, body):
        identity = oid(fmt, kind, body)
        expected_objects[identity] = kind, body
        return identity

    result_tree, _ = file_tree(fmt, AFTER, expected)
    commit_body = f"tree {result_tree}\nparent {base}\nauthor {AUTHOR} 2 +0000\ncommitter {AUTHOR} 2 +0000\n\n{MESSAGE}".encode()
    candidate = expected("commit", commit_body)
    selected = sorted([EDIT, REMOVE, MODE])
    independent = {"format": fmt, "commit": base,
                   "files": [{"pathHex": p.hex(), "blob": oid(fmt, "blob", BEFORE[p][1])} for p in selected]}

    def put(name, value):
        path = home / name
        with path.open("x", encoding="utf-8") as out:
            json.dump(value, out)
        return path

    package_path, expect_path = home / "package.json", put("expected.json", independent)

    def oracle(label, *arguments):
        command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
                   str(source.relative_to(oracle_run / "work")), fmt + "-workspace-" + label, "--", *arguments]
        stem = home / ("oracle-" + label)
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
        c.record(kind="pinned_git_workspace_check", command=command, exit=result.returncode, artifacts=str(stem))
        if result.returncode:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
        require(result.returncode == 0, "pinned Git rejected the fixture or candidate bundle")

    oracle("fsck", "fsck", "--full", "--strict", "--no-reflogs")
    c.run("init", repository, TENANT, REPOSITORY, fmt, "--root-layout", "ref-merkle-v1")
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "operator-workspace-import", source)
    c.run("index", repository, TENANT, REPOSITORY, fmt, REF, "build", "genesis")
    credentials, incarnation = c.credentials(repository, home)
    header = credentials.read_text().splitlines()[0]
    token = "a" * 64
    token_path = home / "token"
    token_path.write_text(token)

    def grants(scopes):
        pending = home / "credentials.next"
        with pending.open("x", encoding="ascii") as out:
            out.write(header + "\n" + hashlib.sha256(token.encode()).hexdigest() + f" {PRINCIPAL} {scopes}\n")
        pending.replace(credentials)

    grants("read,receive,outcomes-read")
    workspace_cli = ROOT / "scripts/fg_source_workspace.mjs"
    changes_cli, edit_cli = ROOT / "scripts/fg_source_changes.mjs", ROOT / "scripts/fg_source_edit.mjs"

    def native(verb, *args):
        return json.loads(c.run(verb, repository, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt, *args))

    def refs():
        page = native("refs")
        require(page["node_closed"] is True and page["has_more"] is False and page["next_after_hex"] is None,
                "native references are incomplete")
        rows = page["references"]
        names = [bytes.fromhex(row["reference_hex"]).decode() for row in rows]
        require(names == sorted(set(names)), "native reference ordering or uniqueness changed")
        return dict(zip(names, (row["tip"] for row in rows)))

    before = c.run("at", repository, TENANT, REPOSITORY, "latest")
    require(refs() == {REF: base}, "native import differs from independent fixture")
    pin = native("show", "--ref", REF, "--path-hex", EDIT.hex(), "--max-bytes", "65536")
    require(pin["node_closed"] is True and pin["source_commit"] == base and pin["root_tree"] == base_tree
            and bytes.fromhex(pin["bytes_hex"]) == BEFORE[EDIT][1], "independent native source selection differs")
    context_cli, package_cli = ROOT / "scripts/fg_source_context.mjs", ROOT / "scripts/fg_source_package.mjs"
    context_bundle = home / "native-context"
    acquisition = HttpServer(c, repository, credentials, "workspace-acquisition-" + fmt)
    acquisition.command.append("--allow-source")
    with acquisition:
        query = put("context-query.json", {"schema": "frankengit-source-context-query-v1", "scope": {
            "tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": incarnation,
            "object_format": fmt}, "reference": REF, "expected_commit": base,
            "expected_head": pin["snapshot_token"], "terms": ["dir"],
            "prefixes_hex": [p.hex() for p in selected], "limits": {"context_max_files": 3}})
        context_args = ["capture", "--endpoint", acquisition.url, "--query-file", str(query),
                        "--token-file", str(token_path), "--output", str(context_bundle), "--require-complete"]
        grants("receive,outcomes-read")
        denied = c.node_command(context_cli, context_args, 2, error_reply=True)
        require(denied["status"] == 403 and not context_bundle.exists(), "context read grant denial was bypassed")
        grants("read,receive,outcomes-read")
        context = c.node_command(context_cli, context_args)
        saved_context = context_bundle / "capture.json"
        require(file_sha256(saved_context) == context["capture_sha256"], "context capture hash changed")
        native_context = json.loads(saved_context.read_bytes())["native_response"]
        require(sorted(bytes.fromhex(f["path_hex"]) for f in native_context["files"]) == selected,
                "actual Initial query selected unexpected source paths")
        for row in native_context["files"]:
            body = BEFORE[bytes.fromhex(row["path_hex"])][1]
            require(row["blob"] == oid(fmt, "blob", body) and row["source_bytes"] == len(body),
                    "native context differs from independent selected object")
            for excerpt in row["excerpts"]:
                data = bytes.fromhex(excerpt["untrusted_bytes_hex"]); at = excerpt["byte_offset"]
                require(body[at:at + len(data)] == data, "native context excerpt differs from original bytes")
        c.facts[f"{fmt}_native_context_and_grant_twins"] = True
        selection = put("package-selection.json", {"endpoint": acquisition.url, "tenant_id": TENANT,
            "repository_id": REPOSITORY, "repository_incarnation": incarnation, "object_format": fmt,
            "ref": REF, "expected_commit": base, "expected_head": pin["snapshot_token"]})
        package_common = ["--selection", str(selection), "--context", str(saved_context),
                          "--context-sha256", context["capture_sha256"], "--expect", str(expect_path)]
        package_args = ["capture", *package_common, "--token-file", str(token_path),
                        "--output", str(package_path), "--native-fg", str(c.fg)]
        grants("receive,outcomes-read")
        c.node_command(package_cli, package_args, 2, error_reply=True)
        require(not package_path.exists(), "package published without its read grant")
        grants("read,receive,outcomes-read")
        chosen = json.loads(selection.read_bytes())
        selection.write_text(json.dumps({**chosen, "expected_head": "alg:2:" + "f" * 64}))
        c.node_command(package_cli, package_args, 2, error_reply=True)
        require(not package_path.exists(), "changed independent head published a package")
        selection.write_text(json.dumps(chosen))
        acquired = c.node_command(package_cli, package_args)
        require(acquired["native_read"]["verified_at_capture"] is True
                and acquired["native_read"]["head"] == pin["snapshot_token"]
                and acquired["native_read"]["binary_sha256"] == file_sha256(c.fg)
                and acquired["native_read"]["files"] == len(selected)
                and acquired["verified"]["authorityVerified"] is False
                and acquired["package_sha256"] == file_sha256(package_path), "native package proof/custody differs")
        package = json.loads(package_path.read_bytes())
        require(package["membership"]["commit"] == {"oid": base, "bodyHex": base_body.hex()}
                and package["membership"]["files"] == [
                    {"pathHex": p.hex(), "blob": oid(fmt, "blob", BEFORE[p][1]), "kind": "file"} for p in selected]
                and package["blobs"] == sorted([
                    {"oid": oid(fmt, "blob", BEFORE[p][1]), "bytesHex": BEFORE[p][1].hex()} for p in selected], key=lambda x: x["oid"]),
                "acquired package does not contain exact independently selected files")
        require({t["pathHex"]: (t["oid"], t["bodyHex"]) for t in package["membership"]["trees"]}
                == {p.hex() if p else None: (identity, body.hex()) for p, (identity, body) in trees.items()},
                "acquired parent trees differ from independent original objects")
    c.node_command(context_cli, ["inspect", "--bundle", str(context_bundle), "--expected-sha256", context["manifest_sha256"]])
    c.node_command(package_cli, ["inspect", *package_common, "--package", str(package_path),
                                 "--package-sha256", acquired["package_sha256"]])
    c.node_command(ROOT / "scripts/fg_verify_source_package.mjs", ["--package", str(package_path), "--expect", str(expect_path)])
    require(c.run("at", repository, TENANT, REPOSITORY, "latest") == before and refs() == {REF: base},
            "source acquisition or proof verification published canonical state")
    c.facts[f"{fmt}_native_package_and_proof_custody"] = True
    workspace = home / "workspace"
    args = ["create", "--package", str(package_path), "--expect", str(expect_path), "--output", str(workspace)]
    made = c.node_command(workspace_cli, args)
    workspace_hash = made["workspace_sha256"]
    require(made["source_commit"] == base and made["repository_changed"] is False,
            "workspace creation changed its independently chosen source")
    status_args = ["status", "--workspace", str(workspace), "--sha256", workspace_hash]
    c.node_command(workspace_cli, [*status_args[:-1], "0" * 64], 2, error_reply=True)
    c.node_command(workspace_cli, status_args)
    require(not (workspace / "files/keep.bin").exists(), "sparse workspace materialized an unselected file")
    for path in [EDIT, MODE, CREATE]:
        output = workspace / "files" / path.decode()
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        output.write_bytes(AFTER[path][1])
        output.chmod(0o700 if AFTER[path][0] == b"100755" else 0o600)
    (workspace / "files" / REMOVE.decode()).unlink()
    c.node_command(workspace_cli, status_args)
    capture = home / "capture"
    paths = sorted([EDIT, REMOVE, MODE, CREATE])
    paths_path = put("paths.json", {"paths_hex": [p.hex() for p in paths]})
    capture_args = ["capture", "--workspace", str(workspace), "--sha256", workspace_hash,
                    "--paths", str(paths_path), "--output", str(capture)]
    c.node_command(workspace_cli, capture_args, 2, error_reply=True)
    require(not capture.exists(), "default text capture accepted NUL-bearing edits")
    paths_path.write_text(json.dumps({"paths_hex": [p.hex() for p in paths], "byte_profile": "binary-safe-v1"}))
    captured = c.node_command(workspace_cli, capture_args)
    require(captured["expected_tree"] == result_tree and captured["changed_path_count"] == 4
            and captured["repository_changed"] is False, "captured intent differs from independently computed tree")
    c.node_command(workspace_cli, ["inspect-capture", "--capture", str(capture), "--sha256", captured["capture_sha256"]])
    c.facts[f"{fmt}_workspace_capture_and_binary_twin"] = True

    server = HttpServer(c, repository, credentials, "workspace-" + fmt)
    server.command.extend(["--allow-source", "--allow-receive", "--allow-outcomes"])
    with server:
        selection = {"endpoint": server.url, "scope": {"tenant_id": TENANT, "repository_id": REPOSITORY,
            "repository_incarnation": incarnation, "object_format": fmt}, "ref": REF, "expected_commit": base,
            "metadata": {"author": AUTHOR, "committer": AUTHOR, "timestamp": 2, "message": MESSAGE},
            "paths_hex": [p.hex() for p in paths], "patch_profile": "exact-tree-binary-v1",
            "expected_result_tree": result_tree}
        selection_path = put("selection.json", selection)
        common = ["--package", str(capture / "source.json"), "--expect", str(capture / "expected.json"),
                  "--changes", str(capture / "changes.json"), "--confirm-draft-sha256", captured["draft_sha256"]]
        candidate_path = home / "candidate"
        prepare = ["prepare-packed", *common, "--selection", str(selection_path), "--token-file", str(token_path),
                   "--output", str(candidate_path)]
        grants("receive,outcomes-read")
        denied = c.node_command(changes_cli, prepare, 2, error_reply=True)
        require(denied.get("http_status") == 403 and not candidate_path.exists(),
                "native refusal status was lost or denied preparation created a candidate")
        grants("read,receive,outcomes-read")
        legacy = c.node_command(changes_cli, prepare, 2, error_reply=True)
        require(legacy["code"] == "source_edit_structural_identity" and not candidate_path.exists(),
                "v3 silently accepted incomplete modified-directory evidence")
        selection["parent_tree_profile"] = "verified-parent-trees-v1"
        selection_path.write_text(json.dumps(selection))
        prepared = c.node_command(changes_cli, prepare)
        require(prepared["candidate_commit"] == candidate, "native preparation changed exact intended commit")
        saved_capture = json.loads((candidate_path / "capture.json").read_text())
        require(saved_capture["schema"] == "frankengit-source-edit-capture-v4"
                and saved_capture["request"]["parent_tree_basis"]["commit"]["oid"] == base,
                "parent-tree basis is not retained in the explicit v4 capture")
        c.facts[f"{fmt}_verified_parent_trees"] = True
        packed = bundle_objects((candidate_path / "candidate.bundle").read_bytes(), fmt, base, candidate)
        # Native export includes the explicitly changed mode-only file's
        # existing blob, but never the untouched siblings' bodies.
        effect_blobs = {oid(fmt, "blob", AFTER[p][1]) for p in paths if p in AFTER}
        inventory = {key: value for key, value in expected_objects.items()
                     if value[0] != "blob" or key in effect_blobs}
        require(packed == inventory and packed[candidate] == ("commit", commit_body), "candidate bundle differs from independent objects")
        (home / "candidate.bundle").write_bytes((candidate_path / "candidate.bundle").read_bytes())
        oracle("bundle", "bundle", "verify", "../candidate.bundle")
        inspect = ["inspect-packed", *common, "--candidate", str(candidate_path), "--sha256", prepared["manifest_sha256"]]
        c.node_command(changes_cli, inspect)
        journal = home / "journal"
        stage = ["stage-packed", *common, "--selection", str(selection_path), "--candidate", str(candidate_path),
                 "--sha256", prepared["manifest_sha256"], "--principal", PRINCIPAL,
                 "--confirm-candidate", candidate, "--journal", str(journal)]
        wrong = stage.copy()
        wrong[wrong.index("--confirm-candidate") + 1] = base
        c.node_command(changes_cli, wrong, 2, error_reply=True)
        require(not journal.exists(), "wrong candidate consent acquired publication custody")
        staged = c.node_command(changes_cli, stage)
        # The other verified-evidence consumer must accept the same structural
        # rows without treating a parent as an extra selected file.
        result_expectation = put("result-expected.json", {"schema": "frankengit-source-edit-result-selection-v1",
            "source": independent, "create_paths_hex": [CREATE.hex()], "after": [
                {"pathHex": p.hex(), "blob": oid(fmt, "blob", AFTER[p][1]) if p in AFTER else None,
                 "kind": ("executable" if AFTER[p][0] == b"100755" else "file") if p in AFTER else None} for p in paths]})
        verified_path = home / "verified-candidate"
        verified = c.node_command(edit_cli, ["prepare-verified", "--selection", str(selection_path),
            "--package", str(capture / "source.json"), "--expect", str(result_expectation),
            "--patch-file", str(capture / "patch.diff"), "--token-file", str(token_path), "--output", str(verified_path)])
        require(verified["candidate_commit"] == candidate and verified["parent_tree_verification"]["reported_tree_effects_verified"] is True,
                "verified evidence consumer lost the exact parent-tree capture")
        c.node_command(edit_cli, ["inspect", "--candidate", str(verified_path), "--sha256", verified["manifest_sha256"]])
        require(c.run("at", repository, TENANT, REPOSITORY, "latest") == before and refs() == {REF: base},
                "capture/preparation/staging published repository state")
        c.facts[f"{fmt}_native_prepare_grant_and_exact_pack"] = True
        original_request = (journal / "request.json").read_bytes()
        for original_path in [workspace, capture, package_path, expect_path, candidate_path]:
            original_path.rename(original_path.with_name(original_path.name + ".retained"))
        reopened = c.node_command(edit_cli, ["inspect", "--candidate", str(journal / "candidate"), "--sha256", prepared["manifest_sha256"]])
        require(reopened["parent_tree_verification"]["after_tree"] == result_tree,
                "journal required an external package or trusted a saved success flag")
        c.facts[f"{fmt}_parent_evidence_custody"] = True
        base_args = ["--journal", str(journal), "--request-sha256", staged["request_sha256"]]
        applied = c.node_command(edit_cli, ["apply", *base_args, "--token-file", str(token_path)])
        require(applied["decision"]["outcome"] == "committed" and applied["submission_retried"] is False,
                "native apply did not retain a canonical committed decision")
        after = c.run("at", repository, TENANT, REPOSITORY, "latest")
        require(after != before and refs() == {REF: candidate}, "source publication moved the wrong reference")
        for path, (mode, body) in AFTER.items():
            page = native("show", "--ref", REF, "--path-hex", path.hex())
            require(page["node_closed"] is True and page["has_more"] is False and page["next_offset"] is None
                    and page["source_commit"] == candidate and page["root_tree"] == result_tree
                    and page["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(page["bytes_hex"]) == body
                    and page["kind"] == ("executable" if mode == b"100755" else "file"), "canonical source read differs")
        directory_page = native("tree", "--ref", REF, "--path", "dir")
        require(directory_page["node_closed"] is True and directory_page["has_more"] is False
                and {bytes.fromhex(row["name_hex"]) for row in directory_page["entries"]} == {b"edit", b"kept", b"tool"},
                "deleted path survived canonical publication")
        c.facts[f"{fmt}_canonical_bytes_modes_and_sibling"] = True
        # Simulate loss of the local terminal after a known committed response.
        # The durable dispatch marker forbids resend; only the original key may recover.
        terminal_path = journal / "terminal.json"
        terminal = terminal_path.read_bytes()
        terminal_path.rename(journal / "retained-terminal.json")
        c.node_command(edit_cli, ["apply", *base_args, "--token-file", str(token_path)], 2, error_reply=True)
        grants("read,receive")
        denied_outcome = c.node_command(edit_cli, ["recover", *base_args, "--token-file", str(token_path)], 2, error_reply=True)
        require(denied_outcome["http_status"] == 403 and denied_outcome["submission_retried"] is False
                and not terminal_path.exists(), "denied outcome read lost its status or manufactured terminal evidence")
        grants("outcomes-read")
        recovered = c.node_command(edit_cli, ["recover", *base_args, "--token-file", str(token_path)])
        require(recovered["decision"] == applied["decision"] and recovered["key"] == staged["key"]
                and recovered["submission_retried"] is False and terminal_path.read_bytes() == terminal
                and (journal / "request.json").read_bytes() == original_request,
                "original-key recovery changed canonical decision or journal identity")
        c.node_command(edit_cli, ["status", *base_args])
        require(c.run("at", repository, TENANT, REPOSITORY, "latest") == after and refs() == {REF: candidate},
                "recovery redispatched a mutation")
        c.facts[f"{fmt}_original_key_and_outcome_grant"] = True
    c.facts[f"{fmt}_service_drained"] = True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary", "oracle-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    fg, node, oracle_run = args.fg.resolve(strict=True), args.node.resolve(strict=True), args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle_run / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private work directory required")
    c = OperatorCampaign(fg, node, args.work.resolve())
    summary: dict[str, Any] = {"complete": False, "facts": c.facts, "binary_sha256": file_sha256(fg),
        "node_sha256": file_sha256(node), "entrypoints": ["scripts/fg_source_context.mjs",
        "scripts/fg_source_package.mjs", "scripts/fg_verify_source_package.mjs", "scripts/fg_source_workspace.mjs",
        "scripts/fg_source_changes.mjs", "scripts/fg_source_edit.mjs"], "oracle_pin": "git-2.54.0",
        "oracle_run": str(oracle_run), "artifacts": str(c.work),
        "non_claim": "Independent imported object corpus, actual native context/package acquisition and authoring/publication; not every operator, current-source native qualification, search completeness beyond this selected corpus, retained authority proofs, TLS or deployment."}

    def stop(_signum, _frame):
        raise InterruptedError("source workspace campaign interrupted; draining owned children")

    signal.signal(signal.SIGTERM, stop)
    try:
        identity = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity.get("type") == "js_runtime_identity" and identity.get("corpus_started") is False, "runtime identity required")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, oracle_run, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
