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
from operator_context_smoke import acquire_context_cases, inspect_context_cases, workspace_scan_case
from operator_composition_smoke import run_composition_case
from operator_native_bundle_smoke import run_native_bundle_case
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


def offline_compilers_case(c, home, fmt, source, base, result_tree, candidate, commit_body, expected_objects, oracle):
    """Consume the shipped offline CLIs' exact outputs in isolated native nodes."""
    for label, script in (("patch", "fg_source_patch.mjs"), ("refactor", "fg_source_refactor.mjs")):
        work = home / ("offline-" + label)
        work.mkdir(mode=0o700)
        rows = []
        for path in (EDIT, REMOVE, MODE, CREATE):
            before = after = None
            if path in BEFORE:
                original = work / ("before-" + path.hex())
                original.write_bytes(BEFORE[path][1])
                before = {"file": str(original), "blob": oid(fmt, "blob", BEFORE[path][1]), "mode": int(BEFORE[path][0], 8)}
            if path in AFTER:
                desired = work / ("after-" + path.hex())
                desired.write_bytes(AFTER[path][1])
                after = {"file": str(desired), "mode": int(AFTER[path][0], 8)}
            rows.append({"path_hex": path.hex(), "before": before, "after": after})
        if label == "refactor":
            # Explicit original-coordinate text -> edited binary move, plus the
            # other edit/mode effects, yields the SAME independently built tree.
            rows[1]["destination_hex"] = CREATE.hex()
            rows[1]["after"] = rows[3]["after"]
            rows.pop()
        plan = {"schema": "frankengit-source-refactoring-v1" if label == "refactor" else "frankengit-source-replacements-v1",
                "object_format": fmt, "changes": rows}
        plan_path, bad_plan, patch = work / "plan.json", work / "bad-plan.json", work / "change.patch"
        plan_path.write_text(json.dumps(plan))
        bad = json.loads(json.dumps(plan)); bad["changes"][0]["before"]["blob"] = "0" * (40 if fmt == "sha1" else 64)
        bad_plan.write_text(json.dumps(bad))
        inputs = {path: path.read_bytes() for path in work.iterdir()}
        flag = "--plan-file" if label == "refactor" else "--changes-file"
        compile_args = ["compile", flag, str(plan_path), "--output", str(patch), "--binary", "literal"]
        if label == "refactor":
            compile_args.extend(["--profile", "exact-tree-binary-v1"])
        wrong = compile_args.copy(); wrong[wrong.index(flag) + 1] = str(bad_plan)
        refused = c.node_command(ROOT / "scripts" / script, wrong, 2, error_reply=True)
        require(refused["code"] == "source_replacement_preimage" and not patch.exists(), "wrong independent preimage published an offline patch")
        compiled = c.node_command(ROOT / "scripts" / script, compile_args)
        identity = patch.stat().st_ino, file_sha256(patch)
        require(compiled["patch_sha256"] == identity[1] and compiled["patch_bytes"] == patch.stat().st_size
                and compiled["source_membership_verified"] is False and compiled["publication_attempted"] is False,
                "offline compiler changed exact bytes or claimed native authority")
        if label == "refactor":
            require(compiled["move_count"] == 1 and compiled["changed_paths"] == 4
                    and compiled["native_patch_profile"] == "exact-tree-binary-v1", "explicit edited move/profile was lost")
        refused = c.node_command(ROOT / "scripts" / script, compile_args, 2, error_reply=True)
        require(refused["code"] == f"source_{label}_destination_exists" and (patch.stat().st_ino, file_sha256(patch)) == identity
                and all(path.read_bytes() == body for path, body in inputs.items()), "compiler retry overwrote output or changed source/plan bytes")
        repository, bundle = work / "repository", work / "candidate.bundle"
        c.run("init", repository, TENANT, REPOSITORY, fmt)
        c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "offline-" + label + "-import", source)
        authority = c.run("at", repository, TENANT, REPOSITORY, "latest")
        prepared = json.loads(c.run("patch", "prepare", repository, TENANT, REPOSITORY, REF, patch, bundle,
            "--trusted-local", "--profile", "exact-tree-binary-v1", "--workspace-id", "44" * 16,
            "--expected-base", base, "--expected-result-tree", result_tree, "--author", AUTHOR,
            "--timestamp", "2", "--message", MESSAGE))
        require(prepared["node_closed"] is True and prepared["published_to_repository"] is False
                and prepared["patch_sha256"] == identity[1] and prepared["candidate_commit"] == candidate
                and prepared["root_tree"] == result_tree and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority,
                "native preparation changed source state or independently selected candidate")
        packed = bundle_objects(bundle.read_bytes(), fmt, base, candidate)
        effects = {oid(fmt, "blob", AFTER[p][1]) for p in (EDIT, MODE, CREATE)}
        inventory = {key: value for key, value in expected_objects.items() if value[0] != "blob" or key in effects}
        require(packed == inventory and packed[candidate] == ("commit", commit_body), "native compiler consumer changed exact candidate objects")
        oracle("offline-" + label + "-bundle", "bundle", "verify", "../offline-" + label + "/candidate.bundle")
        apply = ["patch", "apply", repository, TENANT, REPOSITORY, REF, bundle, "--trusted-local", "--principal", PRINCIPAL,
                 "--key-stdin", "--expected-base", base, "--expected-commit", candidate]
        key = ("offline-" + label + "-publication\n").encode()
        terminal = json.loads(c.run(*apply, input_bytes=key))
        require(terminal["node_closed"] is True and terminal["outcome"] == "committed"
                and terminal["published_to_repository"] is True and terminal["candidate_commit"] == candidate,
                "actual compiled patch failed native publication")
        authority = c.run("at", repository, TENANT, REPOSITORY, "latest")
        require(json.loads(c.run(*apply, input_bytes=key)) == terminal
                and c.run("at", repository, TENANT, REPOSITORY, "latest") == authority, "same-key compiler publication replay changed native authority")
        for path, (mode, body) in AFTER.items():
            page = json.loads(c.run("show", repository, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
                "--ref", REF, "--path-hex", path.hex(), "--max-bytes", "4096"))
            require(page["node_closed"] is True and page["source_commit"] == candidate and page["root_tree"] == result_tree
                    and page["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(page["bytes_hex"]) == body
                    and page["kind"] == ("executable" if mode == b"100755" else "file") and page["has_more"] is False,
                    "canonical compiler result lost source bytes, identity, mode or unselected sibling")
        directory = json.loads(c.run("tree", repository, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
            "--ref", REF, "--path", "dir"))
        require(directory["node_closed"] is True and {bytes.fromhex(row["name_hex"]) for row in directory["entries"]}
                == {b"edit", b"kept", b"tool"}, "compiled deletion/move left its original path")
        c.facts[f"{fmt}_offline_{label}_compiler_native_publication"] = True


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

    def oracle(label, *arguments, directory=source):
        command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
                   str(directory.relative_to(oracle_run / "work")), fmt + "-workspace-" + label, "--", *arguments]
        stem = home / ("oracle-" + label)
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
        c.record(kind="pinned_git_workspace_check", command=command, exit=result.returncode, artifacts=str(stem))
        if result.returncode:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
        require(result.returncode == 0, "pinned Git rejected the fixture or candidate bundle")

    oracle("fsck", "fsck", "--full", "--strict", "--no-reflogs")
    run_native_bundle_case(c, home, fmt, source, base, base_tree, original, BEFORE, oracle)
    offline_compilers_case(c, home, fmt, source, base, result_tree, candidate, commit_body, expected_objects, oracle)
    c.run("init", repository, TENANT, REPOSITORY, fmt, "--root-layout", "ref-merkle-v1")
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "operator-workspace-import", source)
    initial_index = json.loads(c.run("index", repository, TENANT, REPOSITORY, fmt, REF, "build", "genesis"))
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
        context_cases = acquire_context_cases(c, home, fmt, context_bundle, context, selection,
                                              token_path, grants, BEFORE, selected)
        archive_cli = ROOT / "scripts/fg_source_archive.mjs"
        archive, reused_archive = home / "source.tar", home / "reused-source.tar"
        archive_args = ["capture", "--selection", str(selection), "--token-file", str(token_path),
                        "--layout", "objects", "--output", str(archive)]
        grants("receive,outcomes-read")
        denied_archive = c.node_command(archive_cli, archive_args, 2, error_reply=True)
        require(denied_archive["type"] == "source_archive_error" and "HTTP 403" in denied_archive["message"]
                and not archive.exists(), "archive read denial produced a partial visible file")
        grants("read,receive,outcomes-read")
        archived = c.node_command(archive_cli, archive_args)
        require(archived["source_commit"] == base and archived["root_tree"] == base_tree
                and archived["files"] == len(BEFORE) and archived["archive_sha256"] == file_sha256(archive)
                and archived["native_content_and_paths_verified"] is True
                and archived["authority_signatures_verified"] is archived["repository_backup"] is False,
                "native archive changed exact source selection or authority class")
        decode = """const {readFileSync}=require('node:fs');
import(process.argv[1]).then(({restoreSourceCapture})=>{
const c=restoreSourceCapture(readFileSync(process.argv[2]),process.argv[3]);
console.log(JSON.stringify({commit:c.commit,trees:c.trees,files:c.files.map(f=>({path_hex:f.path_hex,
object_id:f.object_id,kind:f.kind,body_hex:Buffer.from(f.bytes).toString('hex')}))}));});"""
        unpacked = c.node_command(Path("-e"), [decode, (ROOT / "scripts/operator/source_archive_tar.mjs").as_uri(),
                                             str(archive), archived["archive_sha256"]])
        require(unpacked["commit"] == {"object_id": base, "body_hex": base_body.hex()}
                and {row["path_hex"]: (row["object_id"], row["body_hex"]) for row in unpacked["trees"]}
                    == {p.hex() if p else None: (identity, body.hex()) for p, (identity, body) in trees.items()}
                and len(unpacked["files"]) == len(BEFORE)
                and {bytes.fromhex(row["path_hex"]): (row["object_id"], row["kind"], row["body_hex"]) for row in unpacked["files"]}
                    == {p: (oid(fmt, "blob", body), "executable" if mode == b"100755" else "file", body.hex())
                        for p, (mode, body) in BEFORE.items()}, "archive bytes/modes/complete membership differ from independent Git fixture")
        c.facts[f"{fmt}_native_archive_and_grant_twins"] = True
        reused_args = [*archive_args[:-1], str(reused_archive), "--reuse-archive", str(archive),
                       "--reuse-sha256", archived["archive_sha256"]]
        reused = c.node_command(archive_cli, reused_args)
        require(reused["source_commit"] == base and reused["archive_sha256"] == file_sha256(reused_archive)
                and reused["reuse_archive_sha256"] == archived["archive_sha256"]
                and reused["read_metrics"]["reused_files"] == len(BEFORE)
                and reused["read_metrics"]["blob_requests"] == reused["read_metrics"]["downloaded_blob_bytes"] == 0,
                "archive reuse skipped fresh membership verification or redownloaded payloads")
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
    inspect_context_cases(c, home, fmt, context_cases)
    inspected_archive = c.node_command(archive_cli, ["inspect", "--archive", str(reused_archive), "--sha256", reused["archive_sha256"]])
    require(inspected_archive["source_commit"] == base and inspected_archive["files"] == len(BEFORE),
            "offline archive inspection lost complete native source")
    c.node_command(archive_cli, ["inspect", "--archive", str(reused_archive), "--sha256", "0" * 64], 2, error_reply=True)
    require(file_sha256(archive) == archived["archive_sha256"] and file_sha256(reused_archive) == reused["archive_sha256"],
            "offline wrong-pin refusal changed retained archives")
    c.facts[f"{fmt}_native_archive_reuse_and_offline_verification"] = True
    c.node_command(context_cli, ["inspect", "--bundle", str(context_bundle), "--expected-sha256", context["manifest_sha256"]])
    c.node_command(package_cli, ["inspect", *package_common, "--package", str(package_path),
                                 "--package-sha256", acquired["package_sha256"]])
    c.node_command(ROOT / "scripts/fg_verify_source_package.mjs", ["--package", str(package_path), "--expect", str(expect_path)])
    wrong_selection = json.loads(json.dumps(independent))
    wrong_selection["files"][0]["blob"] = "f" * len(base)
    wrong_expect = put("wrong-verification-selection.json", wrong_selection)
    refused = c.node_command(ROOT / "scripts/fg_verify_source_package.mjs",
        ["--package", str(package_path), "--expect", str(wrong_expect)], 1, error_reply=True, text_reply=True)
    require(refused == "Source package verification failed. No files were written and no network request was made.\n"
            and file_sha256(package_path) == acquired["package_sha256"], "offline package verifier accepted wrong blob pins or rewrote source")
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
    workspace_scan_case(c, home, fmt, workspace, workspace_hash, capture, captured, BEFORE, AFTER, paths, result_tree)

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
        # Continue the SAME independently acquired workspace across a real native
        # branch advance. No fixture replaces refresh, source verification or CAS.
        old_workspace = workspace.with_name(workspace.name + ".retained")
        local_text = b"LOCAL\r\nwithout final LF"
        (old_workspace / "files/dir/edit").write_bytes(local_text)
        remote = {**AFTER, EDIT: (b"100644", b"before\r\nREMOTE without LF"),
                  REMOVE: (b"100644", b"\0upstream binary replacement\xff"),
                  MODE: (b"100644", b"#!/bin/true\n"),
                  b"dir/kept": (b"100644", b"upstream unselected\0sibling")}
        # The independent bare oracle also needs C, the parent of this upstream B.
        for identity, (kind, body) in expected_objects.items():
            require(loose(source, fmt, kind, body) == identity, "original candidate object framing changed")
        remote_tree, _ = file_tree(fmt, remote, lambda kind, body: loose(source, fmt, kind, body))
        remote_body = f"tree {remote_tree}\nparent {candidate}\nauthor {AUTHOR} 3 +0000\ncommitter {AUTHOR} 3 +0000\n\nupstream\n".encode()
        upstream = loose(source, fmt, "commit", remote_body)
        final_files = {**remote, EDIT: (b"100755", b"LOCAL\r\nREMOTE without LF"), MODE: (b"100755", remote[MODE][1])}
        del final_files[REMOVE]
        final_objects = {}

        def final_object(kind, body):
            identity = oid(fmt, kind, body); final_objects[identity] = kind, body; return identity

        final_tree, final_trees = file_tree(fmt, final_files, final_object)
        final_message = "Publish refreshed local edits\n"
        final_body = f"tree {final_tree}\nparent {upstream}\nauthor {AUTHOR} 4 +0000\ncommitter {AUTHOR} 4 +0000\n\n{final_message}".encode()
        final_commit = final_object("commit", final_body)
        next_expected = put("next-expected.json", {"format": fmt, "commit": upstream,
            "files": [{"pathHex": p.hex(), "blob": oid(fmt, "blob", remote[p][1])} for p in selected]})
        (source / REF).write_text(upstream + "\n")
        oracle("upstream-fsck", "fsck", "--full", "--strict", "--no-reflogs")
        oracle("upstream-bundle", "bundle", "create", "../upstream.bundle", REF)
        c.run("bundle", "sync-import", repository, TENANT, REPOSITORY, home / "upstream.bundle",
              "--trusted-local", "--object-format", fmt, "--principal", PRINCIPAL, "--key-stdin",
              "--allow-ref-updates", "--expect", REF + "=" + candidate, input_bytes=b"operator-workspace-upstream")
        require(refs() == {REF: upstream}, "upstream import did not select independent B")
        grants("read,receive,outcomes-read")
        refreshing = server
        # Keep the same owned listener and immutable candidate endpoint. A new
        # explicitly staged stale proposal must not republish the old source.
        stale_journal = home / "stale-journal"
        old_candidate = candidate_path.with_name(candidate_path.name + ".retained")
        stale = c.node_command(edit_cli, ["stage", "--candidate", str(old_candidate), "--sha256", prepared["manifest_sha256"],
            "--principal", PRINCIPAL, "--confirm-candidate", candidate, "--journal", str(stale_journal)])
        # A retained committed C outcome is history, not the current branch tip.
        original = c.node_command(edit_cli, ["status", *base_args])
        require(original["decision"] == applied["decision"] and refs() == {REF: upstream}, "old outcome became current branch truth")
        stale_args = ["--journal", str(stale_journal), "--request-sha256", stale["request_sha256"]]
        stale_result = c.node_command(edit_cli, ["apply", *stale_args, "--token-file", str(token_path)], 2)
        require(stale_result["decision"]["outcome"] == "refused" and refs() == {REF: upstream}, "stale source overwrote the newer ref")
        after_refusal = c.run("at", repository, TENANT, REPOSITORY, "latest")
        stale_recovery = c.node_command(edit_cli, ["recover", *stale_args, "--token-file", str(token_path)], 2)
        require(stale_recovery["decision"] == stale_result["decision"] and stale_recovery["key"] == stale["key"]
                and stale_recovery["submission_retried"] is False
                and c.run("at", repository, TENANT, REPOSITORY, "latest") == after_refusal, "stale refusal recovery changed its outcome or republished")
        c.facts[f"{fmt}_refresh_stale_publication"] = True

        # The canonical refusal advanced authority, despite leaving B's ref
        # unchanged. Build the exact-source index AFTER those decisions settle.
        c.run("index", repository, TENANT, REPOSITORY, fmt, REF, "build", initial_index["index_token"])
        next_pin = native("show", "--ref", REF, "--path-hex", EDIT.hex())
        next_context = home / "next-context"
        next_query = put("next-query.json", {"schema": "frankengit-source-context-query-v1", "scope": {
            "tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": incarnation,
            "object_format": fmt}, "reference": REF, "expected_commit": upstream,
            "expected_head": next_pin["snapshot_token"], "terms": ["dir"],
            "prefixes_hex": [p.hex() for p in selected], "limits": {"context_max_files": 3}})
        context = c.node_command(context_cli, ["capture", "--endpoint", refreshing.url, "--query-file", str(next_query),
            "--token-file", str(token_path), "--output", str(next_context), "--require-complete"])
        next_selection = put("next-selection.json", {"endpoint": refreshing.url, "tenant_id": TENANT,
            "repository_id": REPOSITORY, "repository_incarnation": incarnation, "object_format": fmt,
            "ref": REF, "expected_commit": upstream, "expected_head": next_pin["snapshot_token"]})
        next_package = home / "next-package.json"
        next_receipt = c.node_command(package_cli, ["capture", "--selection", str(next_selection),
            "--context", str(next_context / "capture.json"), "--context-sha256", context["capture_sha256"],
            "--expect", str(next_expected), "--token-file", str(token_path), "--output", str(next_package), "--native-fg", str(c.fg)])
        require(next_receipt["native_read"]["head"] == next_pin["snapshot_token"]
                and next_receipt["native_read"]["verified_at_capture"] is True
                and next_receipt["native_read"]["files"] == len(selected)
                and next_receipt["native_read"]["binary_sha256"] == file_sha256(c.fg)
                and next_receipt["verified"]["authorityVerified"] is False, "refresh lost its independently selected native source")
        refresh_args = ["--workspace", str(old_workspace), "--sha256", workspace_hash,
                        "--package", str(next_package), "--expect", str(next_expected)]
        plain = c.node_command(workspace_cli, ["refresh-preview", *refresh_args], 1)
        require(plain["conflict_count"] == 2 and plain["ready"] is False, "default refresh silently merged content")
        profile = ["--merge-profile", "bounded-line-merge-v1"]
        conflicted = c.node_command(workspace_cli, ["refresh-preview", *refresh_args, *profile], 1)
        entries = {row["path_hex"]: row for row in conflicted["entries"]}
        require(conflicted["conflict_count"] == 1 and entries[EDIT.hex()]["disposition"] == "text_merged"
                and entries[MODE.hex()]["disposition"] == "combined"
                and entries[REMOVE.hex()]["conflict"] == "local_delete_source_modify", "bounded refresh failed independent text/mode reconciliation")
        output = home / "refreshed-workspace"
        def refresh(plan, extra=()):
            return ["refresh", *refresh_args, *profile, *extra, "--approve-refresh-sha256", plan, "--output", str(output)]
        unresolved = c.node_command(workspace_cli, refresh(conflicted["refresh_sha256"]), 2, error_reply=True)
        require(unresolved["code"] == "source_workspace_refresh_conflict", "unresolved plan failed for an unrelated reason")
        require(not output.exists(), "unresolved refresh acquired output custody")
        choices = put("refresh-choices.json", {"schema": "frankengit-workspace-refresh-resolutions-v1",
            "plan_sha256": conflicted["refresh_sha256"], "choices": [{"path_hex": REMOVE.hex(), "choice": "local"}]})
        resolution = ["--resolutions", str(choices)]
        resolved = c.node_command(workspace_cli, ["refresh-preview", *refresh_args, *profile, *resolution])
        require(resolved["ready"] is True and resolved["resolved_conflict_count"] == 1, "explicit deletion choice was not reviewed")
        old_approval = c.node_command(workspace_cli, refresh(conflicted["refresh_sha256"], resolution), 2, error_reply=True)
        require(old_approval["code"] == "source_workspace_refresh_review_changed", "old approval was not fenced")
        (old_workspace / "files/dir/edit").write_bytes(local_text + b"CHANGED")
        moved_local = c.node_command(workspace_cli, refresh(resolved["refresh_sha256"], resolution), 2, error_reply=True)
        require(moved_local["code"] == "source_workspace_refresh_resolution_plan_changed", "local editor change was not fenced")
        require(not output.exists(), "stale refresh consent published output")
        (old_workspace / "files/dir/edit").write_bytes(local_text)
        refreshed = c.node_command(workspace_cli, refresh(resolved["refresh_sha256"], resolution))
        require(refreshed["source_commit"] == upstream and (output / "files/dir/edit").read_bytes() == final_files[EDIT][1]
                and (output / "files/dir/tool").read_bytes() == final_files[MODE][1]
                and (output / "files/dir/tool").stat().st_mode & 0o100 != 0 and not (output / "files/dir/remove").exists()
                and not (output / "files/new/created").exists() and (old_workspace / "files/new/created").read_bytes() == AFTER[CREATE][1]
                and (old_workspace / "files/dir/edit").read_bytes() == local_text, "refresh lost local bytes/modes/deletion or copied unselected files")
        c.facts[f"{fmt}_refresh_review_and_exact_result"] = True
        refreshed_capture = home / "refreshed-capture"
        refresh_paths = put("refresh-paths.json", {"paths_hex": [p.hex() for p in selected], "byte_profile": "binary-safe-v1"})
        captured_refresh = c.node_command(workspace_cli, ["capture", "--workspace", str(output), "--sha256", refreshed["workspace_sha256"],
            "--paths", str(refresh_paths), "--output", str(refreshed_capture)])
        require(captured_refresh["expected_tree"] == final_tree and captured_refresh["changed_path_count"] == 3,
                "refreshed capture differs from independent final tree")
        final_selection = put("refreshed-selection.json", {"endpoint": refreshing.url, "scope": {
            "tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": incarnation, "object_format": fmt},
            "ref": REF, "expected_commit": upstream, "metadata": {"author": AUTHOR, "committer": AUTHOR,
            "timestamp": 4, "message": final_message}, "paths_hex": [p.hex() for p in selected],
            "patch_profile": "exact-tree-binary-v1", "parent_tree_profile": "verified-parent-trees-v1", "expected_result_tree": final_tree})
        fresh_candidate, fresh_journal = home / "refreshed-candidate", home / "refreshed-journal"
        common_refresh = ["--package", str(refreshed_capture / "source.json"), "--expect", str(refreshed_capture / "expected.json"),
            "--changes", str(refreshed_capture / "changes.json"), "--confirm-draft-sha256", captured_refresh["draft_sha256"]]
        prepared_refresh = c.node_command(changes_cli, ["prepare-packed", *common_refresh, "--selection", str(final_selection),
            "--token-file", str(token_path), "--output", str(fresh_candidate)])
        require(prepared_refresh["candidate_commit"] == final_commit, "native refreshed commit differs from independent framing")
        packed = bundle_objects((fresh_candidate / "candidate.bundle").read_bytes(), fmt, upstream, final_commit)
        wanted_ids = {final_commit, final_tree, final_trees[b"dir"][0], oid(fmt, "blob", final_files[EDIT][1]), oid(fmt, "blob", final_files[MODE][1])}
        require(packed == {key: final_objects[key] for key in wanted_ids}, "refreshed pack includes unselected source or omits an effect")
        (home / "refreshed.bundle").write_bytes((fresh_candidate / "candidate.bundle").read_bytes())
        oracle("refreshed-bundle", "bundle", "verify", "../refreshed.bundle")
        fresh = c.node_command(changes_cli, ["stage-packed", *common_refresh, "--selection", str(final_selection),
            "--candidate", str(fresh_candidate), "--sha256", prepared_refresh["manifest_sha256"], "--principal", PRINCIPAL,
            "--confirm-candidate", final_commit, "--journal", str(fresh_journal)])
        require(fresh["key"] != stale["key"] and fresh["key"] != staged["key"], "new reviewed semantics reused an old key")
        fresh_args = ["--journal", str(fresh_journal), "--request-sha256", fresh["request_sha256"]]
        published = c.node_command(edit_cli, ["apply", *fresh_args, "--token-file", str(token_path)])
        require(published["decision"]["outcome"] == "committed" and refs() == {REF: final_commit}, "refreshed candidate did not publish exactly")
        for path, (mode, body) in final_files.items():
            row = native("show", "--ref", REF, "--path-hex", path.hex())
            require(row["source_commit"] == final_commit and row["node_closed"] is True and bytes.fromhex(row["bytes_hex"]) == body
                    and row["kind"] == ("executable" if mode == b"100755" else "file"), "refreshed canonical bytes/modes/siblings differ")
        selected_tree = native("tree", "--ref", REF, "--path", "dir")
        require({bytes.fromhex(r["name_hex"]) for r in selected_tree["entries"]} == {b"edit", b"kept", b"tool"}, "refresh resurrected a deletion")
        after_refresh = c.run("at", repository, TENANT, REPOSITORY, "latest")
        fresh_terminal = (fresh_journal / "terminal.json").read_bytes()
        (fresh_journal / "terminal.json").rename(fresh_journal / "terminal.retained")
        c.node_command(edit_cli, ["apply", *fresh_args, "--token-file", str(token_path)], 2, error_reply=True)
        grants("outcomes-read")
        recovered_refresh = c.node_command(edit_cli, ["recover", *fresh_args, "--token-file", str(token_path)])
        require(recovered_refresh["decision"] == published["decision"] and recovered_refresh["submission_retried"] is False
                and recovered_refresh["key"] == fresh["key"] and (fresh_journal / "terminal.json").read_bytes() == fresh_terminal,
                "refreshed recovery changed its key or exact decision bytes")
        stale_terminal = (stale_journal / "terminal.json").read_bytes()
        (stale_journal / "terminal.json").rename(stale_journal / "terminal.retained")
        recovered_stale = c.node_command(edit_cli, ["recover", *stale_args, "--token-file", str(token_path)], 2)
        require(recovered_stale["decision"] == stale_result["decision"] and recovered_stale["key"] == stale["key"]
                and recovered_stale["submission_retried"] is False and (stale_journal / "terminal.json").read_bytes() == stale_terminal
                and c.run("at", repository, TENANT, REPOSITORY, "latest") == after_refresh and refs() == {REF: final_commit},
                "historical refusal recovery changed canonical state or transaction identity")
    c.facts[f"{fmt}_refresh_publication_and_drain"] = True
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
        "scripts/fg_source_changes.mjs", "scripts/fg_source_edit.mjs", "scripts/fg_source_archive.mjs",
        "scripts/fg_context_session.mjs", "scripts/fg_context_proof.mjs", "scripts/fg_source_workspace_scan.mjs",
        "scripts/fg_source_assembly.mjs", "scripts/fg_source_replay.mjs", "scripts/fg_source_patch.mjs",
        "scripts/fg_source_refactor.mjs", "scripts/verify_git_bundle_native.mjs",
        "scripts/import_git_bundle_native.mjs", "scripts/recover_git_bundle.mjs"], "oracle_pin": "git-2.54.0",
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
            run_composition_case(c, oracle_run, fmt, file_tree, BEFORE, {EDIT: AFTER[EDIT], MODE: AFTER[MODE]}, AUTHOR)
        commands = [json.loads(line) for line in c.journal.read_text().splitlines()]
        summary["entrypoint_runs"] = []
        for path in summary["entrypoints"]:
            calls = [r for r in commands if r.get("kind") == "operator" and r["command"][1] == str(ROOT / path)]
            successes = sum(r["exit"] == 0 for r in calls)
            nonzero = sum(r["exit"] != 0 for r in calls)
            require(successes > 0 and nonzero > 0, "listed source entrypoint lacks actual success/expected-nonzero calls: " + path)
            summary["entrypoint_runs"].append({"path": path, "binary_sha256": summary["binary_sha256"],
                "client_sha256": file_sha256(ROOT / path), "success_count": successes, "expected_nonzero_count": nonzero})
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
