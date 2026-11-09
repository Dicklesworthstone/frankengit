"""Native consumers of reviewed assembly and explicit exact-preimage replay.

Reuse the workspace fixture, pinned Git sandbox, command journal and owned HTTP
service. Neither contributor labels nor saved review hashes supply authority.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys

from patch_smoke import loose, oid
from full_bundle_smoke import decode_export
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
MAIN, ASSEMBLED = "refs/heads/main", "refs/heads/assembled"


def run_composition_case(c, oracle_run, fmt, build_tree, before, edits, author):
    home = c.work / (fmt + "-composition")
    home.mkdir(mode=0o700)
    source, repository = home / "source", home / "repository"
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_text("ref: " + MAIN + "\n")
    (source / "config").write_text("[core]\nbare=true\nrepositoryformatversion=" +
        ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"))
    base_tree, _ = build_tree(fmt, before, lambda kind, body: loose(source, fmt, kind, body))
    base_body = f"tree {base_tree}\nauthor {author} 1 +0000\ncommitter {author} 1 +0000\n\ncomposition base\n".encode()
    base = loose(source, fmt, "commit", base_body)
    for ref in (MAIN, ASSEMBLED):
        (source / ref).write_text(base + "\n")

    def put(name, value):
        path = home / name
        with path.open("x", encoding="utf-8") as out:
            json.dump(value, out)
        return path

    def oracle(label, *arguments):
        command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
            str(source.relative_to(oracle_run / "work")), fmt + "-composition-" + label, "--", *arguments]
        stem = home / (label + ".oracle")
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
        c.record(kind="pinned_git_composition_check", command=command, exit=result.returncode, artifacts=str(stem))
        if result.returncode:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
        require(result.returncode == 0, "pinned Git rejected composition fixture/candidate")

    oracle("base", "fsck", "--full", "--strict", "--no-reflogs")
    c.run("init", repository, TENANT, REPOSITORY, fmt, "--root-layout", "ref-merkle-v2")
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "composition-fixture", source)
    initial_index = json.loads(c.run("index", repository, TENANT, REPOSITORY, fmt, MAIN, "build", "genesis"))
    credentials, incarnation = c.credentials(repository, home)
    header = credentials.read_text().splitlines()[0]
    token, token_path = "a" * 64, home / "token"
    token_path.write_text(token)

    def grants(scopes):
        pending = home / "credentials.next"
        with pending.open("x", encoding="ascii") as out:
            out.write(header + "\n" + hashlib.sha256(token.encode()).hexdigest() + f" {PRINCIPAL} {scopes}\n")
        pending.replace(credentials)

    grants("read,receive,outcomes-read")

    def native(verb, *args):
        return json.loads(c.run(verb, repository, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt, *args))

    def head():
        return c.run("at", repository, TENANT, REPOSITORY, "latest")

    def refs():
        page = native("refs")
        require(page["node_closed"] is True and page["has_more"] is False and page["next_after_hex"] is None,
                "composition native ref read did not close")
        names = [bytes.fromhex(row["reference_hex"]).decode() for row in page["references"]]
        require(names == sorted(set(names)), "composition native references are duplicated/unordered")
        return dict(zip(names, (row["tip"] for row in page["references"])))

    def check_source(ref, commit, tree, files):
        for path, (mode, body) in files.items():
            row = native("show", "--ref", ref, "--path-hex", path.hex())
            require(row["node_closed"] is True and row["has_more"] is False and row["next_offset"] is None
                    and row["source_commit"] == commit and row["root_tree"] == tree
                    and row["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(row["bytes_hex"]) == body
                    and row["kind"] == ("executable" if mode == b"100755" else "file"),
                    "canonical composition source differs from independent bytes/modes/tree")

    context_cli, package_cli = ROOT / "scripts/fg_source_context.mjs", ROOT / "scripts/fg_source_package.mjs"
    workspace_cli, changes_cli = ROOT / "scripts/fg_source_workspace.mjs", ROOT / "scripts/fg_source_changes.mjs"
    assembly_cli, replay_cli = ROOT / "scripts/fg_source_assembly.mjs", ROOT / "scripts/fg_source_replay.mjs"
    publisher = ROOT / "scripts/fg_source_edit.mjs"
    server = HttpServer(c, repository, credentials, "composition-" + fmt)
    server.command.extend(["--allow-source", "--allow-receive", "--allow-outcomes"])
    selected = sorted(edits)
    require(len(selected) == 2 and refs() == {ASSEMBLED: base, MAIN: base}, "composition needs two independent fixture edits")
    with server:
        def package(label, ref, commit, files, paths):
            observed = native("show", "--ref", ref, "--path-hex", paths[0].hex())
            require(observed["source_commit"] == commit and observed["object_id"] == oid(fmt, "blob", files[paths[0]][1]),
                    "independent package source does not match native selected ref")
            expected = {"format": fmt, "commit": commit,
                "files": [{"pathHex": p.hex(), "blob": oid(fmt, "blob", files[p][1])} for p in paths]}
            expected_path = put(label + "-expected.json", expected)
            query = put(label + "-query.json", {"schema": "frankengit-source-context-query-v1", "scope": {
                "tenant_id": TENANT, "repository_id": REPOSITORY, "repository_incarnation": incarnation, "object_format": fmt},
                "reference": ref, "expected_commit": commit, "expected_head": observed["snapshot_token"],
                "terms": ["dir"], "prefixes_hex": [p.hex() for p in paths], "limits": {"context_max_files": len(paths)}})
            context_dir = home / (label + "-context")
            context = c.node_command(context_cli, ["capture", "--endpoint", server.url, "--query-file", str(query),
                "--token-file", str(token_path), "--output", str(context_dir), "--require-complete"])
            selection = put(label + "-source-selection.json", {"endpoint": server.url, "tenant_id": TENANT,
                "repository_id": REPOSITORY, "repository_incarnation": incarnation, "object_format": fmt,
                "ref": ref, "expected_commit": commit, "expected_head": observed["snapshot_token"]})
            output = home / (label + "-source.json")
            captured = c.node_command(package_cli, ["capture", "--selection", str(selection), "--context", str(context_dir / "capture.json"),
                "--context-sha256", context["capture_sha256"], "--expect", str(expected_path), "--token-file", str(token_path),
                "--output", str(output), "--native-fg", str(c.fg)])
            require(captured["native_read"]["verified_at_capture"] is True and captured["package_sha256"] == file_sha256(output),
                    "composition source package lacks its actual native read receipt")
            value = json.loads(output.read_bytes())
            require(value["membership"]["files"] == [{"pathHex": p.hex(), "blob": oid(fmt, "blob", files[p][1]),
                "kind": "executable" if files[p][0] == b"100755" else "file"} for p in paths], "package selected the wrong native files")
            return output, expected_path

        before_head = head()
        contributions = []
        originals = {}
        for index, path in enumerate(selected):
            label = "contributor-" + str(index)
            source_package, expected = package(label, MAIN, base, before, [path])
            workspace, capture = home / (label + "-workspace"), home / (label + "-capture")
            created = c.node_command(workspace_cli, ["create", "--package", str(source_package), "--expect", str(expected), "--output", str(workspace)])
            edited = workspace / "files" / path.decode()
            edited.write_bytes(edits[path][1]); edited.chmod(0o700 if edits[path][0] == b"100755" else 0o600)
            paths = put(label + "-paths.json", {"paths_hex": [path.hex()], "byte_profile": "binary-safe-v1"})
            captured = c.node_command(workspace_cli, ["capture", "--workspace", str(workspace), "--sha256", created["workspace_sha256"],
                "--paths", str(paths), "--output", str(capture)])
            row = {"id": label, "package": str(capture / "source.json"), "expect": str(capture / "expected.json"),
                "changes": str(capture / "changes.json"), "confirm_draft_sha256": captured["draft_sha256"]}
            for field in ("package", "expect", "changes"):
                originals[Path(row[field])] = Path(row[field]).read_bytes()
            contributions.append(row)
        require(head() == before_head, "native contribution capture published repository state")
        overlap = put("overlap.json", {"contributions": [contributions[0], {**contributions[0], "id": "overlapping"}]})
        denied = c.node_command(assembly_cli, ["capture", "--contributions", str(overlap), "--output", str(home / "overlap")], 2, error_reply=True)
        require(denied["code"] == "source_assembly_write_conflict" and not (home / "overlap").exists(), "overlapping assembly was not refused before publication")
        wrong = put("wrong-review.json", {"contributions": [{**contributions[0], "confirm_draft_sha256": "0" * 64}, contributions[1]]})
        denied = c.node_command(assembly_cli, ["capture", "--contributions", str(wrong), "--output", str(home / "wrong-review")], 2, error_reply=True)
        require(denied["code"] == "source_assembly_confirmation" and not (home / "wrong-review").exists(), "assembly ignored an original review pin")
        selection = put("contributions.json", {"contributions": list(reversed(contributions))})
        assembly = home / "assembly"
        assembled = c.node_command(assembly_cli, ["capture", "--contributions", str(selection), "--output", str(assembly)])
        c.node_command(assembly_cli, ["inspect", "--capture", str(assembly), "--sha256", assembled["capture_sha256"]])
        forward_selection = put("forward-contributions.json", {"contributions": contributions})
        forward = home / "assembly-forward"
        reordered = c.node_command(assembly_cli, ["capture", "--contributions", str(forward_selection), "--output", str(forward)])
        require(reordered["capture_sha256"] == assembled["capture_sha256"]
                and {p.name: p.read_bytes() for p in forward.iterdir()} == {p.name: p.read_bytes() for p in assembly.iterdir()},
                "contribution order changed canonical assembly bytes or attribution")
        require(assembled["contribution_count"] == 2 and assembled["effect_count"] == 2 and assembled["new_review_required"] is True
                and assembled["publication_authorized"] is assembled["repository_changed"] is False
                and all(path.read_bytes() == body for path, body in originals.items()), "assembly changed original custody or consent")
        c.facts[f"{fmt}_composition_native_contributions_and_conflict"] = True

        def publish(label, capture, saved, ref, parent, files, timestamp, old_review):
            objects = {}

            def store(kind, body):
                identity = oid(fmt, kind, body); objects[identity] = kind, body; return identity

            expected_tree, _ = build_tree(fmt, files, store)
            message = "Explicit " + label + "\n"
            body = f"tree {expected_tree}\nparent {parent}\nauthor {author} {timestamp} +0000\ncommitter {author} {timestamp} +0000\n\n{message}".encode()
            candidate = store("commit", body)
            require(saved["expected_tree"] == expected_tree, "composition expected tree differs from independent whole-tree result")
            target = put(label + "-target.json", {"endpoint": server.url, "scope": {"tenant_id": TENANT,
                "repository_id": REPOSITORY, "repository_incarnation": incarnation, "object_format": fmt},
                "ref": ref, "expected_commit": parent, "metadata": {"author": author, "committer": author,
                "timestamp": timestamp, "message": message}, "paths_hex": [p.hex() for p in selected],
                "patch_profile": "exact-tree-binary-v1", "expected_result_tree": expected_tree,
                "parent_tree_profile": "verified-parent-trees-v1"})
            common = ["--package", str(capture / "source.json"), "--expect", str(capture / "expected.json"), "--changes", str(capture / "changes.json")]
            output = home / (label + "-candidate")
            prepare = ["prepare-packed", *common, "--selection", str(target), "--token-file", str(token_path), "--output", str(output)]
            denied = c.node_command(changes_cli, [*prepare, "--confirm-draft-sha256", old_review], 2, error_reply=True)
            require(denied["code"] == "source_changes_confirmation" and not output.exists(), "prepare did not report the expected new-review refusal")
            prepared = c.node_command(changes_cli, [*prepare, "--confirm-draft-sha256", saved["draft_sha256"]])
            require(prepared["candidate_commit"] == candidate, "native composition preparation changed exact commit bytes")
            bundle = (output / "candidate.bundle").read_bytes()
            prefix = b"# v2 git bundle\n" if fmt == "sha1" else b"# v3 git bundle\n@object-format=sha256\n"
            require(bundle.split(b"\n\n", 1)[0] == prefix + f"-{parent} patch base\n{candidate} {ref}".encode(),
                    "composition bundle changed the exact parent or selected target ref")
            # Check the incremental envelope above; reuse the existing generic
            # full-object decoder without changing any returned bundle bytes.
            _, packed = decode_export(bundle, fmt)
            effect_blobs = {oid(fmt, "blob", files[p][1]) for p in selected}
            require(packed == {key: value for key, value in objects.items()
                if value[0] != "blob" or key in effect_blobs}, "native composition pack differs from independent objects")
            (home / (label + ".bundle")).write_bytes(bundle)
            oracle(label + "-bundle", "bundle", "verify", "../" + label + ".bundle")
            c.node_command(changes_cli, ["inspect-packed", *common, "--confirm-draft-sha256", saved["draft_sha256"],
                "--candidate", str(output), "--sha256", prepared["manifest_sha256"]])
            journal = home / (label + "-journal")
            stage = ["stage-packed", *common, "--selection", str(target), "--candidate", str(output),
                "--sha256", prepared["manifest_sha256"], "--principal", PRINCIPAL, "--confirm-candidate", candidate, "--journal", str(journal)]
            refused = c.node_command(changes_cli, [*stage, "--confirm-draft-sha256", old_review], 2, error_reply=True)
            require(refused["code"] == "source_changes_confirmation" and not journal.exists(), "stage did not report the expected new-review refusal")
            staged = c.node_command(changes_cli, [*stage, "--confirm-draft-sha256", saved["draft_sha256"]])
            request = (journal / "request.json").read_bytes()
            args = ["--journal", str(journal), "--request-sha256", staged["request_sha256"], "--token-file", str(token_path)]
            result = c.node_command(publisher, ["apply", *args])
            require(result["decision"]["outcome"] == "committed" and result["submission_retried"] is False, "composition native apply did not commit")
            check_source(ref, candidate, expected_tree, files)
            return dict(candidate=candidate, tree=expected_tree, journal=journal, request=request, args=args, decision=result["decision"], key=staged["key"])

        assembled_files = {**before, **edits}
        first = publish("assembled", assembly, assembled, ASSEMBLED, base, assembled_files, 2, contributions[0]["confirm_draft_sha256"])
        require(refs() == {ASSEMBLED: first["candidate"], MAIN: base}, "assembly changed another branch")
        c.facts[f"{fmt}_composition_assembly_consent_and_canonical_publication"] = True
        next_files = {**before, b"keep.bin": (b"100644", b"unrelated next-base bytes\0\xff")}
        next_tree, _ = build_tree(fmt, next_files, lambda kind, body: loose(source, fmt, kind, body))
        next_body = f"tree {next_tree}\nparent {base}\nauthor {author} 3 +0000\ncommitter {author} 3 +0000\n\nunrelated next base\n".encode()
        next_commit = loose(source, fmt, "commit", next_body)
        (source / MAIN).write_text(next_commit + "\n")
        oracle("next-base", "fsck", "--full", "--strict", "--no-reflogs")
        oracle("next-base-bundle", "bundle", "create", "../next-base.bundle", MAIN)
        c.run("bundle", "sync-import", repository, TENANT, REPOSITORY, home / "next-base.bundle", "--trusted-local",
            "--object-format", fmt, "--principal", PRINCIPAL, "--key-stdin", "--allow-ref-updates", "--expect", MAIN + "=" + base,
            input_bytes=b"composition-independent-next-base")
        c.run("index", repository, TENANT, REPOSITORY, fmt, MAIN, "build", initial_index["index_token"])
        next_package, next_expected = package("next", MAIN, next_commit, next_files, selected)
        c.run("index", repository, TENANT, REPOSITORY, fmt, ASSEMBLED, "build", "genesis")
        changed_package, changed_expected = package("changed", ASSEMBLED, first["candidate"], assembled_files, selected)
        original = ["--package", str(assembly / "source.json"), "--expect", str(assembly / "expected.json"),
            "--changes", str(assembly / "changes.json"), "--confirm-draft-sha256", assembled["draft_sha256"]]
        denied = c.node_command(replay_cli, ["capture", *original, "--next-package", str(changed_package),
            "--next-expect", str(changed_expected), "--output", str(home / "changed-replay")], 2, error_reply=True)
        require(denied["code"] == "source_replay_read_set_changed" and not (home / "changed-replay").exists(), "replay accepted changed selected preimages")
        replay = home / "replay"
        replayed = c.node_command(replay_cli, ["capture", *original, "--next-package", str(next_package),
            "--next-expect", str(next_expected), "--output", str(replay)])
        require(replayed["original_commit"] == base and replayed["selected_commit"] == next_commit
                and replayed["draft_sha256"] != assembled["draft_sha256"] and replayed["new_review_required"] is True
                and replayed["selected_read_set_preserved"] is replayed["exact_patch_preserved"] is True
                and replayed["authority_verified"] is replayed["ancestry_verified"] is False
                and (replay / "patch.diff").read_bytes() == (assembly / "patch.diff").read_bytes(), "replay changed original intent or exaggerated authority")
        c.facts[f"{fmt}_composition_replay_refusal_and_explicit_next_base"] = True
        second = publish("replayed", replay, replayed, MAIN, next_commit, {**next_files, **edits}, 4, assembled["draft_sha256"])
        require(refs() == {ASSEMBLED: first["candidate"], MAIN: second["candidate"]}, "replay lost an unrelated published branch")
        c.facts[f"{fmt}_composition_replay_consent_and_canonical_publication"] = True
        settled_head = head()
        recovered = c.node_command(publisher, ["recover", *first["args"]])
        require(recovered["decision"] == first["decision"] and recovered["key"] == first["key"]
                and recovered["submission_retried"] is False and head() == settled_head
                and (first["journal"] / "request.json").read_bytes() == first["request"], "later replay retargeted original journal or canonical outcome")

    for cli, capture, saved in [(assembly_cli, assembly, assembled), (replay_cli, replay, replayed)]:
        observed = c.node_command(cli, ["inspect", "--capture", str(capture), "--sha256", saved["capture_sha256"]])
        require(observed["capture_sha256"] == saved["capture_sha256"] and observed["draft_sha256"] == saved["draft_sha256"], "offline composition inspection changed its review/custody")
        c.node_command(cli, ["inspect", "--capture", str(capture), "--sha256", "0" * 64], 2, error_reply=True)
    require(all(path.read_bytes() == body for path, body in originals.items()) and server.process is None
            and head() == settled_head and refs() == {ASSEMBLED: first["candidate"], MAIN: second["candidate"]},
            "composition lost original input custody or changed state after service drain")
    c.facts[f"{fmt}_composition_offline_custody_and_original_recovery"] = True
