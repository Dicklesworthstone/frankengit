"""Resolve real native conflicts and publish independently reviewed exact bytes.

Consumed by operator_pull_smoke, under its existing deadline and owned service
drain. Python constructs the expected Git objects; pinned sandboxed Git verifies
fixture/bundle integrity. Neither supplies production merge behavior.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from merge_preparation_smoke import IDENTITY, SOURCE, TARGET, fixture, inspect_bundle
from merge_resolution_smoke import MESSAGE, PATH, expected_objects
from operator_issue_smoke import OperatorCampaign
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
REVIEWER, MERGER, READER = "44" * 16, "55" * 16, "66" * 16
CONTENT = b"\x00\xffoperator-resolved binary\r\nwithout final LF"
MODE = 0o100755


def run_resolution_case(campaign: OperatorCampaign, oracle_run: Path, fmt: str, method: str) -> None:
    label = f"{fmt}-{method}-resolution"
    directory = campaign.work / label
    directory.mkdir(mode=0o700)
    source, root = directory / "source", directory / "repository"
    history = fixture(source, fmt, conflict=True)
    expected_commit, expected_tree, expected_file, objects = expected_objects(fmt, history, CONTENT, MODE, method)

    def oracle(name: str, *arguments: str) -> None:
        command = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle_run),
                   str(source.relative_to(oracle_run / "work")), label + "-" + name, "--", *arguments]
        stem = directory / ("oracle-" + name)
        with stem.with_suffix(".stdout").open("wb") as out, stem.with_suffix(".stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
        campaign.record(kind="pinned_git_resolution_check", command=command, exit=result.returncode, artifacts=str(stem))
        if result.returncode:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
        require(result.returncode == 0, "pinned Git rejected native conflict fixture or resolved bundle")

    oracle("fsck", "fsck", "--full", "--strict", "--no-reflogs")
    campaign.run("init", root, TENANT, REPOSITORY, fmt)
    campaign.run("import", root, TENANT, REPOSITORY, PRINCIPAL, "resolution-import", source)
    opened = json.loads(campaign.run("pr", "open", root, TENANT, REPOSITORY, "1", "--trusted-local",
        "--principal", PRINCIPAL, "--idempotency-key", "resolution-open", "--expected-version", "0",
        "--source-ref", SOURCE, "--target-ref", TARGET, "--expected-source", history["source"],
        "--expected-target", history["target"], "--title", "Resolve exact binary bytes", "--body", method))
    require(opened["outcome"] == "committed" and opened["node_closed"] is True, "native conflict PR did not open")
    credentials, incarnation = campaign.credentials(root, directory)
    header = credentials.read_text().splitlines()[0]
    tokens = {READER: "a" * 64, REVIEWER: "e" * 64, MERGER: "f" * 64}
    scopes = {READER: "read,pulls-read,reviews-read", REVIEWER: "outcomes-read,reviews-write",
              MERGER: "outcomes-read,merges-write"}
    token_paths = {}
    lines = [header]
    for principal, token in tokens.items():
        path = directory / ("token-" + principal)
        path.write_text(token)
        token_paths[principal] = path
        lines.append(f"{hashlib.sha256(token.encode()).hexdigest()} {principal} {scopes[principal]}")
    credentials.write_text("\n".join(lines) + "\n")
    server = HttpServer(campaign, root, credentials, label)
    server.command.extend(["--allow-outcomes", "--allow-source"])

    def native(verb: str, *arguments: str) -> dict[str, Any]:
        return json.loads(campaign.run(verb, root, TENANT, REPOSITORY, "--trusted-local",
                                      "--object-format", fmt, *arguments))

    def pr() -> dict[str, Any]:
        report = json.loads(campaign.run("pr", "show", root, TENANT, REPOSITORY, "1",
                                        "--trusted-local", "--object-format", fmt))
        require(report["found"] is True and report["node_closed"] is True, "native resolved PR read incomplete")
        return report["pull_request"]

    def refs() -> dict[str, str]:
        page = native("refs")
        require(page["node_closed"] is True and page["has_more"] is False and page["next_after_hex"] is None,
                "native ref read is incomplete or did not close")
        rows = page["references"]
        names = [bytes.fromhex(row["reference_hex"]).decode() for row in rows]
        require(names == sorted(names) and len(names) == len(set(names)), "native refs are unordered or duplicated")
        return dict(zip(names, (row["tip"] for row in rows)))

    candidate_script, sender = ROOT / "scripts/fg_pull_candidate.mjs", ROOT / "scripts/remote_pull.mjs"
    before = campaign.run("at", root, TENANT, REPOSITORY, "latest")
    initial_pr, initial_refs = pr(), refs()
    require(initial_refs == {TARGET: history["target"], SOURCE: history["source"]},
            "imported refs differ from the independently constructed conflict fixture")
    with server:
        selection = {"endpoint": server.url, "scope": {"tenant_id": TENANT, "repository_id": REPOSITORY,
            "repository_incarnation": incarnation, "object_format": fmt}, "number": "1", "expected_head": None,
            "method": method, "metadata": {"author": IDENTITY, "committer": IDENTITY, "timestamp": "1",
                                            "message": MESSAGE.decode()}}
        input_path = directory / "selection.json"
        input_path.write_text(json.dumps(selection))
        conflict = directory / "conflict"
        saved = campaign.node_command(candidate_script, ["capture", "--input", str(input_path), "--token-file",
            str(token_paths[READER]), "--output-dir", str(conflict)], 1)
        require(saved["state"] == "conflicted" and saved["published"] is False
                and not (conflict / "candidate.bundle").exists(), "a conflict was treated as a clean candidate")
        original_files = {p.name: p.read_bytes() for p in conflict.iterdir()}
        snapshot = campaign.node_command(candidate_script, ["inspect", "--package", str(conflict), "--sha256", saved["sha256"]])
        report = snapshot["capture"]["preparation"]
        require(report["method"] == method and len(report["conflicts"]) == 1
                and report["conflicts"][0]["path_hex"] == PATH.hex(), "native conflict coordinates differ")
        invalid = directory / "invalid-choices.json"
        invalid.write_text(json.dumps([{"path_hex": b"keep".hex(), "choice": "ours"}]))
        refused = campaign.node_command(candidate_script, ["resolve", "--package", str(conflict), "--sha256", saved["sha256"],
            "--choices", str(invalid), "--token-file", str(token_paths[READER]), "--output-dir", str(directory / "invalid")],
            3, error_reply=True)
        require(refused["published"] is False and not (directory / "invalid").exists(), "invalid choices published a result")
        choices = directory / "choices.json"
        choices.write_text(json.dumps([{"path_hex": PATH.hex(), "choice": "file", "mode": "100755", "content_hex": CONTENT.hex()}]))
        # Resolving constructs a candidate through native read authority. It is
        # not authorized by review/publication grants or the saved local package.
        original_credentials = credentials.read_text()
        denied_credentials = original_credentials.replace(f"{READER} read,pulls-read,reviews-read",
                                                           f"{READER} pulls-read,reviews-read")
        require(denied_credentials != original_credentials, "source-read grant control did not alter its selected credential")
        pending = directory / "credentials.next"
        pending.write_text(denied_credentials)
        pending.replace(credentials)
        denied = campaign.node_command(candidate_script, ["resolve", "--package", str(conflict), "--sha256", saved["sha256"],
            "--choices", str(choices), "--token-file", str(token_paths[READER]), "--output-dir", str(directory / "denied")],
            3, error_reply=True)
        require(denied["status"] == 403 and denied["published"] is False and not (directory / "denied").exists()
                and campaign.run("at", root, TENANT, REPOSITORY, "latest") == before,
                "resolution without source-read grant published a result or repository state")
        pending.write_text(original_credentials)
        pending.replace(credentials)
        resolved = directory / "resolved"
        receipt = campaign.node_command(candidate_script, ["resolve", "--package", str(conflict), "--sha256", saved["sha256"],
            "--choices", str(choices), "--token-file", str(token_paths[READER]), "--output-dir", str(resolved)])
        require(receipt["state"] == "resolved" and receipt["published"] is False
                and receipt["sha256"] == file_sha256(resolved / "manifest.json"), "resolved package lost its independent pin")
        inspected = campaign.node_command(candidate_script, ["inspect", "--package", str(resolved), "--sha256", receipt["sha256"]])
        capture = inspected["capture"]
        require(capture["preparation"]["candidate"]["commit"] == expected_commit
                and capture["inspection"]["candidate_commit"] == expected_commit
                and capture["inspection"]["candidate_commit_body_hex"] == objects[expected_commit][1].hex()
                and capture["pull"]["snapshot_token"] == snapshot["capture"]["pull"]["snapshot_token"],
                "resolved candidate commit, parents, metadata or source snapshot differ")
        actual_commit, actual_objects = inspect_bundle((resolved / "candidate.bundle").read_bytes(), fmt, history["target"], history["source"])
        require(actual_commit == expected_commit and actual_objects == objects, "native resolved objects differ from exact independent bytes")
        oracle("bundle", "bundle", "verify", "../resolved/candidate.bundle")
        require(original_files == {p.name: p.read_bytes() for p in conflict.iterdir()}
                and campaign.run("at", root, TENANT, REPOSITORY, "latest") == before,
                "resolution rewrote the conflict package or published repository state")
        campaign.facts[f"{fmt}_{method}_resolution_read_grant"] = True
        campaign.facts[f"{fmt}_{method}_conflict_resolution"] = True

        def stage(name: str, action: str) -> tuple[Path, str]:
            choice = {"action": action, "principal_id": MERGER if action == "merge" else REVIEWER,
                      "candidate_commit": expected_commit}
            choice.update({"method": method, "required_reviewers": [REVIEWER]} if action == "merge" else
                          {"reason": "Inspected exact resolved binary bytes and mode"})
            path = directory / (name + "-choice.json")
            path.write_text(json.dumps(choice))
            slot = directory / (name + ".slot")
            staged = campaign.node_command(candidate_script, ["stage", "--package", str(resolved), "--sha256", receipt["sha256"],
                "--choices", str(path), "--token-file", str(token_paths[choice["principal_id"]]), "--request-dir", str(slot)])
            require(staged["publication_attempted"] is False and staged["published"] is False
                    and (slot / "candidate.bundle").read_bytes() == (resolved / "candidate.bundle").read_bytes(),
                    "staging changed candidate bytes or claimed repository publication")
            return slot, staged["key"]

        def publish(name: str, action: str, expected: int = 0) -> dict[str, Any]:
            principal = MERGER if action == "merge" else REVIEWER
            slot, key = stage(name, action)
            first = directory / (name + "-send.record")
            options = ["--request-dir", str(slot), "--token-file", str(token_paths[principal])]
            consent = ["--confirm-key", key, "--confirm-candidate", expected_commit,
                       *(["--confirm-merge-method", method] if action == "merge" else [])]
            sent = campaign.node_command(sender, ["send", *options, *consent, "--record", str(first)], expected)
            require(sent["outcome"]["state"] == ("refused" if expected else "committed"), "resolved request lost its native terminal")
            for operation in ("recover", "send"):
                result = campaign.node_command(sender, [operation, *options,
                    *(consent + ["--known", str(first)] if operation == "send" else []),
                    "--record", str(directory / (name + "-" + operation + "-retry.record"))], expected)
                require(result["dispatched"] is False and result["outcome"] == sent["outcome"],
                        "resolved recovery/replay changed the decision or dispatched again")
            return sent

        publish("unapproved", "merge", 1)
        require(pr() == initial_pr and refs() == initial_refs, "missing approval changed the PR or refs")
        publish("approval", "approve")
        reviews = json.loads(campaign.run("pr", "reviews", root, TENANT, REPOSITORY, "1",
                                          "--trusted-local", "--object-format", fmt))
        require(reviews["node_closed"] is True and len(reviews["reviews"]) == 1
                and reviews["reviews"][0]["reviewer"] == REVIEWER
                and reviews["reviews"][0]["candidate_commit"] == expected_commit
                and reviews["reviews"][0]["reviewer_is_opener"] is False and refs() == initial_refs,
                "review lost the exact independent candidate or moved code")
        published = publish("reviewed-publication", "merge")
        require(published["publication"]["method"] == method
                and published["publication"]["principal_id"] == MERGER
                and refs() == {**initial_refs, TARGET: expected_commit} and pr()["state"] == "merged",
                "reviewed publication substituted method, actor, candidate or a different ref")
        file = native("show", "--ref", TARGET, "--path-hex", PATH.hex(), "--expected-commit", expected_commit)
        sibling = native("show", "--ref", TARGET, "--path", "keep", "--expected-commit", expected_commit)
        require(file["node_closed"] is True and file["bytes_hex"] == CONTENT.hex() and file["kind"] == "executable"
                and file["object_id"] == expected_file["oid"] and file["root_tree"] == expected_tree
                and file["source_commit"] == expected_commit and sibling["bytes_hex"] == b"unchanged sibling\n".hex(),
                "canonical resolved binary bytes, executable mode, sibling or native identities differ")
        campaign.facts[f"{fmt}_{method}_exact_reviewed_result"] = True
    campaign.facts[f"{fmt}_{method}_resolution_service_drained"] = True
    print(f"OPERATOR_RESOLUTION {fmt} {method}: exact binary candidate, independent review, publication and drain", flush=True)
