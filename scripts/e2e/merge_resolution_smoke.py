#!/usr/bin/env python3
"""Run real fg conflict resolution, inspection and publication; helpers are not Rust evidence."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import tempfile

from merge_preparation_smoke import (
    IDENTITY, PRINCIPAL, REPOSITORY, SOURCE, TARGET, TENANT, apply_args, commit,
    current_state, fixture, inspect_bundle, invoke, oid, require, synthetic_pack, tree,
)

MESSAGE = b"explicitly resolved merge\n"
PATH = b"dir/text"
CASES = [
    ("Ours", b"ONE\ntwo\nthree\nfour\nfive\n", 0o100755),
    ("Theirs", b"THEIRS\ntwo\nthree\nfour\nfive\n", 0o100644),
    ("Base", b"one\ntwo\nthree\nfour\nfive\n", 0o100644),
    ("Delete", None, None),
    ("File", b"manual resolution\r\nwithout final LF", 0o100755),
    ("File", b"", 0o100644),
    ("File", b"\x00\xffexact binary resolution\r\n", 0o100644),
]


def expected_objects(algorithm, history, content, mode):
    objects = {}

    def add(kind, body):
        identity = oid(algorithm, kind, body)
        if identity not in history["objects"]:
            objects[identity] = (kind, body)
        return identity

    result = None if content is None else {"mode": mode, "oid": add("blob", content)}
    # Removing the conflicted leaf retains its now-empty directory, as the
    # existing path merge planner does; it does not invent an rmdir intent.
    entries = [] if result is None else [(b"text", mode, result["oid"])]
    directory = add("tree", tree(entries))
    root = add("tree", tree([(b"dir", 0o40000, directory), (b"keep", 0o100644, history["kept"])]))
    candidate = add("commit", commit(root, [history["target"], history["source"]], MESSAGE))
    return candidate, root, result, objects


def args(node, output, history, choices):
    return ["merge", "resolve", node, TENANT, REPOSITORY, TARGET, output,
            "--trusted-local", "--profile", "path-v1", "--source-ref", SOURCE,
            "--expected-target", history["target"], "--expected-source", history["source"],
            "--merge-base", history["base"], "--author", IDENTITY,
            "--timestamp", "1", "--message", MESSAGE.decode(), *choices]


def check_report(report, bundle, algorithm, history, choice, content, mode):
    expected, root, result, objects = expected_objects(algorithm, history, content, mode)
    require(report["type"] == "merge_resolution" and report["schema_version"] == 1, "receipt schema")
    require(report["profile"] == "path-resolved-v1" and report["outcome"] == "prepared", "resolution profile")
    require(report["published_to_repository"] is False and report["node_closed"] is True, "publication/lifecycle")
    require(report["bundle_created"] is True and report["repository_id"] == REPOSITORY, "artifact/repository")
    require(report["source_head"] and report["object_format"] == algorithm, "authority/domain")
    for field, value in [("expected_target", history["target"]), ("expected_source", history["source"]),
                         ("merge_base", history["base"]), ("candidate_commit", expected), ("root_tree", root),
                         ("target_reference_hex", TARGET.encode().hex()), ("source_reference_hex", SOURCE.encode().hex())]:
        require(report[field] == value, field)
    require(report["bundle_sha256"] == hashlib.sha256(bundle).hexdigest(), "complete artifact hash")
    require(report["bundle_bytes"] == len(bundle) and report["object_count"] == len(objects), "artifact counts")
    require(report["resolution_count"] == 1 and len(report["resolutions"]) == 1, "conflict count")
    row = report["resolutions"][0]
    require(row["choice"] == choice and row["result"] == result, "exact resolution")
    conflict = row["conflict"]
    require(conflict["path_hex"] == PATH.hex() and conflict["kind"] == "Content", "actual conflict identity")
    for field, (_, data, original_mode) in zip(("ours", "theirs", "base"), CASES[:3]):
        require(conflict[field] == {"mode": original_mode, "oid": oid(algorithm, "blob", data)}, field)
    candidate, actual = inspect_bundle(bundle, algorithm, history["target"], history["source"])
    require(candidate == expected and actual == objects, "exact native candidate objects")
    return expected


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix=f"fg-resolve-{algorithm}-") as temporary:
        root = Path(temporary)
        source, node = root / "source", root / "node"
        history = fixture(source, algorithm, conflict=True)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm])
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "resolve-fixture", source])
        before = current_state(binary, node)
        prepared = []
        for index, (choice, content, mode) in enumerate(CASES):
            if choice == "File":
                local = root / f"resolution-{index}.bytes"
                local.write_bytes(content)
                choices = ["--file-hex", PATH.hex(), f"{mode:o}", local]
            else:
                choices = ["--" + choice.lower() + "-hex", PATH.hex()]
            output = root / f"candidate-{index}.bundle"
            command = args(node, output, history, choices)
            result = invoke(binary, command)
            report, data = json.loads(result.stdout), output.read_bytes()
            candidate = check_report(report, data, algorithm, history, choice, content, mode)
            inspection = json.loads(invoke(binary, ["merge", "inspect", node, TENANT, REPOSITORY, TARGET, output,
                "--trusted-local", "--source-ref", SOURCE, "--expected-source", history["source"],
                "--expected-target", history["target"], "--merge-base", history["base"], "--expected-commit", candidate]).stdout)
            require(inspection["review"]["requested_after"] == candidate, "inspection selected another result")
            require(current_state(binary, node) == before, "resolve or inspect changed authority")
            require(invoke(binary, command, success=False).returncode == 2, "existing destination must refuse")
            require(output.read_bytes() == data, "existing candidate was replaced")
            prepared.append((output, report, choices))
        repeated = root / "repeated.bundle"
        invoke(binary, args(node, repeated, history, prepared[4][2]))
        require(repeated.read_bytes() == prepared[4][0].read_bytes(), "non-deterministic resolved artifact")
        for index, choices in enumerate([
            ["--ours", "dir/text", "--theirs", "dir/text"], ["--ours", "keep"],
            ["--ours", "dir/absent"], ["--delete", "../outside"],
        ]):
            output = root / f"refused-{index}.bundle"
            require(invoke(binary, args(node, output, history, choices), success=False).returncode == 2, "negative exit class")
            require(not output.exists(), "invalid resolution left a candidate")
        for field, wrong in [("target", history["base"]), ("base", history["target"])]:
            changed = {**history, field: wrong}
            output = root / f"stale-{field}.bundle"
            require(invoke(binary, args(node, output, changed, prepared[0][2]), success=False).returncode == 2, "stale pins")
            require(not output.exists(), "stale resolution left a candidate")
        require(current_state(binary, node) == before, "refusal changed authority")
        output, report, choices = prepared[4]
        command = apply_args(node, output, report, "resolved-review", 17)
        terminal = json.loads(invoke(binary, command).stdout)
        require(terminal["outcome"] == "committed" and terminal["published_to_repository"] is True, "real publication")
        after = current_state(binary, node)
        require(report["candidate_commit"].encode() in after[0] and after != before, "published target")
        retry = json.loads(invoke(binary, command).stdout)
        for field in ("tx_id", "decision_sequence", "repository_commit_id"):
            require(terminal[field] == retry[field], "retry changed original terminal identity")
        require(current_state(binary, node) == after, "retry published a second decision")
        stale_output = root / "after-publication.bundle"
        require(invoke(binary, args(node, stale_output, history, choices), success=False).returncode == 2, "moved target")
        require(not stale_output.exists() and current_state(binary, node) == after, "stale recomputation mutated state")
        print(json.dumps({"type": "merge_resolution_smoke", "format": algorithm, "cases": len(CASES), "rust_executed": True}))


def self_test():
    rejected = 0
    for algorithm in ("sha1", "sha256"):
        with tempfile.TemporaryDirectory() as temporary:
            history = fixture(Path(temporary) / "source", algorithm, conflict=True)
            for choice, content, mode in CASES:
                candidate, root, result, objects = expected_objects(algorithm, history, content, mode)
                signature = "# v2 git bundle\n" if algorithm == "sha1" else "# v3 git bundle\n@object-format=sha256\n"
                header = (signature + f'-{history["target"]} target\n-{history["source"]} source\n{candidate} {TARGET}\n\n').encode()
                bundle = header + synthetic_pack(algorithm, [objects[key] for key in sorted(objects)])
                conflict = {"path_hex": PATH.hex(), "kind": "Content"}
                for field, (_, data, original_mode) in zip(("ours", "theirs", "base"), CASES[:3]):
                    conflict[field] = {"mode": original_mode, "oid": oid(algorithm, "blob", data)}
                report = {"type": "merge_resolution", "schema_version": 1, "profile": "path-resolved-v1", "outcome": "prepared",
                    "published_to_repository": False, "node_closed": True, "bundle_created": True, "repository_id": REPOSITORY,
                    "source_head": "fixture-only", "object_format": algorithm, "expected_target": history["target"],
                    "expected_source": history["source"], "merge_base": history["base"], "candidate_commit": candidate,
                    "root_tree": root, "target_reference_hex": TARGET.encode().hex(), "source_reference_hex": SOURCE.encode().hex(),
                    "bundle_sha256": hashlib.sha256(bundle).hexdigest(), "bundle_bytes": len(bundle), "object_count": len(objects),
                    "resolution_count": 1, "resolutions": [{"conflict": conflict, "choice": choice, "result": result}]}
                check_report(report, bundle, algorithm, history, choice, content, mode)
                for field, bad in [("candidate_commit", history["target"]), ("published_to_repository", True),
                                   ("bundle_sha256", "0" * 64), ("resolution_count", 0)]:
                    damaged = copy.deepcopy(report)
                    damaged[field] = bad
                    try:
                        check_report(damaged, bundle, algorithm, history, choice, content, mode)
                    except AssertionError:
                        rejected += 1
                    else:
                        raise AssertionError("checker accepted a damaged receipt")
    print(json.dumps({"type": "merge_resolution_checker", "rejected": rejected, "rust_executed": False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", type=Path)
    parser.add_argument("--self-test", action="store_true")
    options = parser.parse_args()
    if options.self_test:
        self_test()
        return
    if not options.fg:
        parser.error("--fg is required for the native campaign")
    binary = options.fg.resolve(strict=True)
    fingerprint = hashlib.sha256(binary.read_bytes()).hexdigest()
    for algorithm in ("sha1", "sha256"):
        run_format(binary, algorithm)
    require(hashlib.sha256(binary.read_bytes()).hexdigest() == fingerprint, "binary changed during campaign")
    print(json.dumps({"type": "merge_resolution_binary", "sha256": fingerprint, "rust_executed": True}))


if __name__ == "__main__":
    main()
