#!/usr/bin/env python3
"""Exercise prepare -> saved bundle -> canonical publication with the actual fg binary.

Each invocation opens the node in a fresh process. Candidate bytes must come
from workspace run; identities are checked independently. No Git engine or
replacement authority is used. This script requires a built Linux fg binary.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile

from workspace_tool_smoke import (
    AUTHOR, PRINCIPAL, REF, REPOSITORY, TENANT, commit, identity, inspect_bundle,
    invoke, require, tree, write_object,
)


def publication_args(node, path, base, candidate, key):
    return ["workspace", "apply", node, TENANT, REPOSITORY, REF, path,
            "--trusted-local", "--principal", PRINCIPAL, "--idempotency-key", key,
            "--expected-base", base, "--expected-commit", candidate]


def terminal(result, expected, base, candidate):
    receipt = json.loads(result.stdout)
    require(receipt["type"] == "workspace_publication", "must report a publication decision")
    require(receipt["outcome"] == expected, "wrong canonical terminal outcome")
    require(receipt["published_to_repository"] is (expected == "committed"), "wrong publication claim")
    require(receipt["node_closed"] is True and receipt["cleanup_error"] is None, "node did not close cleanly")
    require(receipt["expected_base"] == base and receipt["candidate_commit"] == candidate, "review binding drift")
    require(receipt["reference_hex"] == REF.encode().hex(), "branch binding drift")
    require(isinstance(receipt["decision_sequence"], int) and receipt["decision_sequence"] > 0, "missing decision sequence")
    require(isinstance(receipt["tx_id"], str) and receipt["tx_id"], "missing transaction identity")
    if expected == "committed":
        require(receipt["repository_commit_id"] and receipt["repository_commit_id"] != candidate,
                "RCR identity must not be confused with native commit identity")
        require(receipt["refusal_code"] is None and receipt["refusal_record_id"] is None, "commit claims refusal evidence")
    else:
        require(receipt["repository_commit_id"] is None and receipt["refusal_record_id"], "missing canonical refusal record")
        require(receipt["refusal_code"] == "ExpectedOldRefMismatch", "stale candidate must get the exact expected-old refusal")
    return receipt


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix=f"fg-workspace-publication-{algorithm}-") as temporary:
        root = Path(temporary)
        node, source, parent = root / "node", root / "source", root / "private"
        parent.mkdir(mode=0o700)
        (source / "refs/heads").mkdir(parents=True)
        (source / "HEAD").write_text(f"ref: {REF}\n")
        (source / "config").write_text(
            "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
            if algorithm == "sha256" else "[core]\nrepositoryformatversion = 0\nbare = true\n")
        original_blob = write_object(source, algorithm, "blob", b"before\n")
        keep = write_object(source, algorithm, "blob", b"preserved\n")
        original_tree = write_object(source, algorithm, "tree", tree([
            (b"100644", b"edit.txt", original_blob), (b"100644", b"keep.txt", keep)]))
        base = write_object(source, algorithm, "commit", commit(original_tree, None, 0, b"base\n"))
        (source / REF).write_text(base + "\n")
        environment = dict(os.environ)
        invoke(binary, ["init", node, TENANT, REPOSITORY, algorithm], environment)
        invoke(binary, ["import", node, TENANT, REPOSITORY, PRINCIPAL, "publication-source", source], environment)

        def state():
            # Include the authority head/decision summary, not only the ref tip:
            # a replay that emits a duplicate decision must fail this comparison.
            prefix = ["at", node, TENANT, REPOSITORY, "latest"]
            return (invoke(binary, prefix + ["refs"], environment).stdout,
                    invoke(binary, prefix, environment).stdout)

        def prepare(number, expected_parent, previous, content):
            name = f"candidate-{number}.bundle"
            slot = f"{number:032x}"
            tool = ("from pathlib import Path; "
                    f"assert Path('edit.txt').read_bytes() == {previous!r}; "
                    "assert not Path('keep.txt').exists(); "
                    f"Path('edit.txt').write_bytes({content!r})")
            args = ["workspace", "run", node, TENANT, REPOSITORY, REF, parent, slot, name,
                    "--trusted-local", "--read", "edit.txt", "--write", "edit.txt",
                    "--author", AUTHOR, "--timestamp", str(number), "--message", f"candidate {number}\n",
                    "--timeout-secs", "30", "--", sys.executable, "-c", tool]
            receipt = json.loads(invoke(binary, args, environment).stdout)
            require(receipt["published_to_repository"] is False, "preparation published unexpectedly")
            require(receipt["source_commit"] == expected_parent, "tool started from a different source")
            changed = identity(algorithm, "blob", content)
            tree_body = tree([(b"100644", b"edit.txt", changed), (b"100644", b"keep.txt", keep)])
            tree_id = identity(algorithm, "tree", tree_body)
            body = commit(tree_id, expected_parent, number, f"candidate {number}\n".encode())
            candidate = identity(algorithm, "commit", body)
            require(receipt["candidate_commit"] == candidate and receipt["root_tree"] == tree_id, "candidate bytes do not match independent derivation")
            path = parent / name
            objects = inspect_bundle(path.read_bytes(), algorithm, expected_parent, candidate)
            require(objects == {changed: ("blob", content), tree_id: ("tree", tree_body), candidate: ("commit", body)},
                    "sparse candidate lost unselected content or included unreviewed objects")
            require(not (parent / f"workspace-{slot}").exists(), "prepared workspace was not reaped")
            return candidate, path

        initial = state()
        winner, first = prepare(1, base, b"before\n", b"accepted\n")
        loser, second = prepare(2, base, b"before\n", b"competing\n")
        require(winner != loser and state() == initial, "preparation changed canonical state")
        first_args = publication_args(node, first, base, winner, "reviewed-winner")

        no_trust = first_args.copy()
        no_trust.remove("--trusted-local")
        invoke(binary, no_trust, environment, success=False)
        require(state() == initial, "missing trust opt-in changed authority")
        wrong = first_args.copy()
        wrong[-1] = loser
        invoke(binary, wrong, environment, success=False)
        require(state() == initial, "mismatched reviewed commit changed authority")
        corrupt = bytearray(first.read_bytes())
        corrupt[-1] ^= 1
        bad_path = parent / "corrupt.bundle"
        bad_path.write_bytes(corrupt)
        invoke(binary, publication_args(node, bad_path, base, winner, "bad-checksum"), environment, success=False)
        require(state() == initial, "corrupt pack changed authority")

        accepted = terminal(invoke(binary, first_args, environment), "committed", base, winner)
        after_winner = state()
        require(winner.encode() in after_winner[0] and after_winner != initial, "commit did not move the canonical branch")
        replay = terminal(invoke(binary, first_args, environment), "committed", base, winner)
        require(replay == accepted and state() == after_winner, "fresh-process retry published another decision")
        misuse = invoke(binary, publication_args(node, second, base, loser, "reviewed-winner"), environment, success=False)
        require(not misuse.stdout and b"IdempotencyKeyReuse" in misuse.stderr, "key misuse must not alias a terminal success")
        require(state() == after_winner, "key misuse changed authority")

        second_args = publication_args(node, second, base, loser, "reviewed-loser")
        refused = terminal(invoke(binary, second_args, environment, success=False), "refused", base, loser)
        require(refused["decision_sequence"] > accepted["decision_sequence"], "refusal must consume decision sequence")
        after_refusal = state()
        require(winner.encode() in after_refusal[0] and after_refusal[0] == after_winner[0], "stale candidate overwrote the winner")
        require(after_refusal[1] != after_winner[1], "canonical refusal was not published")
        refusal_replay = terminal(invoke(binary, second_args, environment, success=False), "refused", base, loser)
        require(refusal_replay == refused and state() == after_refusal, "refusal retry changed authority")

        # This tool reads the body actually published by the winner from a new
        # process, then creates and publishes a genuine next descendant.
        descendant, third = prepare(3, winner, b"accepted\n", b"next descendant\n")
        require(state() == after_refusal, "next candidate preparation changed state")
        third_args = publication_args(node, third, winner, descendant, "reviewed-descendant")
        next_result = terminal(invoke(binary, third_args, environment), "committed", winner, descendant)
        final = state()
        require(descendant.encode() in final[0], "descendant did not publish")
        require(next_result["decision_sequence"] > refused["decision_sequence"], "decision sequence did not advance")
        historical = invoke(binary, ["at", node, TENANT, REPOSITORY,
                            f"decision:{accepted['decision_sequence']}", "refs"], environment).stdout
        require(winner.encode() in historical and descendant.encode() not in historical, "historical authority lost the earlier commit")
        old_replay = terminal(invoke(binary, first_args, environment), "committed", base, winner)
        require(old_replay == accepted and state() == final, "old successful retry rolled back a newer descendant")
        return {"format": algorithm, "winner": winner, "descendant": descendant,
                "winner_tx_id": accepted["tx_id"], "stale_refusal": refused["refusal_code"],
                "fresh_process_replays": 3, "native_candidate_bytes_verified": True,
                "historical_ref_verified": True, "unchanged_objects_preserved": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path, help="actual freshly built fg binary")
    parser.add_argument("--format", choices=("sha1", "sha256", "both"), default="both")
    options = parser.parse_args()
    binary = options.fg.resolve(strict=True)
    require(sys.platform.startswith("linux"), "trusted workspace command profile is Linux-only")
    algorithms = ("sha1", "sha256") if options.format == "both" else (options.format,)
    results = [run_format(binary, algorithm) for algorithm in algorithms]
    print(json.dumps({"binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                      "results": results}, sort_keys=True))


if __name__ == "__main__":
    main()
