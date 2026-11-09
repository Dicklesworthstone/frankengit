#!/usr/bin/env python3
"""Fresh-process canonical HEAD publication, policy rotation and recovery."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, document, fixture, require


def run_format(binary, algorithm, layout):
    with tempfile.TemporaryDirectory(prefix="fg-default-branch-") as temporary:
        root = Path(temporary)
        node = root / "node"
        source = root / "source"
        objects = fixture(source, algorithm)
        main, topic, raw = b"refs/heads/main", b"refs/heads/topic", b"refs/heads/\xff"
        successor, stranger = "d4" * 16, "d5" * 16
        common = [node, TENANT, REPOSITORY]
        calls = 0

        def invoke(arguments, expected=0, stdin=None):
            nonlocal calls
            calls += 1
            result = subprocess.run(
                [str(binary), *map(str, arguments)], input=stdin,
                capture_output=True, timeout=120,
            )
            require(result.returncode == expected,
                    f"default-branch step {calls}: exit={result.returncode}, "
                    f"expected={expected}; stdout={result.stdout!r}; stderr={result.stderr!r}")
            if stdin is not None:
                require(stdin.rstrip(b"\n") not in result.stdout + result.stderr,
                        "private idempotency key leaked")
            return result

        def branch(action, *arguments):
            return ["branch", action, *common, "--trusted-local",
                    "--object-format", algorithm, *arguments]

        def read():
            report = document(invoke(branch("default")))
            require(report["type"] == "default_branch" and report["schema_version"] == 1,
                    "default read schema")
            require(report["read_only"] is True and report["node_closed"] is True,
                    "default read lifecycle")
            require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY
                    and report["object_format"] == algorithm, "default read domain")
            return report

        def refs():
            return document(invoke(branch("list")))["branches"]

        def command(old, new, tip, key, principal=PRINCIPAL, stdin=None):
            previous = ["--expect-no-default"] if old is None else ["--expected-default-hex", old.hex()]
            key_args = ["--key-stdin"] if stdin is not None else ["--idempotency-key", key]
            return branch("set-default", "--principal", principal, *key_args, *previous,
                          "--ref-hex", new.hex(), "--expected-tip", tip)

        def change(old, new, tip, key, expected=0, principal=PRINCIPAL, stdin=None):
            result = invoke(command(old, new, tip, key, principal, stdin), expected, stdin)
            if expected == 2:
                require(not result.stdout and json.loads(result.stderr)["type"] == "branch_error",
                        "nonterminal error invented a terminal receipt")
                return None
            report = document(result)
            require(report["type"] == "default_branch_publication"
                    and report["schema_version"] == 1 and report["action"] == "set-default",
                    "default publication schema")
            require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY
                    and report["principal_id"] == principal
                    and report["authentication"] == "operator-asserted"
                    and report["object_format"] == algorithm, "publication scope")
            require(report["expected_default_reference_hex"] == (None if old is None else old.hex())
                    and report["default_reference_hex"] == new.hex()
                    and report["expected_tip"] == tip, "original command identity")
            committed = expected == 0
            require(report["outcome"] == ("committed" if committed else "refused")
                    and report["command_committed"] is committed, "terminal classification")
            require(report["head_changed_by_transaction"] is (committed and old != new)
                    and report["direct_refs_changed"] is False, "HEAD/direct-ref effects")
            require(report["node_closed"] is True and report["cleanup_error"] is None
                    and report["delivery_acknowledged"] is None, "publication lifecycle")
            require(report["tx_id"].startswith("frankengit/ref-txn/v2/")
                    and type(report["decision_sequence"]) is int
                    and report["decision_sequence"] > 0, "ordinary transaction identity")
            if committed:
                require(report["repository_commit_id"].startswith("frankengit/rcr/v1/")
                        and report["refusal_code"] is None
                        and report["refusal_record_id"] is None, "committed evidence")
            else:
                require(report["repository_commit_id"] is None
                        and report["refusal_code"] is not None
                        and report["refusal_record_id"] is not None, "canonical refusal evidence")
            return report

        def configure(who, version, epoch, administrator):
            report = document(invoke([
                "protection", "set", *common, "--trusted-local", "--object-format", algorithm,
                "--principal", who, "--idempotency-key", f"default-policy-{version}",
                "--expected-version", version, "--expected-epoch", epoch,
                "--admin", administrator, "--clear",
            ]))
            require(report["committed"] is True and report["refs_changed"] is False,
                    "canonical administrator rotation")

        invoke(["init", *common, algorithm, "--root-layout", layout])
        unborn = read()
        require(unborn["default_reference_hex"] == main.hex()
                and unborn["tip"] is None and unborn["unborn"] is True,
                "unborn HEAD lost its exact target")
        invoke(["import", *common, PRINCIPAL, "default-import", source])
        imported = read()
        require(imported["default_reference_hex"] == main.hex()
                and imported["tip"] == objects["target"] and imported["unborn"] is False,
                "import did not resolve canonical HEAD")
        original_refs = refs()

        switched = change(main, topic, objects["source"], "default-main-topic")
        selected = read()
        require(selected["default_reference_hex"] == topic.hex()
                and selected["tip"] == objects["source"]
                and selected["source_head"] != imported["source_head"], "HEAD did not publish")
        require(refs() == original_refs, "HEAD selection changed direct refs")
        require(change(main, topic, objects["source"], "default-main-topic") == switched,
                "exact retry changed the original decision")
        require(read() == selected, "retry moved the authority head")
        change(main, main, objects["target"], "default-main-topic", expected=2)
        require(read() == selected, "changed semantics reused a sealed key")

        stale = change(main, main, objects["target"], "default-stale", expected=3)
        require(change(main, main, objects["target"], "default-stale", expected=3) == stale,
                "canonical refusal retry changed identity")
        change(None, main, objects["target"], "default-absent-mismatch", expected=3)
        change(topic, main, objects["base"], "default-tip-mismatch", expected=3)
        change(topic, b"refs/heads/missing", objects["base"], "default-missing", expected=3)
        require(read()["default_reference_hex"] == topic.hex() and refs() == original_refs,
                "refused expectation changed the selected target or refs")

        before = read()
        for action, extra in [
            ("delete", []),
            ("rename", ["--destination", "refs/heads/renamed-default"]),
        ]:
            invoke(branch(action, "--principal", PRINCIPAL, "--idempotency-key", f"deny-{action}",
                          "--ref-hex", topic.hex(), "--expected-tip", objects["source"], *extra), 2)
        require(read() == before, "deletion protection moved authority")
        invoke(branch("delete", "--principal", PRINCIPAL, "--idempotency-key", "delete-old-main",
                      "--ref-hex", main.hex(), "--expected-tip", objects["target"]))
        require(change(main, topic, objects["source"], "default-main-topic") == switched,
                "historical retry depended on the old branch still existing")
        no_op = change(topic, topic, objects["source"], "default-same-target")
        require(no_op["head_changed_by_transaction"] is False
                and no_op["repository_commit_id"] != switched["repository_commit_id"],
                "same-target request was not separately audited")

        invoke(branch("create", "--principal", PRINCIPAL, "--idempotency-key", "create-raw-default",
                      "--ref-hex", raw.hex(), "--target", objects["base"]))
        secret = b"private-default-key\n"
        raw_selection = change(topic, raw, objects["base"], None, stdin=secret)
        raw_read = read()
        require(raw_read["default_reference_hex"] == raw.hex()
                and raw_read["tip"] == objects["base"], "raw-byte target was normalized")
        recovered = document(invoke([
            "outcome", *common, "--trusted-local", "--principal", PRINCIPAL,
            "--object-format", algorithm, "--key-stdin",
        ], stdin=secret))
        require(recovered["state"] == "committed"
                and recovered["transaction"]["tx_id"] == raw_selection["tx_id"]
                and recovered["read_only"] is True
                and recovered["request_reexecuted"] is False, "read-only recovery mismatch")
        require(change(topic, raw, objects["base"], None, stdin=secret) == raw_selection
                and read() == raw_read, "stdin key bytes did not replay exactly")

        configure(PRINCIPAL, 0, 1, PRINCIPAL)
        change(raw, topic, objects["source"], "default-stranger", expected=3, principal=stranger)
        configure(PRINCIPAL, 1, 2, successor)
        change(raw, topic, objects["source"], "default-revoked-admin", expected=3)
        change(raw, topic, objects["source"], "default-successor", principal=successor)
        settled = read()
        require(change(topic, raw, objects["base"], None, stdin=secret) == raw_selection,
                "historical terminal retry was invalidated by administrator rotation")
        require(read() == settled, "historical retry reversed a newer HEAD selection")

        # Publication is already canonical when stdout fails. The diagnostic
        # retains that fact, and a fresh process recovers the original receipt.
        if Path("/dev/full").exists():
            arguments = command(topic, raw, objects["base"], "default-lost-receipt", successor)
            with Path("/dev/full").open("wb") as full:
                result = subprocess.run([str(binary), *map(str, arguments)],
                                        stdout=full, stderr=subprocess.PIPE, timeout=120)
            calls += 1
            require(result.returncode == 2, "failed output was reported as delivered")
            error = json.loads(result.stderr)
            require(error["type"] == "branch_error" and "is committed as" in error["error"],
                    "failed output discarded the known canonical decision")
            selected = read()
            replay = change(topic, raw, objects["base"], "default-lost-receipt", principal=successor)
            require(replay["tx_id"] in error["error"] and read() == selected,
                    "lost receipt recovery reexecuted the mutation")

        for action in ["default", "set-default"]:
            require(b"fg branch" in invoke(["branch", action, "--help"]).stdout, "missing help")
        print(f"DEFAULT_BRANCH format={algorithm} layout={layout} passed commands={calls}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    arguments = parser.parse_args()
    for algorithm, layout in [("sha1", "legacy"), ("sha256", "ref-merkle-v2")]:
        run_format(arguments.fg.resolve(), algorithm, layout)


if __name__ == "__main__":
    main()
