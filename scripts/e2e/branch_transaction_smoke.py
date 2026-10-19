#!/usr/bin/env python3
"""Real native multi-branch transactions, with independent object fixtures."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, fixture, document, require


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-branch-transaction-") as temporary:
        root = Path(temporary)
        node = root / "node"
        source = root / "source"
        f = fixture(source, algorithm)
        calls = 0

        def invoke(args, code=0, stdin=None):
            nonlocal calls
            calls += 1
            env = dict(os.environ, PATH=str(root / "no-programs"), HOME=str(root))
            result = subprocess.run([str(binary), *map(str, args)], input=stdin, capture_output=True,
                                    env=env, timeout=120)
            require(result.returncode == code,
                    f"step {calls}: wanted {code}, got {result.returncode}: {result.stdout!r} {result.stderr!r}")
            return result

        invoke(["init", node, TENANT, REPOSITORY, algorithm])
        invoke(["import", node, TENANT, REPOSITORY, PRINCIPAL, "transaction-fixture", source])

        def listing():
            return document(invoke(["branch", "list", node, TENANT, REPOSITORY, "--trusted-local",
                                    "--object-format", algorithm, "--limit", "100"]))

        def transact(key, operations, code=0, stdin=None):
            keys = ["--key-stdin"] if stdin is not None else ["--idempotency-key", key]
            result = invoke(["branch", "transaction", node, TENANT, REPOSITORY, "--trusted-local",
                             "--principal", PRINCIPAL, "--object-format", algorithm, *keys, *operations], code, stdin)
            if code == 2:
                require(not result.stdout, "invalid request returned a terminal receipt")
                require(json.loads(result.stderr)["type"] == "branch_error", "wrong error surface")
                return None
            report = document(result)
            require(report["type"] == "branch_publication" and report["action"] == "transaction", "transaction receipt")
            require(report["atomic"] is True and report["command_committed"] is (code == 0), "atomic outcome")
            require(report["node_closed"] is True and report["cleanup_error"] is None, "owned shutdown")
            require(report["outcome"] == ("committed" if code == 0 else "refused"), "terminal classification")
            if stdin is not None:
                require(stdin.rstrip(b"\n") not in result.stdout + result.stderr, "private key leaked")
            return report

        a, b, c = "refs/heads/atomic-a", "refs/heads/atomic-b", "refs/heads/atomic-c"
        initial = listing()
        created = transact("create-batch", ["--create", a, f["base"], "--create", b, f["base"]])
        require(len(created["commands"]) == 2, "two independent creations")
        operations = ["--update", a, f["base"], f["target"], "--delete", b, f["base"], "--create", c, f["target"]]
        changed = transact("mixed-batch", operations)
        require(len(changed["commands"]) == 3, "mixed batch cardinality")
        require(changed["decision_sequence"] == created["decision_sequence"] + 1, "one decision per transaction")
        after = listing()
        rows = {bytes.fromhex(row["reference_hex"]).decode(): row["tip"] for row in after["branches"]}
        require(rows[a] == f["target"] and b not in rows and rows[c] == f["target"], "atomic net effect")
        require(rows["refs/heads/main"] == f["target"] and rows["refs/heads/topic"] == f["source"], "unrelated refs changed")
        require(transact("mixed-batch", operations) == changed, "exact retry across processes")
        reordered = transact("mixed-batch", ["--create", c, f["target"], "--delete", b, f["base"],
                                            "--update", a, f["base"], f["target"]])
        require(reordered["tx_id"] == changed["tx_id"] and reordered["repository_commit_id"] == changed["repository_commit_id"],
                "canonical command order changed identity")
        require(listing() == after, "retry republished")
        transact("mixed-batch", ["--create", "refs/heads/different", f["base"]], code=2)
        require(listing() == after, "changed sealed request changed authority")

        stale = ["--delete", a, f["base"], "--create", "refs/heads/no-prefix", f["base"], "--delete", c, f["target"]]
        denied = transact("stale-batch", stale, code=3)
        require(all(row["reference_hex"] for row in denied["commands"]), "refusal omitted exact commands")
        require(listing()["branches"] == after["branches"], "stale branch partially committed")
        refused_head = listing()
        require(transact("stale-batch", stale, code=3) == denied, "refused retry changed outcome")
        require(listing() == refused_head, "refused retry changed head")
        transact("default-guard", ["--create", "refs/heads/no-default", f["base"],
                                   "--delete", "refs/heads/main", f["target"]], code=2)
        transact("blob-guard", ["--create", "refs/heads/no-blob", f["base"], "--create", "refs/heads/blob", f["blob"]], code=2)
        transact("nonff-guard", ["--create", "refs/heads/no-rewind", f["base"], "--update", a, f["target"], f["base"]], code=2)
        require(listing() == refused_head, "pre-admission guard published another member")

        raw = b"refs/heads/raw-\xff"
        secret = b"private-transaction-key\n"
        exact = ["--create-hex", raw.hex(), f["base"], "--create", "refs/heads/second", f["base"]]
        result = transact(None, exact, stdin=secret)
        require(result["commands"][0]["reference_hex"] == raw.hex(), "non-UTF8 reference lost")
        source.rename(root / "source-offline")
        require(transact(None, exact, stdin=secret) == result, "retry required offline import source")
        recovered = document(invoke(["outcome", node, TENANT, REPOSITORY, "--trusted-local", "--principal", PRINCIPAL,
                                     "--object-format", algorithm, "--key-stdin"], stdin=secret))
        require(recovered["state"] == "committed" and recovered["transaction"]["tx_id"] == result["tx_id"], "read-only recovery")
        require(recovered["read_only"] is True and recovered["request_reexecuted"] is False, "recovery repeated work")
        require(b"transaction" in invoke(["branch", "transaction", "--help"]).stdout, "missing help")
        print(f"BRANCH_TRANSACTION format={algorithm} passed commands={calls}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", type=Path, required=True)
    args = parser.parse_args()
    for algorithm in ["sha1", "sha256"]:
        run_format(args.fg.resolve(), algorithm)


if __name__ == "__main__":
    main()
