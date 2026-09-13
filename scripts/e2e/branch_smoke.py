#!/usr/bin/env python3
"""Fresh-process native branch lifecycle; no production Git or mock authority."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
from pull_request_smoke import TENANT, REPOSITORY, PRINCIPAL, fixture, document, require


def run_format(binary, algorithm):
    with tempfile.TemporaryDirectory(prefix="fg-branch-cli-") as temporary:
        root = Path(temporary)
        node = root / "node"
        f = fixture(root / "source", algorithm)
        calls = 0

        def invoke(args, code=0, stdin=None):
            nonlocal calls
            calls += 1
            result = subprocess.run([str(binary), *map(str, args)], input=stdin, capture_output=True, timeout=120)
            require(result.returncode == code, f"branch campaign step {calls}: exit {result.returncode}, wanted {code}: {result.stderr!r}; {result.stdout!r}")
            return result

        invoke(["init", node, TENANT, REPOSITORY, algorithm])
        invoke(["import", node, TENANT, REPOSITORY, PRINCIPAL, "branch-import", root / "source"])

        def args(action, *extra):
            return ["branch", action, node, TENANT, REPOSITORY, "--trusted-local", "--object-format", algorithm, *extra]

        def listing(*extra):
            report = document(invoke(args("list", *extra)))
            require(report["type"] == "branch_page" and report["schema_version"] == 1, "page schema")
            require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "page identity")
            require(report["object_format"] == algorithm and report["node_closed"] is True, "page domain/close")
            names = [bytes.fromhex(row["reference_hex"]) for row in report["branches"]]
            require(names == sorted(set(names)) and all(n.startswith(b"refs/heads/") for n in names), "ordered byte-safe branches")
            require(report["has_more"] is (report["next_after_hex"] is not None), "continuation presence")
            return report

        def mutation(action, name, key, *extra, code=0, stdin=None):
            key_args = ["--key-stdin"] if stdin is not None else ["--idempotency-key", key]
            result = invoke(args(action, "--principal", PRINCIPAL, *key_args, "--ref-hex", name.hex(), *extra), code, stdin)
            if code == 2:
                require(not result.stdout, "nonterminal error emitted a terminal result")
                error = json.loads(result.stderr)
                require(error["type"] == "branch_error", "structured error")
                return error
            report = document(result)
            require(report["type"] == "branch_publication" and report["schema_version"] == 1, "mutation schema")
            require(report["action"] == action and report["atomic"] is True, "atomic action")
            require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY, "mutation repository")
            require(report["principal_id"] == PRINCIPAL and report["object_format"] == algorithm, "mutation principal/domain")
            require(report["command_committed"] is (code == 0), "committed flag")
            require(report["outcome"] == ("committed" if code == 0 else "refused"), "terminal classification")
            require(report["node_closed"] is True and report["cleanup_error"] is None, "explicit close")
            require(report["delivery_acknowledged"] is None, "no invented delivery acknowledgement")
            require(type(report["decision_sequence"]) is int and report["decision_sequence"] > 0, "decision sequence")
            require(len(report["commands"]) == (2 if action == "rename" else 1), "atomic command cardinality")
            require(report["commands"][0]["reference_hex"] == name.hex(), "original command identity")
            require(report["tx_id"].startswith("frankengit/ref-txn/v2/"), "transaction identity")
            if code == 0:
                require(report["repository_commit_id"].startswith("frankengit/rcr/v1/") and report["refusal_code"] is None, "committed record")
            else:
                require(report["repository_commit_id"] is None and report["refusal_code"] is not None and report["refusal_record_id"] is not None, "canonical refusal")
            if stdin is not None:
                require(stdin.rstrip(b"\n") not in result.stdout + result.stderr, "private stdin key leaked")
            return report

        initial = listing()
        require([bytes.fromhex(r["reference_hex"]) for r in initial["branches"]] == [b"refs/heads/main", b"refs/heads/topic"], "imported refs")
        work, ready = b"refs/heads/work", b"refs/heads/ready"
        created = mutation("create", work, "create-work", "--target", f["base"])
        advanced = mutation("update", work, "advance-work", "--expected-tip", f["base"], "--target", f["target"])
        renamed = mutation("rename", work, "rename-work", "--expected-tip", f["target"], "--destination-hex", ready.hex())
        rows = {bytes.fromhex(r["reference_hex"]): r["tip"] for r in listing()["branches"]}
        require(work not in rows and rows[ready] == f["target"], "atomic source removal/destination creation")
        removed = mutation("delete", ready, "delete-ready", "--expected-tip", f["target"])
        settled = listing()
        require(mutation("create", work, "create-work", "--target", f["base"]) == created, "create replay after deletion")
        require(mutation("update", work, "advance-work", "--expected-tip", f["base"], "--target", f["target"]) == advanced, "update replay after deletion")
        require(mutation("rename", work, "rename-work", "--expected-tip", f["target"], "--destination-hex", ready.hex()) == renamed, "rename replay after deletion")
        require(mutation("delete", ready, "delete-ready", "--expected-tip", f["target"]) == removed, "delete replay")
        require(listing() == settled, "replays moved authority")
        mutation("create", b"refs/heads/changed", "create-work", "--target", f["base"], code=2)
        require(listing() == settled, "changed sealed request changed authority")

        mutation("create", work, "recreate-work", "--target", f["base"])
        before = listing()["branches"]
        occupied = mutation("rename", work, "occupied", "--expected-tip", f["base"], "--destination", "refs/heads/topic", code=3)
        require(listing()["branches"] == before, "occupied destination partially renamed source")
        require(mutation("rename", work, "occupied", "--expected-tip", f["base"], "--destination", "refs/heads/topic", code=3) == occupied, "refused replay")
        mutation("rename", work, "stale", "--expected-tip", f["target"], "--destination-hex", ready.hex(), code=3)
        require(listing()["branches"] == before, "stale source partially created destination")
        before = listing()
        mutation("delete", b"refs/heads/main", "delete-default", "--expected-tip", f["target"], code=2)
        mutation("rename", b"refs/heads/main", "rename-default", "--expected-tip", f["target"], "--destination-hex", ready.hex(), code=2)
        mutation("create", b"refs/heads/blob", "blob", "--target", f["blob"], code=2)
        require(listing() == before, "early branch validation changed authority")

        non_utf8 = b"refs/heads/\xff"
        secret = b"private-branch-key\n"
        private = mutation("create", non_utf8, None, "--target", f["base"], stdin=secret)
        pinned = listing()
        require(mutation("create", non_utf8, None, "--target", f["base"], stdin=secret) == private, "stdin exact replay")
        recovered = document(invoke(["outcome", node, TENANT, REPOSITORY, "--trusted-local", "--principal", PRINCIPAL,
                                     "--object-format", algorithm, "--key-stdin"], stdin=secret))
        require(recovered["state"] == "committed" and recovered["transaction"]["tx_id"] == private["tx_id"], "read-only key recovery")
        require(recovered["read_only"] is True and recovered["request_reexecuted"] is False, "recovery reexecuted mutation")
        require(listing() == pinned, "key recovery changed authority")
        first = listing("--limit", "1")
        tail = listing("--after-hex", first["next_after_hex"], "--expected-head", first["snapshot_token"], "--limit", "100")
        require(first["branches"] + tail["branches"] == pinned["branches"], "paged listing dropped/repeated branches")
        require(tail["source_head"] == pinned["source_head"] and tail["has_more"] is False, "mixed page source")
        invoke(args("list", "--after-hex", first["next_after_hex"]), 2)
        mutation("create", b"refs/heads/another", "move-page", "--target", f["base"])
        invoke(args("list", "--after-hex", first["next_after_hex"], "--expected-head", first["snapshot_token"]), 2)
        for action in ["list", "create", "update", "delete", "rename"]:
            require(b"fg branch" in invoke(["branch", action, "--help"]).stdout, "help omitted branch usage")
        print(f"BRANCH_LIFECYCLE format={algorithm} passed commands={calls}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    args = parser.parse_args()
    for algorithm in ["sha1", "sha256"]:
        run_format(args.fg.resolve(), algorithm)


if __name__ == "__main__":
    main()
