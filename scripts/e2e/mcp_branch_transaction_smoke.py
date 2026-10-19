#!/usr/bin/env python3
"""Real stdio MCP clients over one persisted native repository."""
import argparse
import json
import subprocess


def require(value, message):
    if not value:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["binary", "storage", "tenant", "repository", "principal", "incarnation", "format", "base", "tip"]:
        parser.add_argument("--" + name, required=True)
    a = parser.parse_args()
    tool = "frankengit_branch_transaction"
    calls = 0

    def invoke(requests, write=True, recovery=False):
        nonlocal calls
        calls += 1
        command = [a.binary, a.storage, a.tenant, a.repository, "--trusted-local", "--object-format", a.format,
                   "--expected-incarnation", a.incarnation, "--max-messages", "32"]
        if write:
            command += ["--allow-source-writes"]
        if recovery:
            command += ["--allow-outcomes"]
        if write or recovery:
            command += ["--principal", a.principal]
        else:
            command += ["--allow-source"]
        messages = [dict(jsonrpc="2.0", id=1, method="initialize", params=dict(
            protocolVersion="2025-06-18", capabilities={}, clientInfo=dict(name="atomic-branch-test", version="1"))),
            dict(jsonrpc="2.0", method="notifications/initialized")]
        messages += [dict(jsonrpc="2.0", id=i + 2, method=method, params=params)
                     for i, (method, params) in enumerate(requests)]
        result = subprocess.run(command, input="".join(json.dumps(m, separators=(",", ":")) + "\n" for m in messages),
                                capture_output=True, text=True, timeout=120)
        require(result.returncode == 0, f"MCP process {calls} failed: {result.stderr}; {result.stdout}")
        responses = [json.loads(line) for line in result.stdout.splitlines()]
        require(len(responses) == len(requests) + 1, f"missing responses: {responses}")
        require([v["id"] for v in responses] == list(range(1, len(requests) + 2)), "RPC response identity mismatch")
        return responses[1:]

    def call(key, commands):
        return "tools/call", dict(name=tool, arguments=dict(idempotency_key=key, commands=commands))

    def content(response, committed=True):
        require("result" in response, f"not a tool result: {response}")
        result = response["result"]
        require(result.get("isError", False) is (not committed), f"wrong tool outcome: {response}")
        structured = result["structuredContent"]
        require(structured["atomic"] is True and structured["complete"] is True, "incomplete atomic result")
        require(structured["ref_transaction_committed"] is committed, "wrong canonical outcome")
        require(structured["current_refs_asserted"] is False, "historical outcome presented as current refs")
        require(structured["action"] == "transaction", "wrong operation")
        return structured

    create = lambda name, tip: dict(action="create", reference=name, target=tip)
    setup = [create("refs/heads/a", a.base), create("refs/heads/b", a.base)]
    changes = [dict(action="update", reference="refs/heads/a", expected_old=a.base, target=a.tip),
               dict(action="delete", reference="refs/heads/b", expected_old=a.base),
               dict(action="create", reference_hex=b"refs/heads/raw-\xff".hex(), target=a.tip)]
    responses = invoke([("tools/list", {}), call("seed", setup), call("mixed", changes)])
    names = {t["name"] for t in responses[0]["result"]["tools"]}
    require(tool in names, "transaction tool missing from discovery")
    require("frankengit_transaction_outcome" not in names, "write grant widened to recovery")
    require(not {"frankengit_source_blob", "frankengit_source_tree"} & names, "write grant widened to source read")
    content(responses[1])
    committed = content(responses[2])
    require(len(committed["submitted_commands"]) == 3, "partial command receipt")
    replay = content(invoke([call("mixed", list(reversed(changes)))])[0])
    require(replay["tx_id"] == committed["tx_id"] and replay["decision_sequence"] == committed["decision_sequence"],
            "reordered restart replay created a new decision")
    stale = [dict(action="delete", reference="refs/heads/a", expected_old=a.base), create("refs/heads/no-prefix", a.tip)]
    refused = content(invoke([call("stale", stale)])[0], False)
    repeat = content(invoke([call("stale", stale)])[0], False)
    require(repeat["tx_id"] == refused["tx_id"], "refusal did not survive restart")
    changed = invoke([call("mixed", [create("refs/heads/key-reuse", a.tip)])])[0]
    require("error" in changed or changed.get("result", {}).get("isError") is True, "changed key semantics admitted")
    denied = invoke([("tools/list", {}), call("not-granted", [create("refs/heads/forbidden", a.tip)])], write=False)
    require(tool not in {t["name"] for t in denied[0]["result"]["tools"]}, "read grant exposed transaction")
    require("error" in denied[1] or denied[1].get("result", {}).get("isError") is True, "read grant mutated refs")
    recovery = invoke([("tools/call", dict(name="frankengit_transaction_outcome", arguments=dict(idempotency_key="mixed")))],
                      write=False, recovery=True)[0]["result"]["structuredContent"]
    require(recovery["tx_id"] == committed["tx_id"] and recovery["repository_changed"] is False,
            "original-key recovery changed transaction scope")
    require(recovery["complete"] is True, "terminal recovery incomplete")
    print(f"MCP_BRANCH_TRANSACTION format={a.format} passed processes={calls}")


if __name__ == "__main__":
    main()
