#!/usr/bin/env python3
"""Exercise split write and recovery grants against a prebuilt native node."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
from urllib.parse import urlsplit

from operator_issue_smoke import OperatorCampaign
from pull_request_smoke import fixture
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, require

CLI = Path(__file__).resolve().parents[1] / "fg_branch_transaction.mjs"
OTHER = "44" * 16
UA = "frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)"
DELETE, UPDATE, RAW = (name.hex() for name in
                        (b"refs/heads/obsolete", b"refs/heads/update", b"refs/heads/raw-\xff"))


def write_private(path, text):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600),
                   "w", encoding="utf-8") as output:
        output.write(text)
    return path


def native_request(campaign, server, name, endpoint, token_file, key, body=None):
    parsed = urlsplit(server.url)
    token = token_file.read_text(encoding="ascii").removesuffix("\n")
    path = parsed.path + endpoint
    headers = {"Authorization": "Bearer " + token, "Idempotency-Key": key,
               "User-Agent": UA, "Connection": "close"}
    payload = b"" if body is None else body.encode("ascii")
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=15)
    try:
        connection.request("POST", path, payload, headers)
        response = connection.getresponse()
        wire = response.read(65537)
        require(len(wire) <= 65536, "scope and outcome control response exceeded its bound")
        artifact = campaign.work / (name + ".json")
        artifact.write_bytes(wire)
        campaign.record(kind="http", path=path, status=response.status, artifact=str(artifact))
        return response.status, json.loads(wire)
    finally:
        connection.close()


def check_connections(server, expected):
    rows = (json.loads(line) for line in server.stdout_path.read_text().splitlines())
    drain = next(row for row in rows if row["type"] == "smart_http_drained")
    require(drain["accepted"] == expected, "unexpected HTTP request count after native drain")


def run_case(campaign, directory, fmt):
    repository = directory / "repository"
    origin = directory / "origin"
    git = fixture(origin, fmt)
    for name in ("obsolete", "update"):
        (origin / "refs" / "heads" / name).write_text(git["base"] + "\n", encoding="ascii")
    campaign.run("init", repository, TENANT, REPOSITORY, fmt)
    campaign.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "operator-branch-base", origin)
    credentials, incarnation = campaign.credentials(repository, directory)
    header = credentials.read_text(encoding="ascii").splitlines()[0]
    grants = {
        "writer": (PRINCIPAL, "receive"),
        "outcomes": (PRINCIPAL, "outcomes-read"),
        "rotated": (PRINCIPAL, "outcomes-read"),
        "other_writer": (OTHER, "receive"),
        "other_reader": (OTHER, "outcomes-read"),
    }
    tokens, credential_rows = {}, []
    for label, (principal, grant) in grants.items():
        value = secrets.token_hex(32)
        tokens[label] = write_private(directory / (label + ".token"), value + "\n")
        credential_rows.append(f"{hashlib.sha256(value.encode()).hexdigest()} {principal} {grant}")
    credentials.write_text("\n".join([header, *credential_rows]) + "\n", encoding="ascii")

    def snapshot():
        return json.loads(campaign.run("branch", "list", repository, TENANT, REPOSITORY,
                                       "--trusted-local", "--object-format", fmt, "--limit", 100))

    def refs(page):
        return {row["reference_hex"]: row["tip"] for row in page["branches"]}

    def server(name):
        gateway = HttpServer(campaign, repository, credentials, fmt + "-" + name)
        gateway.command.extend(("--allow-source", "--allow-receive", "--allow-outcomes"))
        return gateway

    def prepare(name, endpoint, changes, writer):
        path = write_private(directory / (name + ".json"), json.dumps({
            "endpoint": endpoint, "scope": {"tenant_id": TENANT, "repository_id": REPOSITORY,
                "repository_incarnation": incarnation, "principal_id": PRINCIPAL, "object_format": fmt},
            "bind_writer_scope": True, "changes": changes,
        }))
        job = directory / (name + "-job")
        reply = campaign.node_command(CLI, ["prepare", "--input", str(path), "--request-dir",
                                            str(job), "--token-file", str(tokens[writer])])
        return ["--request-dir", str(job), "--confirm", reply["intent_sha256"]], json.loads(
            (job / "intent.json").read_text(encoding="utf-8"))

    def invoke(action, job, name, writer, reader=None, status=0, error=False, preload=None):
        args = [action, *job, "--token-file", str(tokens[writer]),
                "--record", str(directory / (name + "-record.json"))]
        if reader is not None:
            args.extend(("--outcome-token-file", str(tokens[reader])))
        return campaign.node_command(CLI, args, status, error_reply=error, preload=preload)

    def recorded(name):
        return json.loads((directory / (name + "-record.json")).read_text(encoding="utf-8"))

    changes = [
        dict(operation="delete", ref_hex=DELETE, expected_commit=git["base"]),
        dict(operation="update", ref_hex=UPDATE, expected_commit=git["base"], new_commit=git["target"]),
        dict(operation="create", ref_hex=RAW, new_commit=git["source"]),
    ]
    before = snapshot()
    with server("initial") as gateway:
        endpoint = gateway.url
        job, intent = prepare("mixed", endpoint, changes, "writer")
        scope = ":".join((TENANT, REPOSITORY, incarnation, PRINCIPAL))
        require(intent["body"].endswith("&expected_scope=" + scope), "exact writer binding was absent")
        invoke("send", job, "no_reader", "writer", status=3, error=True)
        denied = recorded("no_reader")
        require(denied["error"]["status"] == 403 and denied["error"]["phase"] == "preflight"
                and not denied["dispatched"] and snapshot() == before, "receive-only twin attempted publication")

        invoke("send", job, "wrong_reader", "writer", "other_reader", 3, True)
        denied = recorded("wrong_reader")
        require(denied["error"]["code"] == "outcome_scope_or_semantics_changed"
                and denied["error"]["phase"] == "preflight" and not denied["dispatched"]
                and snapshot() == before, "an outcome credential crossed the selected principal")

        wrong_job, wrong_intent = prepare("wrong_writer", endpoint, changes, "other_writer")
        invoke("send", wrong_job, "wrong_writer", "other_writer", "outcomes", 3, True)
        denied = recorded("wrong_writer")
        require(denied["error"]["status"] == 403 and denied["error"]["phase"] == "publication"
                and denied["dispatched"] and denied["publication"] is None and snapshot() == before,
                "expected a request-level 403 for the mismatched writer with the canonical branch page intact")
        status, refused_scope = native_request(campaign, gateway, fmt + "-wrong-writer-reply",
                "/api/v1/source/branches/transaction", tokens["other_writer"], wrong_intent["key"],
                wrong_intent["body"])
        require(status == 403 and refused_scope["code"] == "branch_transaction_scope_mismatch",
                "native gateway did not identify the exact writer mismatch")
        status, observation = native_request(campaign, gateway, fmt + "-wrong-writer-outcome",
                "/api/v1/outcomes", tokens["other_reader"], wrong_intent["key"])
        require(status == 200 and observation["state"] == "key_not_observed"
                and observation["transaction"] is None, "the mismatched writer registered a native transaction")

        # Truncate the real native response after its headers. The original
        # request still reaches the native publish boundary over its socket.
        hook = write_private(directory / "lose-publication.mjs", """import http from 'node:http';
import { writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const request = http.request;
const receipt = new URL('./truncated-response.json', import.meta.url);
http.request = function (...args) {
  const req = Reflect.apply(request, this, args);
  if (req.method === 'POST' && args[0].pathname.endsWith('/source/branches/transaction')) {
    req.prependOnceListener('response', res => {
      writeFileSync(receipt, JSON.stringify({status: res.statusCode}), {mode: 0o600, flag: 'wx'});
      res.destroy(new Error('planted reply truncation'));
    });
  }
  return req;
};
syncBuiltinESMExports();
""")
        lost = invoke("send", job, "lost_reply", "writer", "outcomes", 3, True, hook)
        unresolved = recorded("lost_reply")
        truncation = json.loads((directory / "truncated-response.json").read_text())
        require(truncation["status"] == 200 and lost["record_saved"]
                and unresolved["dispatched"] and unresolved["error"]["phase"] == "publication"
                and unresolved["outcome"]["state"] == "key_not_observed"
                and unresolved["publication"] is None, "truncated publication was presented as confirmed")
        after = snapshot()
        wanted = refs(before)
        del wanted[DELETE]
        wanted.update({UPDATE: git["target"], RAW: git["source"]})
        require(refs(after) == wanted and after["source_head"] != before["source_head"],
                "native atomic publication did not produce the three reviewed effects")
        status, terminal = native_request(campaign, gateway, fmt + "-published-before-restart",
                "/api/v1/outcomes", tokens["outcomes"], intent["key"])
        require(status == 200 and terminal["terminal"] and terminal["state"] == "committed",
                "independent native lookup could not recover the original decision before restart")
        sequence = terminal["decision"]["decision_sequence"]
        require(type(sequence) is int and 0 < sequence < 2**64, "native outcome sequence was not an exact u64")
        terminal["decision"]["decision_sequence"] = str(sequence)
    check_connections(gateway, 9)

    restarted = server("restarted")
    restarted.command[5] = f"127.0.0.1:{urlsplit(endpoint).port}"
    with restarted:
        require(restarted.url == endpoint, "restart did not restore the reviewed endpoint")
        recovered = invoke("recover", job, "rotated", "rotated")
        repeated = invoke("send", job, "repeat", "writer", "rotated")
        for observation in (recovered, repeated):
            require(not observation["dispatched"] and observation["outcome"] == terminal,
                    "restart retrieval changed the original seal, decision or scope")
        require(snapshot() == after, "original-key recovery changed canonical refs or their head")

        stale_job, _ = prepare("stale", endpoint, [
            dict(operation="create", ref_hex=b"refs/heads/must-not-appear".hex(), new_commit=git["base"]),
            dict(operation="delete", ref_hex=UPDATE, expected_commit=git["base"]),
        ], "writer")
        refused = invoke("send", stale_job, "stale", "writer", "outcomes", 1)
        recovered_refusal = invoke("recover", stale_job, "recovered_refusal", "rotated", status=1)
        require(refused["state"] == "refused" and refused["dispatched"]
                and refused["outcome"]["terminal"] and not recovered_refusal["dispatched"]
                and refused["outcome"]["decision"]["code"] == "ExpectedOldRefMismatch"
                and refused["outcome"] == recovered_refusal["outcome"] and refs(snapshot()) == wanted,
                "the stale lease published a partial effect or lost its terminal refusal")
    check_connections(restarted, 6)
    return {"publication": terminal, "refusal": refused["outcome"], "refs": wanted}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("fg", "node", "work"):
        parser.add_argument("--" + argument, required=True, type=Path)
    args = parser.parse_args()
    campaign = OperatorCampaign(args.fg.resolve(strict=True), args.node.resolve(strict=True), args.work)
    def stop(_signum, _frame):
        raise InterruptedError("branch transaction campaign interrupted; draining owned children")

    signal.signal(signal.SIGTERM, stop)
    for fmt in ("sha1", "sha256"):
        directory = args.work / fmt
        directory.mkdir(mode=0o700)
        result = run_case(campaign, directory, fmt)
        # Keep both terminal proofs and the canonical raw-byte ref map.
        (args.work / (fmt + "-terminal.json")).write_text(json.dumps(result, sort_keys=True) + "\n")
        print(json.dumps({"object_format": fmt, "native_split_grant_campaign": "complete"}), flush=True)


if __name__ == "__main__":
    main()
