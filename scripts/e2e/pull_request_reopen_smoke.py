#!/usr/bin/env python3
"""Native CLI/HTTP PR reopening, review freshness and exact-retry campaign.

Requires an already-built fg. No substitute server, Git subprocess or Rust build.
Failure artifacts are retained; a pass requires both real process and HTTP paths.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import zlib

TENANT, REPOSITORY = "d1" * 16, "d2" * 16
OPENER, EDITOR, REVIEWER, MERGER = (value * 16 for value in ("d3", "d4", "d5", "d6"))
SOURCE, TARGET = "refs/heads/topic", "refs/heads/main"
TIMEOUT, MAX_REPLY = 120, 2 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def call(fg: Path, arguments: list, expected: int = 0, *, decode: bool = False):
    result = subprocess.run([str(fg), *map(str, arguments)], capture_output=True, timeout=TIMEOUT)
    require(result.returncode == expected,
            f"fg {arguments[:2]!r}: exit {result.returncode}, expected {expected}; "
            f"stderr={result.stderr[-8000:]!r}; stdout={result.stdout[-8000:]!r}")
    return json.loads(result.stdout) if decode else result.stdout


def seed(root: Path, algorithm: str):
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text(f"ref: {TARGET}\n")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = " +
                                ("1\n[extensions]\nobjectformat = sha256\n" if algorithm == "sha256" else "0\n"))
    def identity(kind: str, body: bytes) -> str:
        return hashlib.new(algorithm, f"{kind} {len(body)}\0".encode() + body).hexdigest()
    def store(kind: str, body: bytes) -> str:
        oid = identity(kind, body)
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(f"{kind} {len(body)}\0".encode() + body))
        return oid
    def commit(tree: str, parents: list[str], message: str) -> bytes:
        return (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents) +
                "author Fixture <fixture@example.invalid> 1 +0000\n"
                "committer Fixture <fixture@example.invalid> 1 +0000\n\n" + message + "\n").encode()
    blob = store("blob", b"reopening never changes repository bytes\n")
    tree = store("tree", b"100644 keep.txt\0" + bytes.fromhex(blob))
    base = store("commit", commit(tree, [], "base"))
    target = store("commit", commit(tree, [base], "target"))
    source = store("commit", commit(tree, [base], "source"))
    (root / TARGET).write_text(target + "\n")
    (root / SOURCE).write_text(source + "\n")
    merged = commit(tree, [target, source], "reviewed candidate")
    candidate = identity("commit", merged)
    size = len(merged)
    header = bytearray([(1 << 4) | (size & 15)])
    size >>= 4
    if size:
        header[0] |= 128
    while size:
        byte = size & 127
        size >>= 7
        header.append(byte | (128 if size else 0))
    pack = b"PACK" + struct.pack(">II", 2, 1) + header + zlib.compress(merged)
    pack += hashlib.new(algorithm, pack).digest()
    preamble = "# v2 git bundle\n" if algorithm == "sha1" else "# v3 git bundle\n@object-format=sha256\n"
    bundle = (preamble + f"-{target} target\n-{source} source\n{candidate} {TARGET}\n\n").encode() + pack
    data = dict(source_ref=SOURCE, target_ref=TARGET, source_tip=source, target_tip=target,
                title="Resume the same pull request", body='Untrusted <script>\né "quoted"\n')
    return data, base, candidate, bundle


def private_file(path: Path, text: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(text)


@contextlib.contextmanager
def serve(fg: Path, node: Path, root: Path, grants: Path, ordinal: int):
    stop = root / f"stop-{ordinal}"
    stdout, stderr = root / f"server-{ordinal}.out", root / f"server-{ordinal}.err"
    args = [fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
            "--credentials-file", grants, "--allow-pulls", "--max-in-flight", "4",
            "--session-timeout-secs", "30", "--processing-timeout-secs", "60",
            "--continuous", "--stop-file", stop]
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(list(map(str, args)), stdout=out, stderr=err)
        try:
            started, ready = time.monotonic(), None
            while time.monotonic() - started < TIMEOUT:
                for line in stdout.read_text().splitlines():
                    try:
                        value = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if value.get("type") == "smart_http_listening":
                        ready = value
                        break
                if ready:
                    break
                require(process.poll() is None, "HTTP server exited before readiness")
                time.sleep(0.02)
            require(ready is not None and ready["pulls_enabled"], "native PR listener not ready")
            require(not ready["receive_enabled"], "metadata service unexpectedly enabled Git writes")
            yield ready["url"]
            stop.touch(exist_ok=False)
            process.wait(timeout=90)
            require(process.returncode == 0, f"server did not drain cleanly: {stderr.read_bytes()[-8000:]!r}")
            records = [json.loads(line) for line in stdout.read_text().splitlines() if line]
            drained = [row for row in records if row.get("type") == "smart_http_drained"]
            require(len(drained) == 1, "missing native drain receipt")
            receipt = drained[0]
            require(receipt["accepted"] == receipt["completed_transports"] + receipt["refused_transports"],
                    "not every accepted connection was settled")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def api(url: str, suffix: str, token: str | None, *, fields=None, key: str | None = None,
        bundle: bytes | None = None):
    endpoint = urllib.parse.urlsplit(url)
    require(endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1"
            and endpoint.path == f"/{REPOSITORY}.git", "unexpected nonlocal native endpoint")
    headers = {"Connection": "close"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if key is not None:
        headers["Idempotency-Key"] = key
    body = None
    if fields is not None:
        body = urllib.parse.urlencode(fields, doseq=True).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if bundle is not None:
        require(body is not None, "bundle requires an explicit command")
        boundary = "fg-reopen-" + secrets.token_hex(16)
        require(boundary.encode() not in bundle and boundary.encode() not in body, "multipart collision")
        body = (f'--{boundary}\r\nContent-Disposition: form-data; name="command"\r\n'
                'Content-Type: application/x-www-form-urlencoded\r\n\r\n').encode() + body + (
                f'\r\n--{boundary}\r\nContent-Disposition: form-data; name="bundle"; filename="candidate.bundle"\r\n'
                'Content-Type: application/x-git-bundle\r\n\r\n').encode() + bundle + f'\r\n--{boundary}--\r\n'.encode()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=30)
    try:
        connection.request("GET" if fields is None else "POST", endpoint.path + "/api/v1/pulls/7" + suffix,
                           body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(MAX_REPLY + 1)
        require(len(payload) <= MAX_REPLY, "native response exceeded campaign limit")
        return response.status, json.loads(payload)
    finally:
        connection.close()


def exercise(fg: Path, root: Path, algorithm: str) -> None:
    root.mkdir()
    node = root / "node"
    data, base, candidate, bundle = seed(root / "source", algorithm)
    call(fg, ["init", node, TENANT, REPOSITORY, algorithm])
    call(fg, ["import", node, TENANT, REPOSITORY, OPENER, "reopen-fixture", root / "source"])
    refs = lambda: call(fg, ["at", node, TENANT, REPOSITORY, "latest", "refs"])
    initial_refs = refs()
    def encoded_data(value):
        return dict(source_reference_hex=value["source_ref"].encode().hex(),
                    target_reference_hex=value["target_ref"].encode().hex(),
                    source_tip=value["source_tip"], target_tip=value["target_tip"],
                    title=value["title"], body=value["body"])
    def mutate(action, version, key, value, actor=OPENER, committed=True):
        args = ["pr", action, node, TENANT, REPOSITORY, "7", "--trusted-local", "--principal", actor,
                "--idempotency-key", key, "--expected-version", str(version)]
        for name, field in [("--source-ref", "source_ref"), ("--target-ref", "target_ref"),
                            ("--source-tip", "source_tip"), ("--target-tip", "target_tip"),
                            ("--title", "title"), ("--body", "body")]:
            args.extend([name, value[field]])
        report = call(fg, args, 0 if committed else 3, decode=True)
        require(report["type"] == "pull_request_publication" and report["action"] == action,
                "CLI did not preserve the requested action")
        require(report["outcome"] == ("committed" if committed else "refused")
                and report["principal_id"] == actor and report["expected_version"] == version,
                "CLI terminal identity or version disagrees")
        require(report["refs_changed"] is False and report["delivery_acknowledged"] is None,
                "metadata command claimed a ref or delivery effect")
        require(report["data"] == encoded_data(value), "CLI command changed metadata or native coordinates")
        require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY
                and report["object_format"] == algorithm and report["node_closed"] is True
                and report["cleanup_error"] is None, "CLI scope or shutdown mismatch")
        return report
    def show(version, state, value, actor):
        report = call(fg, ["pr", "show", node, TENANT, REPOSITORY, "7", "--trusted-local",
                           "--object-format", algorithm], decode=True)
        row = report["pull_request"]
        require(report["found"] and row["version"] == version and row["state"] == state,
                "fresh-process PR read selected wrong lifecycle state")
        require(row["opened_by"] == OPENER and row["last_metadata_actor"] == actor,
                "reopening replaced the opener or lost the authenticated actor")
        require(row["data"] == encoded_data(value), "reopened metadata changed after persistence")
        require(row["number"] == 7 and row["kind"] == "pull_request" and report["node_closed"] is True,
                "reopened PR identity or read shutdown mismatch")
    def form(version, value):
        return dict(value, expected_version=version, object_format=algorithm)
    def terminal(result, committed, *, action=None):
        status, report = result
        require(status == (200 if committed else 409) and report["outcome"] == ("committed" if committed else "refused"),
                "HTTP did not return the required canonical terminal decision")
        require(report["delivery_acknowledged"] is None, "publication claimed external delivery")
        require(report["tenant_id"] == TENANT and report["repository_id"] == REPOSITORY
                and report["object_format"] == algorithm, "HTTP publication scope mismatch")
        if action is not None:
            require(report["action"] == action, "HTTP action differs")
        return report
    mutate("open", 0, "open", data)
    show(1, "open", data, OPENER)
    header = call(fg, ["serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                      "--print-credentials-header"]).decode().strip()
    require(header.startswith(f"frankengit-http-credentials-v1 {TENANT} {REPOSITORY} "), "credential binding header")
    edit, readonly, review, merger = (secrets.token_hex(32) for _ in range(4))
    grants = root / "grants"
    rows = [(edit, EDITOR, "pulls-read,pulls-write"), (readonly, EDITOR, "pulls-read"),
            (review, REVIEWER, "reviews-read,reviews-write"), (merger, MERGER, "merges-write")]
    private_file(grants, header + "\n" + "".join(
        f"{hashlib.sha256(token.encode()).hexdigest()} {principal} {scopes}\n"
        for token, principal, scopes in rows))
    reopened = dict(data, title="Explicit reopening", body=data["body"] + "Resume review.\n")
    remote = dict(data, title="Reopened through HTTP")
    with serve(fg, node, root, grants, 1) as url:
        status, page = api(url, "/reviews", review)
        require(status == 200 and page["found"], "review basis is unavailable")
        epoch = page["policy_epoch"]
        common = dict(object_format=algorithm, pull_request_version=1, policy_epoch=epoch,
                      source_ref=SOURCE, target_ref=TARGET, source_tip=data["source_tip"],
                      target_tip=data["target_tip"], merge_base=base, candidate_commit=candidate)
        terminal(api(url, "/reviews/approve", review,
                     fields=dict(common, expected_version=0, reason="Reviewed exact candidate"),
                     key="review-before-close", bundle=bundle), True)
        def freshness(expected):
            status, page = api(url, "/reviews", review)
            require(status == 200 and len(page["reviews"]) == 1, "review stream disappeared")
            require(page["reviews"][0]["freshness"] == expected, "review freshness disagrees with PR version")
            require(page["reviews"][0]["reviewer"] == REVIEWER
                    and page["reviews"][0]["candidate"]["candidate_commit"] == candidate,
                    "review lost its authenticated reviewer or exact candidate")
            require(page["merge_authorized"] is False, "read page granted merge authority")
        freshness("current")
        mutate("close", 1, "close-first", data)
        freshness("pull_request_closed")
        old_cli = mutate("reopen", 2, "reopen-cli", reopened, EDITOR)
        show(3, "open", reopened, EDITOR)
        freshness("pull_request_changed")
        terminal(api(url, "/merge", merger, fields=dict(common, pull_request_version=3,
                     required_reviewer=REVIEWER), key="old-review-must-not-merge", bundle=bundle), False)
        require(refs() == initial_refs, "stale approval moved a Git ref")
        terminal(api(url, "/reopen", edit, fields=form(3, reopened), key="already-open"), False, action="reopen")
        mutate("close", 3, "close-second", reopened)
        show(4, "closed", reopened, OPENER)
        for token, expected in [(None, 401), (readonly, 403)]:
            require(api(url, "/reopen", token, fields=form(4, remote), key="unauthorized")[0] == expected,
                    "reopen bypassed authentication or pulls-write")
        old_http = terminal(api(url, "/reopen", edit, fields=form(4, remote), key="reopen-http"), True, action="reopen")
        show(5, "open", remote, EDITOR)
        freshness("pull_request_changed")
        mutate("close", 5, "close-third", remote)
        require(refs() == initial_refs, "reopen metadata changed Git refs")
    with serve(fg, node, root, grants, 2) as url:
        recovered = terminal(api(url, "/reopen", edit, fields=form(4, remote), key="reopen-http"), True, action="reopen")
        require(recovered == old_http, "restart changed original HTTP terminal receipt")
        require(mutate("reopen", 2, "reopen-cli", reopened, EDITOR) == old_cli,
                "restart changed original CLI terminal receipt")
        show(6, "closed", remote, OPENER)
        require(api(url, "/reopen", edit, fields=form(4, dict(remote, title="changed semantics")),
                    key="reopen-http")[0] != 200, "key reuse accepted different metadata")
        for key, version, value in [
            ("stale-version", 4, remote),
            ("retarget", 6, dict(remote, source_ref="refs/heads/other")),
            ("stale-tip", 6, dict(remote, source_tip=data["target_tip"])),
        ]:
            terminal(api(url, "/reopen", edit, fields=form(version, value), key=key), False, action="reopen")
        show(6, "closed", remote, OPENER)
        race_data = dict(remote, title="One version wins the reopening race")
        keys = ["reopen-race-a", "reopen-race-b"]
        start = threading.Barrier(2)
        def compete(key):
            start.wait(timeout=10)
            return api(url, "/reopen", edit, fields=form(6, race_data), key=key)
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(compete, keys))
        require(sorted(status for status, _ in results) == [200, 409], "competing reopen attempts did not have one winner")
        for key, result in zip(keys, results, strict=True):
            terminal(result, result[0] == 200, action="reopen")
            require(api(url, "/reopen", edit, fields=form(6, race_data), key=key) == result,
                    "racing command did not retain its exact terminal outcome")
        show(7, "open", race_data, EDITOR)
        require(refs() == initial_refs, "racing metadata changed Git refs")
        common["pull_request_version"] = 7
        terminal(api(url, "/reviews/approve", review,
                     fields=dict(common, expected_version=1, reason="Re-reviewed after reopening"),
                     key="review-current", bundle=bundle), True)
        status, page = api(url, "/reviews", review)
        require(status == 200 and page["reviews"][0]["freshness"] == "current"
                and page["reviews"][0]["subject"]["pull_request_version"] == 7,
                "fresh candidate approval did not bind the reopened version")
        terminal(api(url, "/merge", merger, fields=dict(common, required_reviewer=REVIEWER),
                     key="merge-current", bundle=bundle), True)
        show(8, "merged", race_data, EDITOR)
        merged_refs = refs()
        require(candidate.encode() in merged_refs and merged_refs != initial_refs, "reviewed merge did not publish its candidate")
        denied = mutate("reopen", 8, "merged-is-terminal", race_data, EDITOR, False)
        require(denied["refusal_code"] == "ProtectedRefTransitionDenied", "merged PR reopened")
        show(8, "merged", race_data, EDITOR)
        require(refs() == merged_refs, "reopening refusal changed merged refs")
    print(json.dumps({"type": "pull_request_reopen_passed", "format": algorithm,
                      "final_version": 8, "candidate": candidate, "native_execution": True}), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--format", action="append", choices=["sha1", "sha256"], dest="formats")
    options = parser.parse_args()
    fg = options.fg.resolve(strict=True)
    require(fg.is_file() and os.access(fg, os.X_OK), "--fg must be an executable file")
    root = Path(tempfile.mkdtemp(prefix="fg-pr-reopen-"))
    with fg.open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    print(json.dumps({"type": "pull_request_reopen_started", "fg_sha256": digest}), flush=True)
    try:
        for algorithm in dict.fromkeys(options.formats or ["sha1", "sha256"]):
            exercise(fg, root / algorithm, algorithm)
    except BaseException:
        print(json.dumps({"type": "pull_request_reopen_failed", "artifacts": str(root)}), flush=True)
        raise
    else:
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
