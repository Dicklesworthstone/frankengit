#!/usr/bin/env python3
"""Exercise canonical event reads through a prebuilt fg, HTTP and stdio MCP.

No Git subprocess, mock node, synthetic event database, or implicit build. All
commands, HTTP responses and service stdout/stderr remain in --work, including
on failure. Fixture credentials never leave the private loopback test service.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

TENANT, REPOSITORY, PRINCIPAL = "11" * 16, "22" * 16, "33" * 16
TOKENS = {"issues": "a" * 64, "pulls": "b" * 64, "write": "c" * 64, "both": "d" * 64}
MAX_RESPONSE = 2 * 1024 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def rows(page: dict[str, Any]) -> list[tuple[str, str]]:
    return [(event["cursor"], event["event_frame_hex"]) for event in page["events"]]


class Campaign:
    def __init__(self, fg: Path, work: Path) -> None:
        self.fg, self.work = fg, work
        self.serial = 0
        self.facts: dict[str, bool] = {}
        self.journal = work / "commands.jsonl"

    def record(self, **entry: Any) -> None:
        with self.journal.open("a", encoding="utf-8") as out:
            out.write(json.dumps(entry, sort_keys=True) + "\n")

    def run(self, *args: Any, input_bytes: bytes | None = None) -> bytes:
        self.serial += 1
        stem = self.work / f"command-{self.serial:03d}"
        command = [str(self.fg), *map(str, args)]
        started = time.monotonic()
        with stem.with_suffix(".stdout").open("wb") as stdout, stem.with_suffix(".stderr").open("wb") as stderr:
            try:
                completed = subprocess.run(command, input=input_bytes, stdout=stdout, stderr=stderr,
                                           timeout=90, check=False)
            except subprocess.TimeoutExpired:
                self.record(kind="command", command=command, timeout=True,
                            duration_ms=round((time.monotonic() - started) * 1000))
                raise
        self.record(kind="command", command=command, exit=completed.returncode,
                    duration_ms=round((time.monotonic() - started) * 1000), artifacts=str(stem))
        if completed.returncode:
            sys.stderr.write(stem.with_suffix(".stderr").read_text(errors="replace"))
            raise AssertionError(f"fg command failed ({completed.returncode}); see {stem}")
        return stem.with_suffix(".stdout").read_bytes()

    def issue(self, root: Path, fmt: str, version: int, key: str, body: str) -> None:
        verb = "open" if version == 0 else "comment"
        fields = ["--title", "Canonical feed fixture"] if version == 0 else []
        receipt = json.loads(self.run("issue", verb, root, TENANT, REPOSITORY, "1", "--trusted-local",
                                     "--object-format", fmt, "--principal", PRINCIPAL,
                                     "--idempotency-key", key, "--expected-version", version,
                                     *fields, "--body", body))
        require(receipt["command_committed"] is True and receipt["node_closed"] is True,
                "issue seed did not canonically commit and close")

    def canonical(self, root: Path, fmt: str) -> dict[str, Any]:
        return json.loads(self.run("events", root, TENANT, REPOSITORY, "--trusted-local",
                                   "--object-format", fmt, "--limit", "100"))

    def mcp(self, root: Path, fmt: str, grant: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "event-feed-e2e", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"} if arguments is None else
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "frankengit_events", "arguments": arguments}},
        ]
        data = ("\n".join(json.dumps(message) for message in messages) + "\n").encode()
        output = self.run("mcp", root, TENANT, REPOSITORY, "--trusted-local", grant,
                          "--object-format", fmt, "--max-messages", "8", input_bytes=data)
        replies = [json.loads(line) for line in output.splitlines()]
        require(len(replies) == 2 and replies[-1].get("id") == 2, "MCP did not finish the actual protocol")
        require("error" not in replies[-1], f"MCP refused: {replies[-1]}")
        result = replies[-1]["result"]
        require(not result.get("isError", False), f"MCP read failed: {result}")
        return result if arguments is None else result["structuredContent"]

    def credentials(self, root: Path, directory: Path) -> tuple[Path, str]:
        header = self.run("serve-http", root, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--print-credentials-header").decode().strip()
        parts = header.split()
        require(len(parts) == 4 and parts[:3] == ["frankengit-http-credentials-v1", TENANT, REPOSITORY],
                "credential header does not bind this repository")
        scopes = {"issues": "issues-read", "pulls": "pulls-read", "write": "issues-write,pulls-write",
                  "both": "issues-read,pulls-read"}
        lines = [header, *[f"{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} {scopes[name]}"
                          for name, token in TOKENS.items()]]
        path = directory / "credentials"
        with path.open("x", encoding="utf-8") as out:
            os.chmod(path, 0o600)
            out.write("\n".join(lines) + "\n")
        return path, parts[-1]


class HttpServer:
    def __init__(self, campaign: Campaign, root: Path, credentials: Path, label: str) -> None:
        self.campaign = campaign
        self.stop = campaign.work / f"{label}.stop"
        self.stdout_path = campaign.work / f"{label}.stdout"
        self.stderr_path = campaign.work / f"{label}.stderr"
        self.command = [str(campaign.fg), "serve-http", str(root), TENANT, REPOSITORY, "127.0.0.1:0",
                        "--trusted-local", "--credentials-file", str(credentials),
                        "--allow-issues", "--allow-pulls", "--continuous", "--stop-file", str(self.stop),
                        "--max-in-flight", "2", "--session-timeout-secs", "60"]
        self.process: subprocess.Popen[bytes] | None = None
        self.url = ""

    def __enter__(self) -> HttpServer:
        with self.stdout_path.open("wb") as stdout, self.stderr_path.open("wb") as stderr:
            self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        self.campaign.record(kind="service_start", command=self.command, pid=self.process.pid,
                             stdout=str(self.stdout_path), stderr=str(self.stderr_path))
        try:
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                require(self.process.poll() is None, "HTTP service exited before readiness")
                for line in self.stdout_path.read_bytes().splitlines():
                    try:
                        value = json.loads(line)
                    except (ValueError, UnicodeDecodeError):
                        continue
                    if value.get("type") == "smart_http_listening":
                        self.url = value["url"]
                        parsed = urlsplit(self.url)
                        require(parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port,
                                "readiness did not name a bounded loopback listener")
                        return self
                time.sleep(0.05)
            raise TimeoutError("HTTP service did not become ready")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.process is None:
            return
        process, self.process = self.process, None
        started = time.monotonic()
        self.stop.touch(exist_ok=False)
        forced = False
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            forced = True
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        self.campaign.record(kind="service_stop", pid=process.pid, exit=process.returncode, forced=forced,
                             duration_ms=round((time.monotonic() - started) * 1000))
        # Always retain and show actual service diagnostics; do not suppress an
        # error that explains a refused transport or failed drain.
        diagnostics = self.stderr_path.read_text(errors="replace")
        if diagnostics:
            sys.stderr.write(diagnostics)
        require(not forced and process.returncode == 0, "HTTP child did not drain cleanly within 30 seconds")
        values = [json.loads(line) for line in self.stdout_path.read_bytes().splitlines()]
        drains = [value for value in values if value.get("type") == "smart_http_drained"]
        require(len(drains) == 1, "missing unique drain receipt")
        drain = drains[0]
        require(drain["accepted"] == drain["completed_transports"] + drain["refused_transports"],
                "HTTP drain did not settle every accepted connection")

    def __exit__(self, *_: Any) -> None:
        self.close()

    def get(self, grant: str | None, *, parameters: dict[str, Any] | None = None,
            suffix: str | None = None, expected: int = 200, method: str = "GET",
            body: bytes | None = None, basic: bool = False) -> dict[str, Any]:
        parsed = urlsplit(self.url)
        query = urlencode(parameters or {})
        target = parsed.path + "/api/v1/events" + ("?" + query if query else "")
        if suffix is not None:
            target = parsed.path + "/api/v1/events" + suffix
        headers = {"Connection": "close"}
        if grant is not None:
            headers["Authorization"] = "Basic Z2l0OmFhYQ==" if basic else "Bearer " + TOKENS[grant]
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=90)
        self.campaign.serial += 1
        artifact = self.campaign.work / f"http-{self.campaign.serial:03d}.json"
        started = time.monotonic()
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            wire = response.read(MAX_RESPONSE + 1)
            require(len(wire) <= MAX_RESPONSE, "HTTP response exceeded its output bound")
            artifact.write_bytes(wire)
            observed_headers = dict(response.getheaders())
            self.campaign.record(kind="http", method=method, path=target, grant=grant,
                                 status=response.status, expected=expected, headers=observed_headers,
                                 artifact=str(artifact), duration_ms=round((time.monotonic() - started) * 1000))
            require(response.status == expected, f"HTTP status {response.status}, expected {expected}: {wire!r}")
            require(int(response.getheader("Content-Length", "-1")) == len(wire), "incorrect framing length")
            require(response.getheader("Cache-Control") == "no-store", "event response was cacheable")
            require(response.getheader("Vary") == "Authorization", "scope-sensitive response missing Vary")
            require(response.getheader("X-Content-Type-Options") == "nosniff", "missing nosniff")
            if expected == 401:
                challenge = response.getheader("WWW-Authenticate", "")
                require(challenge.startswith("Bearer ") and "Basic" not in challenge, "ambient Basic challenge")
            if expected == 405:
                require(response.getheader("Allow") == "GET", "event endpoint advertised writes")
            value = json.loads(wire)
            require(value.get("read_only") is True, "response did not preserve read-only semantics")
            if expected != 200:
                require(value["type"] == "event_error" and value["outcome_unknown"] is False,
                        "read refusal was not a typed event error")
            return value
        finally:
            connection.close()


def run_case(campaign: Campaign, fmt: str) -> None:
    directory = campaign.work / fmt
    directory.mkdir()
    root = directory / "node"
    campaign.run("init", root, TENANT, REPOSITORY, fmt)
    campaign.issue(root, fmt, 0, "open-fixture", "Canonical é\r\n<script>data only</script>")
    campaign.issue(root, fmt, 1, "comment-fixture", "Second event")
    campaign.issue(root, fmt, 1, "comment-fixture", "Second event")
    canonical = campaign.canonical(root, fmt)
    require(len(canonical["events"]) == 2, "retry appended duplicate canonical events")
    credentials, incarnation = campaign.credentials(root, directory)
    with HttpServer(campaign, root, credentials, fmt + "-first") as server:
        first = server.get("issues", parameters={"limit": 1})
        pin = first["snapshot_token"]
        require(first["repository_incarnation"] == incarnation, "HTTP changed incarnation")
        require(first["object_format"] == fmt, "HTTP selected the wrong native hash domain")
        require(first["has_more"] is True and len(first["events"]) == 1, "first page missing continuation")
        second = server.get("issues", parameters={"after": first["next_after"], "limit": 1, "expected_head": pin})
        require(second["has_more"] is False and second["next_after"] is None, "tail did not reach EOF")
        resume = second["resume_after"]
        require(resume is not None, "EOF lost the append-poll watermark")
        require(rows(first) + rows(second) == rows(canonical), "HTTP dropped/repeated/rewrote canonical frames")
        require(second["snapshot_token"] == pin, "page snapshots differ")
        require(first == campaign.mcp(root, fmt, "--allow-issues", {"limit": 1}), "HTTP and MCP first pages diverge")
        require(second == campaign.mcp(root, fmt, "--allow-issues", {
            "after": first["next_after"], "limit": 1, "expected_head": pin}), "HTTP and MCP tails diverge")
        for event in first["events"] + second["events"]:
            for field in ("repository_sequence", "event_index", "policy_epoch", "aggregate_version"):
                require(isinstance(event[field], str) and event[field].isdigit(), "lossy numeric event field")
        hidden = server.get("pulls", parameters={"limit": 1})
        require(hidden["events"] == [] and hidden["next_after"] == first["next_after"], "filtered page stalled/leaked")
        require(hidden["cursor_discloses_repository_activity"] is True, "cursor leakage was not explicit")
        require(hidden == campaign.mcp(root, fmt, "--allow-pulls", {"limit": 1}), "filtered transports differ")
        hidden_tail = server.get("pulls", parameters={"after": hidden["next_after"]})
        require(hidden_tail["events"] == [] and hidden_tail["resume_after"] == resume, "hidden tail did not advance")
        server.get("write", expected=403)
        server.get(None, expected=401)
        server.get("issues", basic=True, expected=401)
        server.get("issues", parameters={"principal": "admin"}, expected=400)
        server.get("issues", suffix="?limit=1&%6cimit=2", expected=400)
        server.get("issues", parameters={"after": "1:00"}, expected=400)
        server.get("issues", parameters={"limit": 101}, expected=400)
        server.get("issues", method="POST", expected=405)
        server.get("issues", body=b"not an event append", expected=400)
        # A planted-invalid request must not disturb its exact permitted twin.
        require(server.get("issues", parameters={"limit": 1, "expected_head": pin}) == first,
                "refusals changed repository state")
        tools = campaign.mcp(root, fmt, "--allow-source", None)["tools"]
        require(all(tool["name"] != "frankengit_events" for tool in tools), "source read silently grants metadata")
    campaign.facts[fmt + "_parity_scopes_bounds"] = True

    # Reopening separate HTTP/MCP processes reconstructs, rather than remembers,
    # the cursor. Closing/starting a listener must not publish a repository head.
    with HttpServer(campaign, root, credentials, fmt + "-reopened") as server:
        eof = server.get("issues", parameters={"after": resume, "expected_head": pin})
        require(eof["events"] == [] and eof["resume_after"] == resume, "restart lost EOF watermark")
        require(eof == campaign.mcp(root, fmt, "--allow-issues", {"after": resume, "expected_head": pin}),
                "MCP restart changed cursor semantics")
        campaign.issue(root, fmt, 2, "append-fixture", "Third event after restart")
        stale = server.get("issues", parameters={"after": resume, "expected_head": pin}, expected=409)
        require(stale["code"] == "snapshot_moved", "stale pin silently refreshed")
        appended = server.get("issues", parameters={"after": resume})
        require(len(appended["events"]) == 1 and appended["events"][0]["aggregate_version"] == "3", "append cursor skipped/duplicated")
        require(appended == campaign.mcp(root, fmt, "--allow-issues", {"after": resume}), "append transports differ")
        require(rows(campaign.canonical(root, fmt)) == rows(canonical) + rows(appended), "canonical parity after append")
        require(appended["snapshot_token"] != pin, "append did not advance authority")
        after_reads = server.get("issues", parameters={"expected_head": appended["snapshot_token"]})
        require(rows(after_reads) == rows(canonical) + rows(appended), "reads unexpectedly published")
    campaign.facts[fmt + "_restart_append_drain"] = True
    print(f"SCOPED_EVENTS format={fmt} canonical_parity_scopes_restart_append_drain=passed", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    args = parser.parse_args()
    fg = args.fg.resolve(strict=True)
    require(fg.is_file() and os.access(fg, os.X_OK), "--fg must be a prebuilt executable")
    args.work.mkdir(parents=True, exist_ok=True)
    require(not any(args.work.iterdir()), "--work must be an empty retained artifact directory")
    campaign = Campaign(fg, args.work.resolve())
    summary: dict[str, Any] = {"facts": campaign.facts, "complete": False,
        "binary_sha256": file_sha256(fg),
        "python": sys.version, "artifacts": str(campaign.work),
        "non_claim": "No indexed O(limit) read, browser, TLS, hostile isolation, long-poll or full forge event coverage."}
    def stop(_signum: int, _frame: Any) -> None:
        raise InterruptedError("campaign interrupted; draining owned children")
    signal.signal(signal.SIGTERM, stop)
    try:
        for fmt in ("sha1", "sha256"):
            run_case(campaign, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
