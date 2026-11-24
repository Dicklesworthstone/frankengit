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
import socket
import subprocess
import sys
import threading
import time
from typing import Any
from urllib.parse import urlencode, urlsplit

TENANT, REPOSITORY, PRINCIPAL = "11" * 16, "22" * 16, "33" * 16
TOKENS = {"issues": "a" * 64, "pulls": "b" * 64, "write": "c" * 64, "both": "d" * 64}
MAX_RESPONSE = 2 * 1024 * 1024
ARTIFACT_LOCK = threading.Lock()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wait_process_interruptibly(process: subprocess.Popen[Any], timeout: float) -> int:
    # CPython 3.15's Popen._wait_kqueue wraps kq.control() in `except OSError: return False`,
    # which catches and discards signal-handler InterruptedError (an OSError subclass).
    deadline = time.monotonic() + timeout
    delay = 0.0005
    while True:
        code = process.poll()
        if code is not None:
            return code
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        time.sleep(min(delay, remaining))
        delay = min(delay * 2, 0.02)


def rows(page: dict[str, Any]) -> list[tuple[str, str]]:
    return [(event["cursor"], event["event_frame_hex"]) for event in page["events"]]


class Campaign:
    def __init__(self, fg: Path, work: Path) -> None:
        self.fg, self.work = fg, work
        self.serial = 0
        self.facts: dict[str, bool] = {}
        self.journal = work / "commands.jsonl"

    def record(self, **entry: Any) -> None:
        with ARTIFACT_LOCK, self.journal.open("a", encoding="utf-8") as out:
            out.write(json.dumps(entry, sort_keys=True) + "\n")

    def run(self, *args: Any, input_bytes: bytes | None = None) -> bytes:
        with ARTIFACT_LOCK:
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

    def mcp(self, root: Path, fmt: str, grant: str, arguments: dict[str, Any] | None,
            *, invalid: str | None = None, failed: str | None = None) -> dict[str, Any]:
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
        if invalid is not None:
            error = replies[-1].get("error", {})
            require(error.get("code") == -32602 and error.get("message") == invalid,
                    f"MCP did not report the exact invalid-parameter refusal: {replies[-1]}")
            return error
        require("error" not in replies[-1], f"MCP refused: {replies[-1]}")
        result = replies[-1]["result"]
        if failed is not None:
            body = result.get("structuredContent", {})
            require(result.get("isError") is True and body.get("code") == failed
                    and body.get("complete") is False,
                    f"MCP did not report the exact read refusal: {result}")
            return body
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
        try:
            with self.stdout_path.open("wb") as stdout, self.stderr_path.open("wb") as stderr:
                self.process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
            self.campaign.record(kind="service_start", command=self.command, pid=self.process.pid,
                                 stdout=str(self.stdout_path), stderr=str(self.stderr_path))
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
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                if self.process is not None:
                    raise RuntimeError("HTTP child containment failed after startup failure") from cleanup
                # A failed startup stays a failure even if shutdown itself
                # cannot produce a normal drain receipt. Preserve both causes.
                raise error from cleanup
            raise

    def close(self) -> None:
        if self.process is None:
            return
        process = self.process
        started = time.monotonic()
        forced = False
        try:
            self.stop.touch(exist_ok=False)
            try:
                wait_process_interruptibly(process, timeout=30)
            except subprocess.TimeoutExpired:
                forced = True
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except BaseException as error:
            # A failed stop-file write or cancellation still owns this child.
            # Keep its Popen capability and finish the bounded reap before
            # propagating the original failure. Repeated cancellation must not
            # interrupt this final drain or silently turn it into success.
            handlers = {}
            try:
                if threading.current_thread() is threading.main_thread():
                    for number in (signal.SIGTERM, signal.SIGINT):
                        handlers[number] = signal.signal(number, signal.SIG_IGN)
                try:
                    if process.poll() is None:
                        forced = True
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                except BaseException as cleanup:
                    self.campaign.record(kind="service_stop", pid=process.pid, exit=process.poll(),
                                         forced=forced, close_error=type(error).__name__,
                                         cleanup_error=type(cleanup).__name__,
                                         duration_ms=round((time.monotonic() - started) * 1000))
                    raise RuntimeError("HTTP child containment failed during interrupted close") from cleanup
                self.process = None
                self.campaign.record(kind="service_stop", pid=process.pid, exit=process.returncode,
                                     forced=forced, close_error=type(error).__name__,
                                     duration_ms=round((time.monotonic() - started) * 1000))
            finally:
                for number, handler in handlers.items():
                    signal.signal(number, handler)
            raise
        self.process = None
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
            body: bytes | None = None, basic: bool = False,
            connection: http.client.HTTPConnection | None = None,
            request_sent: threading.Event | None = None) -> dict[str, Any]:
        parsed = urlsplit(self.url)
        query = urlencode(parameters or {})
        target = parsed.path + "/api/v1/events" + ("?" + query if query else "")
        if suffix is not None:
            target = parsed.path + "/api/v1/events" + suffix
        headers = {"Connection": "close"}
        if grant is not None:
            headers["Authorization"] = "Basic Z2l0OmFhYQ==" if basic else "Bearer " + TOKENS[grant]
        if connection is None:
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=90)
        with ARTIFACT_LOCK:
            self.campaign.serial += 1
            artifact = self.campaign.work / f"http-{self.campaign.serial:03d}.json"
        started = time.monotonic()
        try:
            connection.request(method, target, body=body, headers=headers)
            if request_sent is not None:
                request_sent.set()
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


def append_while_http_waits(campaign: Campaign, server: HttpServer, root: Path,
                           fmt: str, resume: str, pin: str) -> dict[str, dict[str, Any]]:
    """Own both real HTTP reads until a CLI append wakes or refuses them."""
    parsed = urlsplit(server.url)
    requests = {
        "unpinned": ({"after": resume, "wait_ms": 5000}, 200),
        "pinned": ({"after": resume, "expected_head": pin, "wait_ms": 5000}, 409),
    }
    connections = {name: http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
                   for name in requests}
    sent = {name: threading.Event() for name in requests}
    done = {name: threading.Event() for name in requests}
    pages: dict[str, dict[str, Any]] = {}
    errors: dict[str, BaseException] = {}
    threads: list[threading.Thread] = []

    def read(name: str) -> None:
        parameters, expected = requests[name]
        try:
            pages[name] = server.get("issues", parameters=parameters, expected=expected,
                                     connection=connections[name], request_sent=sent[name])
        except BaseException as error:
            errors[name] = error
        finally:
            done[name].set()

    try:
        for name in requests:
            thread = threading.Thread(target=read, args=(name,), name=f"event-wait-{fmt}-{name}")
            threads.append(thread)
            thread.start()
        for name in requests:
            require(sent[name].wait(5), f"{name} HTTP wait was not sent within its bound")
            # A response-completion barrier makes a premature empty response
            # observable; publication is not coordinated by a guessed sleep.
            require(not done[name].wait(0.1), f"{name} HTTP read completed before the append")
        campaign.record(kind="event_wait", object_format=fmt, wait_ms=5000,
                        phase="both_requests_pending", after=resume)
        campaign.issue(root, fmt, 2, "append-fixture", "Third event during bounded HTTP waits")
        for name in requests:
            require(done[name].wait(10), f"{name} HTTP wait did not finish after publication")
    finally:
        # On assertion, timeout or interruption, release each owned socket
        # before joining. Repeated cancellation cannot interrupt this drain.
        handlers = {}
        try:
            if threading.current_thread() is threading.main_thread():
                for number in (signal.SIGTERM, signal.SIGINT):
                    handlers[number] = signal.signal(number, signal.SIG_IGN)
            for connection in connections.values():
                owned_socket = connection.sock
                if owned_socket is not None:
                    try:
                        owned_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                connection.close()
            for thread in threads:
                if thread.ident is not None:
                    thread.join(timeout=12)
            require(all(not thread.is_alive() for thread in threads), "HTTP wait reader did not drain")
        finally:
            for number, handler in handlers.items():
                signal.signal(number, handler)
    if errors:
        raise AssertionError(f"bounded HTTP wait failed: {errors}") from next(iter(errors.values()))
    require(set(pages) == set(requests), "HTTP wait lost a completed response")
    require(pages["pinned"]["code"] == "snapshot_moved", "pinned wait silently selected a new head")
    campaign.record(kind="event_wait", object_format=fmt, phase="readers_joined",
                    pinned_code=pages["pinned"]["code"], unpinned_events=len(pages["unpinned"]["events"]))
    return pages


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
        for wait_ms in (0, 2000):
            arguments = {"limit": 1, "wait_ms": wait_ms}
            require(server.get("issues", parameters=arguments) == first,
                    "HTTP wait changed an already available canonical page")
            require(campaign.mcp(root, fmt, "--allow-issues", arguments) == first,
                    "MCP wait changed an already available canonical page")
        for event in first["events"] + second["events"]:
            for field in ("repository_sequence", "event_index", "policy_epoch", "aggregate_version"):
                require(isinstance(event[field], str) and event[field].isdigit(), "lossy numeric event field")
        hidden = server.get("pulls", parameters={"limit": 1, "wait_ms": 2000})
        require(hidden["events"] == [] and hidden["next_after"] == first["next_after"], "filtered page stalled/leaked")
        require(hidden["cursor_discloses_repository_activity"] is True, "cursor leakage was not explicit")
        require(hidden == campaign.mcp(root, fmt, "--allow-pulls", {"limit": 1, "wait_ms": 2000}),
                "filtered wait transports differ")
        hidden_tail = server.get("pulls", parameters={"after": hidden["next_after"]})
        require(hidden_tail["events"] == [] and hidden_tail["resume_after"] == resume, "hidden tail did not advance")
        server.get("write", expected=403)
        server.get(None, expected=401)
        server.get("issues", basic=True, expected=401)
        server.get("issues", parameters={"principal": "admin"}, expected=400)
        server.get("issues", suffix="?limit=1&%6cimit=2", expected=400)
        server.get("issues", parameters={"after": "1:00"}, expected=400)
        server.get("issues", parameters={"limit": 101}, expected=400)
        for wait_ms in (30001, 18446744073709551616, -1, "1.0", "1e3", ""):
            refused = server.get("issues", parameters={"wait_ms": wait_ms}, expected=400)
            require(refused["code"] == "invalid_event_wait", "HTTP wait bound was not a typed refusal")
        for wait_ms in (30001, 18446744073709551616, -1, 1.0, "1", None, False):
            campaign.mcp(root, fmt, "--allow-issues", {"wait_ms": wait_ms}, invalid="invalid_event_wait")
        server.get("issues", method="POST", expected=405)
        server.get("issues", body=b"not an event append", expected=400)
        # A planted-invalid request must not disturb its exact permitted twin.
        require(server.get("issues", parameters={"limit": 1, "expected_head": pin}) == first,
                "refusals changed repository state")
        tools = campaign.mcp(root, fmt, "--allow-source", None)["tools"]
        require(all(tool["name"] != "frankengit_events" for tool in tools), "source read silently grants metadata")
        tools = campaign.mcp(root, fmt, "--allow-issues", None)["tools"]
        event_tool = next(tool for tool in tools if tool["name"] == "frankengit_events")
        schema = event_tool["inputSchema"]
        wait = schema["properties"]["wait_ms"]
        require(wait["type"] == "integer" and wait["minimum"] == 0
                and wait["maximum"] == 30000 and wait["default"] == 0
                and schema["additionalProperties"] is False,
                "live MCP catalog does not describe the strict bounded optional wait")
    campaign.facts[fmt + "_parity_scopes_bounds"] = True

    # Reopening separate HTTP/MCP processes reconstructs, rather than remembers,
    # the cursor. Closing/starting a listener must not publish a repository head.
    with HttpServer(campaign, root, credentials, fmt + "-reopened") as server:
        eof = server.get("issues", parameters={"after": resume, "expected_head": pin})
        require(eof["events"] == [] and eof["resume_after"] == resume, "restart lost EOF watermark")
        require(eof == campaign.mcp(root, fmt, "--allow-issues", {"after": resume, "expected_head": pin}),
                "MCP restart changed cursor semantics")
        for wait_ms in (0, 100):
            arguments = {"after": resume, "expected_head": pin, "wait_ms": wait_ms}
            started = time.monotonic()
            require(server.get("issues", parameters=arguments) == eof,
                    "HTTP tail timeout changed the empty page, cursor or exact pin")
            if wait_ms:
                require(time.monotonic() - started >= 0.075, "HTTP tail returned before its bounded wait")
            require(campaign.mcp(root, fmt, "--allow-issues", arguments) == eof,
                    "MCP tail timeout changed the empty page, cursor or exact pin")
        waiting = append_while_http_waits(campaign, server, root, fmt, resume, pin)
        stale = server.get("issues", parameters={"after": resume, "expected_head": pin, "wait_ms": 2000}, expected=409)
        require(stale["code"] == "snapshot_moved", "stale pin silently refreshed")
        require(waiting["pinned"] == stale, "head movement during a wait changed the refusal contract")
        campaign.mcp(root, fmt, "--allow-issues", {
            "after": resume, "expected_head": pin, "wait_ms": 2000}, failed="snapshot_moved")
        appended = server.get("issues", parameters={"after": resume, "wait_ms": 2000})
        require(len(appended["events"]) == 1 and appended["events"][0]["aggregate_version"] == "3", "append cursor skipped/duplicated")
        require(waiting["unpinned"] == appended, "pending HTTP wait did not return the exact appended page")
        require(appended == campaign.mcp(root, fmt, "--allow-issues", {"after": resume, "wait_ms": 2000}),
                "append wait transports differ")
        require(rows(campaign.canonical(root, fmt)) == rows(canonical) + rows(appended), "canonical parity after append")
        require(appended["snapshot_token"] != pin, "append did not advance authority")
        after_reads = server.get("issues", parameters={"expected_head": appended["snapshot_token"]})
        require(rows(after_reads) == rows(canonical) + rows(appended), "reads unexpectedly published")
    campaign.facts[fmt + "_restart_append_drain"] = True
    campaign.facts[fmt + "_bounded_wait"] = True
    print(f"SCOPED_EVENTS format={fmt} canonical_parity_scopes_restart_append_wait_pin_drain=passed", flush=True)


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
        "non_claim": "No indexed O(limit) read, browser, TLS, hostile isolation or full forge event coverage."}
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
