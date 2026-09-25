#!/usr/bin/env python3
"""Exercise continuous serving and graceful stop against an already-built fg.

No Rust build, substitute server, or mocked transport. Requires Python 3.11+.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

from smart_http_smoke import (
    Commands, PRINCIPAL, REPOSITORY, SECRETS, TENANT, isolated_environment,
    redact, require, seed,
)


def private_file(path: Path, text: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
        stream.write(text)


def exchange(url: str, token: str | None) -> tuple[int, bytes]:
    endpoint = urllib.parse.urlsplit(url)
    require(endpoint.hostname == "127.0.0.1" and endpoint.scheme == "http", "non-loopback URL")
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
    headers = {"Connection": "close"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    try:
        connection.request("GET", endpoint.path + "/info/refs?service=git-upload-pack", headers=headers)
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        require(len(body) <= 1024 * 1024, "discovery exceeded its fixture bound")
        return response.status, body
    finally:
        connection.close()


def packet(text: str) -> bytes:
    data = text.encode("ascii")
    return f"{len(data) + 4:04x}".encode("ascii") + data


def ls_refs_request(fmt: str) -> bytes:
    require(fmt in ("sha1", "sha256"), "unknown object format")
    return (packet("command=ls-refs\n") + packet(f"object-format={fmt}\n")
            + b"0001" + packet("symrefs\n") + b"0000")


def active_read(url: str, token: str, fmt: str) -> tuple[socket.socket, bytes]:
    """Observe 100 Continue so the test KNOWS an authenticated child is active."""
    endpoint = urllib.parse.urlsplit(url)
    body = ls_refs_request(fmt)
    stream = socket.create_connection((endpoint.hostname, endpoint.port), timeout=15)
    try:
        stream.sendall((
            f"POST {endpoint.path}/git-upload-pack HTTP/1.1\r\nHost: local\r\n"
            f"Authorization: Bearer {token}\r\nGit-Protocol: version=2\r\n"
            "Content-Type: application/x-git-upload-pack-request\r\n"
            f"Content-Length: {len(body)}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
        ).encode("ascii"))
        interim = bytearray()
        while not interim.endswith(b"\r\n\r\n"):
            part = stream.recv(1)
            require(bool(part) and len(interim) < 4096, "missing bounded interim response")
            interim.extend(part)
        require(interim == b"HTTP/1.1 100 Continue\r\n\r\n", "request was not admitted for intake")
        return stream, body
    except BaseException:
        stream.close()
        raise


@contextlib.contextmanager
def running(fg: str, commands: Commands, root: Path, credentials: list[str], label: str):
    stop = root / f"{label}.stop"
    args = [fg, "serve-http", str(root / "state"), TENANT, REPOSITORY, "127.0.0.1:0",
            "--trusted-local", *credentials, "--allow-receive", "--continuous",
            "--stop-file", str(stop), "--max-in-flight", "2",
            "--session-timeout-secs", "30", "--processing-timeout-secs", "60"]
    # Pre-existing controls must refuse startup and must not be silently removed.
    private_file(stop, "prior stop\n")
    refused = subprocess.run(args, env=commands.env, capture_output=True, text=True, timeout=30)
    require(refused.returncode != 0 and "smart_http_listening" not in refused.stdout,
            "pre-existing stop file did not refuse startup")
    require(stop.read_text() == "prior stop\n", "startup removed/replaced the operator's stop request")
    stop.unlink()
    stdout_path, stderr_path = root / f"{label}.out", root / f"{label}.err"
    with stdout_path.open("w") as out, stderr_path.open("w") as err:
        process = subprocess.Popen(args, env=commands.env, stdout=out, stderr=err)
        try:
            end = time.monotonic() + commands.timeout
            ready = None
            while time.monotonic() < end:
                for line in stdout_path.read_text().splitlines():
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("type") == "smart_http_listening":
                        ready = record
                if ready is not None:
                    break
                require(process.poll() is None, "continuous server exited before readiness")
                time.sleep(0.02)
            require(ready is not None and ready.get("lifetime") == "continuous", "continuous readiness missing")
            url = ready["url"]
            require(url.startswith("http://127.0.0.1:") and url.endswith(f"/{REPOSITORY}.git"), "foreign listener")
            yield url, stop, process
            process.wait(timeout=90)
            require(process.returncode == 0, redact("HTTP drain failed: " + stderr_path.read_text()[-8000:]))
            records = [json.loads(line) for line in stdout_path.read_text().splitlines() if line]
            receipts = [record for record in records if record.get("type") == "smart_http_drained"]
            require(len(receipts) == 1, "missing or duplicate drain receipt")
            receipt = receipts[0]
            require(receipt["accepted"] == receipt["completed_transports"] + receipt["refused_transports"],
                    "accepted connections were not all settled")
            if label == "static":
                require(receipt["accepted"] > 1024, "campaign never crossed the old lifetime cap")
            require(stop.is_file(), "service removed its stop control")
        finally:
            if process.poll() is None:
                # Failure cleanup is not credited as a successful graceful drain.
                process.kill()
                process.wait(timeout=10)


def exercise(fg: str, git: str, root: Path, fmt: str, timeout: int) -> None:
    root.mkdir()
    commands = Commands(git, isolated_environment(root / "home"), timeout)
    token = secrets.token_hex(32)
    SECRETS.append(token)
    token_file = root / "token"
    private_file(token_file, token + "\n")
    commands.run([fg, "init", str(root / "state"), TENANT, REPOSITORY, fmt])
    source, initial = seed(commands, root, fmt)
    with running(fg, commands, root, ["--token-file", str(token_file), "--principal", PRINCIPAL], "static") as (url, stop, process):
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/main")
        # These lightweight requests still consume lifetime sessions, not mutation
        # quota. Genuine stock push/read operations follow the old lifetime cap.
        for _ in range(1030):
            require(exchange(url, None)[0] == 401, "unauthenticated discovery changed behavior")
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/after-limit")
        require(f"{initial}\trefs/heads/after-limit" in commands.remote_git(token, 2, "ls-remote", url).splitlines(),
                "useful work failed after the old session limit")
        stream, body = active_read(url, token, fmt)
        try:
            private_file(stop, "drain active read\n")
            # The accepting loop polls the control at most every 50 ms, while
            # this child cannot finish until we send its declared body.
            time.sleep(0.2)
            require(process.poll() is None, "service dropped a known active request")
            stream.sendall(body)
            response = http.client.HTTPResponse(stream)
            response.begin()
            result = response.read(1024 * 1024 + 1)
            require(response.status == 200 and len(result) <= 1024 * 1024
                    and initial.encode("ascii") + b" refs/heads/main\n" in result,
                    "accepted read was not completed during drain")
            response.close()
        finally:
            stream.close()
    # The same controlled lifetime must retain per-request credential reloads.
    header = commands.run([fg, "serve-http", str(root / "state"), TENANT, REPOSITORY,
                           "127.0.0.1:0", "--trusted-local", "--print-credentials-header"])
    table = root / "credentials"
    grants = header + "\n" + hashlib.sha256(token.encode()).hexdigest() + " " + PRINCIPAL + " read,receive\n"
    private_file(table, grants)
    with running(fg, commands, root, ["--credentials-file", str(table)], "reloadable") as (url, stop, _):
        require(exchange(url, token)[0] == 200, "continuous reloadable grant unavailable")
        replacement = root / "revoked"
        private_file(replacement, header + "\n")
        replacement.replace(table)
        require(exchange(url, token)[0] == 401, "continuous lifetime cached a revoked grant")
        private_file(replacement, grants)
        replacement.replace(table)
        require(exchange(url, token)[0] == 200, "restored current grant not observed")
        private_file(stop, "normal stop\n")
    print(json.dumps({"type": "continuous_http_smoke_passed", "format": fmt,
                      "over_1024_sessions": True, "known_active_child_drained": True,
                      "credential_reload": True}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--format", choices=("sha1", "sha256"), action="append", dest="formats")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    require(1 <= args.timeout <= 600, "timeout must be in 1..600")
    fg = args.fg.resolve(strict=True)
    git = shutil.which(args.git)
    require(fg.is_file() and os.access(fg, os.X_OK) and git is not None, "fg/Git executable missing")
    root = Path(tempfile.mkdtemp(prefix="fg-continuous-http-"))
    success = False
    try:
        with fg.open("rb") as binary:
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
        commands = Commands(git, isolated_environment(root / "home"), args.timeout)
        print(json.dumps({"type": "continuous_http_smoke_started", "fg_binary_sha256": digest,
                          "git_version": commands.local_git("--version")}), flush=True)
        for fmt in dict.fromkeys(args.formats or ["sha1", "sha256"]):
            exercise(str(fg), git, root / fmt, fmt, args.timeout)
        success = True
        return 0
    finally:
        if success:
            shutil.rmtree(root)
        else:
            print(f"continuous HTTP failure artifacts retained: {root}", file=sys.stderr)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(redact(f"continuous HTTP smoke FAILED: {error}"), file=sys.stderr)
        raise SystemExit(1)
