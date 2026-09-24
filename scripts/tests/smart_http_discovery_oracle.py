#!/usr/bin/env python3
"""Exercise stock Git's discovery-redirect contract (x2mv.4.8).

This is a development-only protocol oracle using git-http-backend, NOT an
execution of FrankenGit's Rust server or canonical admission. It establishes
that an ordinary client follows authenticated discovery redirects and keeps
that attempt's URL for receive-pack, without an Idempotency-Key extraHeader.

Run with the repository's pinned oracle when available:
    GIT_ORACLE_BIN=/path/to/git python3 scripts/tests/smart_http_discovery_oracle.py

The JSON receipt records the actual Git version; an unpinned Git run must not
be represented as pinned-client conformance. No production code calls Git.
"""
from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import threading
import urllib.parse

TIMEOUT = 20
MAX_BODY = 16 * 1024 * 1024
ALIAS = re.compile(
    r"/repo\.git/\.fgit-receive/([0-9a-f]{64})/(info/refs|git-receive-pack)"
)


def require(condition: bool, message: str) -> None:
    # Assertions here must survive python -O too.
    if not condition:
        raise RuntimeError(message)


def command(
    *args: str,
    cwd: Path | None = None,
    env: dict[str, str],
    data: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        args, cwd=cwd, env=env, input=data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=TIMEOUT, check=True,
    )


def run(git: str = "git") -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="fg-http-discovery-oracle-") as directory:
        root = Path(directory)
        # Ambient Git config/work-tree/index/trace variables must not select
        # the caller's repository or disclose fixture credentials in a trace.
        env = {
            key: value for key, value in os.environ.items()
            if not key.startswith("GIT_")
            and key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
        }
        env.update(
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="Retry oracle",
            GIT_AUTHOR_EMAIL="retry@example.invalid",
            GIT_COMMITTER_NAME="Retry oracle",
            GIT_COMMITTER_EMAIL="retry@example.invalid",
            GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00",
            GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00",
            NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost",
            LC_ALL="C",
        )
        command(git, "init", "--bare", str(root / "repo.git"), env=env)
        command(
            git, "--git-dir", str(root / "repo.git"), "config",
            "http.receivepack", "true", env=env,
        )
        work = root / "client"
        command(git, "init", "--initial-branch=main", str(work), env=env)
        (work / "one.txt").write_text("one\n", encoding="utf-8")
        command(git, "add", "one.txt", cwd=work, env=env)
        command(git, "commit", "-m", "one", cwd=work, env=env)
        expected = command(git, "rev-parse", "HEAD", cwd=work, env=env).stdout.strip()
        records: list[dict[str, object]] = []
        lock = threading.Lock()
        auth = "Basic " + base64.b64encode(b"oracle:secret").decode("ascii")
        backend = str(
            Path(command(git, "--exec-path", env=env).stdout.decode().strip())
            / "git-http-backend"
        )
        require(Path(backend).is_file(), "selected Git has no git-http-backend")

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(TIMEOUT)

            def log_message(self, *args: object) -> None:
                pass

            def do_GET(self) -> None:
                self.serve()

            def do_POST(self) -> None:
                self.serve()

            def empty(self, status: int, **headers: str) -> None:
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name.replace("_", "-"), value)
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True

            def serve(self) -> None:
                parsed = urllib.parse.urlsplit(self.path)
                authorized = self.headers.get("Authorization") == auth
                with lock:
                    records.append({
                        "method": self.command, "path": self.path,
                        "authorized": authorized,
                        "explicit_key": self.headers.get("Idempotency-Key"),
                    })
                if not authorized:
                    self.empty(401, WWW_Authenticate='Basic realm="frankengit"')
                    return
                if (
                    self.command == "GET" and parsed.path == "/repo.git/info/refs"
                    and parsed.query == "service=git-receive-pack"
                    and not self.headers.get("Idempotency-Key")
                ):
                    nonce = secrets.token_hex(32)
                    self.empty(
                        307,
                        Location=(
                            f"/repo.git/.fgit-receive/{nonce}/info/refs?{parsed.query}"
                        ),
                        Cache_Control="no-store",
                        X_FrankenGit_Receive_Key=f"fg-http-v1-{nonce}",
                    )
                    return
                match = ALIAS.fullmatch(parsed.path)
                normalized = f"/repo.git/{match[2]}" if match else parsed.path
                # This small oracle deliberately refuses unsupported framing;
                # it is not a second production HTTP parser or a chunked test.
                require(
                    self.headers.get("Transfer-Encoding") is None,
                    "oracle fixture unexpectedly used transfer encoding",
                )
                length = int(self.headers.get("Content-Length", "0"))
                require(0 <= length <= MAX_BODY, "oracle body ceiling exceeded")
                body = self.rfile.read(length)
                require(len(body) == length, "truncated oracle request body")
                cgi_env = dict(
                    env, GIT_PROJECT_ROOT=str(root), GIT_HTTP_EXPORT_ALL="1",
                    PATH_INFO=normalized, QUERY_STRING=parsed.query,
                    REQUEST_METHOD=self.command, REMOTE_USER="oracle",
                    REMOTE_ADDR="127.0.0.1",
                    CONTENT_TYPE=self.headers.get("Content-Type", ""),
                    CONTENT_LENGTH=str(length), SERVER_PROTOCOL="HTTP/1.1",
                )
                result = command(backend, env=cgi_env, data=body).stdout
                headers, payload = result.split(b"\r\n\r\n", 1)
                lines = headers.decode().split("\r\n")
                status = 200
                for line in lines:
                    if line.lower().startswith("status:"):
                        status = int(line.split()[1])
                self.send_response(status)
                for line in lines:
                    name, value = line.split(":", 1)
                    if name.lower() not in ("status", "content-length", "connection"):
                        self.send_header(name, value.strip())
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(payload)
                self.close_connection = True

        # Non-daemon request threads are joined by server_close. Together with
        # socket/subprocess bounds, this makes cleanup an observed obligation.
        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

        server = Server(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            url = f"http://oracle:secret@127.0.0.1:{server.server_port}/repo.git"
            # Default redirect behavior, no custom idempotency header.
            command(git, "push", url, "HEAD:refs/heads/topic", cwd=work, env=env)
            command(git, "push", url, ":refs/heads/topic", cwd=work, env=env)
            command(git, "push", url, "HEAD:refs/heads/topic", cwd=work, env=env)
            found = command(
                git, "ls-remote", url, "refs/heads/topic", cwd=work, env=env,
            ).stdout.split()[0]
            require(found == expected, "create/delete/recreate changed the expected ref")
            with lock:
                observed = list(records)
            posts = [row for row in observed if row["method"] == "POST"]
            require(len(posts) == 3, "three distinct pushes must reach receive-pack")
            paths = [str(row["path"]) for row in posts]
            require(
                len(set(paths)) == 3,
                "create/delete/recreate must not share one attempt identity",
            )
            for row in posts:
                require(bool(row["authorized"]), "POST must authenticate independently")
                require(row["explicit_key"] is None, "client must not inject a retry header")
                match = ALIAS.fullmatch(str(row["path"]))
                require(match is not None, "Git did not retain the discovery-scoped URL")
                nonce = match[1]
                require(any(
                    record["authorized"] and record["path"] == (
                        f"/repo.git/.fgit-receive/{nonce}/info/refs"
                        "?service=git-receive-pack"
                    ) for record in observed
                ), "POST must use its own authenticated discovery route")
            return {
                "kind": "stock-client-protocol-oracle",
                "scope": "Git client behavior, not FrankenGit Rust execution or admission",
                "git": command(git, "--version", env=env).stdout.decode().strip(),
                "pushes": len(posts), "distinct_attempts": len(set(paths)),
                "final_ref": found.decode(), "requests": observed,
            }
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=TIMEOUT)
            require(not thread.is_alive(), "oracle server did not drain")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git", default=os.environ.get("GIT_ORACLE_BIN", "git"))
    args = parser.parse_args()
    print(json.dumps(run(args.git), indent=2))
