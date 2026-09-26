#!/usr/bin/env python3
"""Stock `git push` over fg serve-http through dropped connections and protection.

frankengit-root-doctrine-x2mv.4.8 acceptance 1. The client is stock git with
no extra configuration: the token is the password of an ordinary URL login.
A small TCP relay between git and the real fg serve-http can drop one
receive-pack request:

- after the request is fully delivered, when the server starts to answer
  (the push is committed, but git sees the connection die). The retry must
  find the ref already there and publish nothing: the authority generation
  (`fg doctor`) stays where the dropped attempt left it;
- before any of the request reaches the server (nothing is committed). The
  retry then publishes exactly once.

A push to a protected branch is refused through report-status, and the ref
is never created. Prints one JSON summary; the suite asserts on it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from continuous_http_smoke import private_file
from smart_http_smoke import PRINCIPAL, REPOSITORY, TENANT, isolated_environment, require

REVIEWER = "d4" * 16
TIMEOUT = 300


class Relay:
    """Forwards 127.0.0.1 TCP connections to the server; can drop one receive-pack POST."""

    def __init__(self, upstream: int):
        self.upstream = upstream
        self.mode = "pass"
        self.dropped = 0
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        threading.Thread(target=self._accept, daemon=True).start()

    def arm(self, mode: str) -> None:
        self.mode, self.dropped = mode, 0

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(client,), daemon=True).start()

    def _serve(self, client: socket.socket) -> None:
        server = socket.create_connection(("127.0.0.1", self.upstream))
        first = client.recv(65536)
        receive_post = first.startswith(b"POST ") and b"git-receive-pack" in first.split(b"\r\n", 1)[0]
        mode = self.mode if receive_post else "pass"
        if receive_post and mode != "pass":
            self.mode = "pass"
            self.dropped += 1
        if mode == "drop_before_request":
            client.close()
            server.close()
            return
        server.sendall(first)
        done = threading.Event()

        def pump(source: socket.socket, sink: socket.socket, drop_on_first: bool) -> None:
            try:
                while True:
                    data = source.recv(65536)
                    if not data:
                        break
                    if drop_on_first:
                        # The server has started its answer: the request was
                        # delivered in full. Cut both sides without relaying it.
                        break
                    sink.sendall(data)
            except OSError:
                pass
            finally:
                done.set()
                for end in (source, sink):
                    try:
                        end.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(client, server, False), daemon=True).start()
        pump(server, client, mode == "drop_after_request")
        done.wait(timeout=TIMEOUT)
        client.close()
        server.close()


def run(args: list, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in args], env=env, capture_output=True, text=True,
                          timeout=TIMEOUT)


def checked(args: list, env: dict[str, str]) -> str:
    result = run(args, env)
    require(result.returncode == 0, f"{args[:3]!r} failed: {result.stderr[-2000:]}")
    return result.stdout.strip()


def generation(fg: str, node: Path, env: dict[str, str]) -> int:
    text = checked([fg, "doctor", node, TENANT, REPOSITORY], env)
    match = re.search(r"authority head at generation (\d+)", text)
    require(match is not None, f"doctor did not report a generation: {text[:400]}")
    return int(match.group(1))


def exercise(fg: str, git: str, root: Path) -> dict:
    env = isolated_environment(root / "home")
    node = root / "node"
    checked([fg, "init", node, TENANT, REPOSITORY, "sha1"], env)
    checked([fg, "protection", "set", node, TENANT, REPOSITORY, "--trusted-local",
             "--object-format", "sha1", "--principal", PRINCIPAL,
             "--idempotency-key", "faults-protect", "--expected-version", "0",
             "--expected-epoch", "1", "--admin", PRINCIPAL,
             "--require-reviewer", f"refs/heads/protected:{REVIEWER}"], env)
    header = checked([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                      "--trusted-local", "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    table = root / "credentials"
    private_file(table, f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                 "read,receive\n")
    source = root / "source"
    checked([git, "init", "-q", "-b", "main", source], env)

    def commit(name: str) -> str:
        (source / name).write_text(f"{name}\n")
        checked([git, "-C", source, "add", name], env)
        checked([git, "-C", source, "commit", "-qm", name], env)
        return checked([git, "-C", source, "rev-parse", "HEAD"], env)

    stop, out, err = root / "serve.stop", root / "serve.out", root / "serve.err"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", table, "--allow-receive",
                          "--continuous", "--stop-file", stop]],
        env=env, stdout=out.open("w"), stderr=err.open("w"))
    summary: dict = {"type": "stock_http_push_faults_summary",
                     "git": checked([git, "--version"], env)}
    try:
        url = None
        started = time.monotonic()
        while url is None and time.monotonic() - started < 60:
            require(process.poll() is None, "serve-http exited before readiness")
            for line in out.read_text().splitlines():
                if line.startswith("{") and "smart_http_listening" in line:
                    url = json.loads(line)["url"]
            time.sleep(0.05)
        require(url is not None, "no readiness report")
        upstream = int(url.split(":")[2].split("/")[0])
        relay = Relay(upstream)
        remote = f"http://git:{token}@127.0.0.1:{relay.port}/{url.split('/', 3)[3]}"

        def push(refspec: str) -> subprocess.CompletedProcess:
            return run([git, "-C", source, "push", remote, refspec], env)

        def tip(ref: str) -> str | None:
            line = checked([git, "ls-remote", remote, ref], env)
            return line.split()[0] if line else None

        first = commit("base")
        summary["initial_push_exit"] = push("HEAD:refs/heads/main").returncode
        summary["initial_published"] = tip("refs/heads/main") == first
        g0 = generation(fg, node, env)

        # 1. The request is delivered and committed, but the reply is cut.
        second = commit("second")
        relay.arm("drop_after_request")
        dropped = push("HEAD:refs/heads/main")
        summary["drop_after_dropped_one_request"] = relay.dropped == 1
        summary["drop_after_client_failed"] = dropped.returncode != 0
        g1 = generation(fg, node, env)
        summary["drop_after_committed_once"] = g1 == g0 + 1 and tip("refs/heads/main") == second
        retry = push("HEAD:refs/heads/main")
        summary["drop_after_retry_exit"] = retry.returncode
        summary["drop_after_retry_up_to_date"] = "Everything up-to-date" in retry.stderr
        summary["drop_after_retry_not_duplicated"] = generation(fg, node, env) == g1

        # 2. Twin: the request never reaches the server, so nothing commits.
        third = commit("third")
        relay.arm("drop_before_request")
        dropped = push("HEAD:refs/heads/main")
        summary["drop_before_dropped_one_request"] = relay.dropped == 1
        summary["drop_before_client_failed"] = dropped.returncode != 0
        summary["drop_before_nothing_committed"] = (
            generation(fg, node, env) == g1 and tip("refs/heads/main") == second)
        retry = push("HEAD:refs/heads/main")
        summary["drop_before_retry_exit"] = retry.returncode
        summary["drop_before_retry_committed_once"] = (
            generation(fg, node, env) == g1 + 1 and tip("refs/heads/main") == third)

        # 3. A protected branch refuses a direct push through report-status.
        refused = push("HEAD:refs/heads/protected")
        summary["protected_push_exit"] = refused.returncode
        summary["protected_report_status_refusal"] = bool(
            re.search(r"\[remote rejected\] +HEAD -> protected", refused.stderr))
        summary["protected_ref_absent"] = tip("refs/heads/protected") is None
        stop.touch()
        process.wait(timeout=120)
        summary["server_drained_exit"] = process.returncode
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--summary", type=Path)
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-stock-push-faults-"))
    try:
        summary = exercise(str(options.fg.resolve()), options.git, root)
    except BaseException:
        print(json.dumps({"type": "stock_http_push_faults_failed", "artifacts": str(root)}),
              flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
