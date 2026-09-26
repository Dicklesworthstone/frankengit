#!/usr/bin/env python3
"""SIGTERM and SIGINT drain a continuous fg serve-http instead of ending it.

frankengit-root-doctrine-x2mv.4.8 acceptance 3. Against the real fg binary:

- SIGTERM while an authenticated read is admitted (100 Continue observed) and
  waiting for its body: the service keeps running, completes that request once
  the body arrives, then exits 0 with a drain receipt that settles every
  accepted connection;
- SIGINT against an idle service: the same clean exit, promptly.

Reuses continuous_http_smoke's request helpers. Prints one JSON summary.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import secrets
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from continuous_http_smoke import active_read, exchange, private_file
from smart_http_smoke import Commands, PRINCIPAL, REPOSITORY, SECRETS, TENANT, isolated_environment, require, seed


def start(fg: str, commands: Commands, root: Path, table: Path, label: str):
    stop = root / f"{label}.stop"
    out, err = root / f"{label}.out", root / f"{label}.err"
    args = [fg, "serve-http", str(root / "state"), TENANT, REPOSITORY, "127.0.0.1:0",
            "--trusted-local", "--credentials-file", str(table), "--allow-receive", "--continuous",
            "--stop-file", str(stop), "--max-in-flight", "2",
            "--session-timeout-secs", "30", "--processing-timeout-secs", "60"]
    process = subprocess.Popen(args, env=commands.env, stdout=out.open("w"), stderr=err.open("w"))
    end = time.monotonic() + 60
    while time.monotonic() < end:
        for line in out.read_text().splitlines():
            record = json.loads(line) if line.startswith("{") else {}
            if record.get("type") == "smart_http_listening":
                return process, record["url"], out, err
        require(process.poll() is None, "server exited before readiness")
        time.sleep(0.02)
    process.kill()
    raise RuntimeError("no readiness report")


def drained(process: subprocess.Popen, out: Path, err: Path, within: float) -> dict:
    process.wait(timeout=within)
    require(process.returncode == 0, f"signal did not end in a clean drain: {err.read_text()[-4000:]}")
    receipts = [json.loads(line) for line in out.read_text().splitlines()
                if line.startswith("{") and "smart_http_drained" in line]
    require(len(receipts) == 1, "missing or duplicate drain receipt")
    receipt = receipts[0]
    require(receipt["accepted"] == receipt["completed_transports"] + receipt["refused_transports"],
            "an accepted connection was not settled")
    require("termination signal received" in err.read_text(), "the drain cause was not reported")
    return receipt


def exercise(fg: str, git: str, root: Path) -> dict:
    root.mkdir()
    commands = Commands(git, isolated_environment(root / "home"), 180)
    token = secrets.token_hex(32)
    SECRETS.append(token)
    commands.run([fg, "init", str(root / "state"), TENANT, REPOSITORY, "sha1"])
    source, initial = seed(commands, root, "sha1")
    header = commands.run([fg, "serve-http", str(root / "state"), TENANT, REPOSITORY,
                           "127.0.0.1:0", "--trusted-local", "--print-credentials-header"])
    table = root / "credentials"
    private_file(table, header + "\n" + hashlib.sha256(token.encode()).hexdigest()
                 + " " + PRINCIPAL + " read,receive\n")
    summary: dict = {"type": "http_signal_drain_summary"}

    process, url, out, err = start(fg, commands, root, table, "term")
    try:
        require(exchange(url, token)[0] == 200, "service not serving before the signal")
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/main")
        stream, body = active_read(url, token, "sha1")
        try:
            process.send_signal(signal.SIGTERM)
            # The accept loop polls its stop condition at most every 50 ms; the
            # admitted read cannot finish until its declared body is sent.
            time.sleep(0.5)
            require(process.poll() is None, "SIGTERM ended the process instead of draining")
            stream.sendall(body)
            response = http.client.HTTPResponse(stream)
            response.begin()
            result = response.read(1024 * 1024 + 1)
            require(response.status == 200 and initial.encode("ascii") + b" refs/heads/main\n" in result,
                    "the admitted read was not completed during the drain")
            response.close()
        finally:
            stream.close()
        summary["sigterm_receipt"] = drained(process, out, err, 90)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)

    process, url, out, err = start(fg, commands, root, table, "int")
    try:
        require(exchange(url, token)[0] == 200, "second service not serving")
        started = time.monotonic()
        process.send_signal(signal.SIGINT)
        summary["sigint_receipt"] = drained(process, out, err, 30)
        summary["sigint_exit_s"] = round(time.monotonic() - started, 3)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    summary["sigterm_drained_admitted_read"] = True
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--summary", type=Path)
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-http-signal-drain-")) / "run"
    try:
        summary = exercise(str(options.fg.resolve()), options.git, root)
    except BaseException:
        print(json.dumps({"type": "http_signal_drain_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
