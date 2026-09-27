#!/usr/bin/env python3
"""Each browser API client makes one real request from its served page in Chrome.

frankengit-root-doctrine-x2mv.4.45 acceptance 4. A persisted node with one
imported commit is served by the real `fg serve-http` with the issues, pulls
and source surfaces enabled. browser_client_fetch_probe.mjs loads each client's
page in an installed Chrome and, in that page, constructs the page's own client
with its production defaults (the platform fetch) and performs one read.

Records facts as one JSON summary; suites/browser/client_fetch.sh asserts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import subprocess
import tempfile
import time
import zlib
from pathlib import Path

TENANT, REPOSITORY, PRINCIPAL = "c1" * 16, "c2" * 16, "c3" * 16
TIMEOUT = 300


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def checked(args: list, env: dict[str, str]) -> str:
    result = subprocess.run([str(a) for a in args], env=env, capture_output=True, text=True, timeout=TIMEOUT)
    require(result.returncode == 0, f"{[str(a) for a in args[:3]]!r} failed: {result.stderr[-2000:]}")
    return result.stdout.strip()


def seed(root: Path) -> None:
    """A bare SHA-1 repository with one commit on refs/heads/main, as loose objects."""
    (root / "refs/heads").mkdir(parents=True)
    (root / "HEAD").write_text("ref: refs/heads/main\n")
    (root / "config").write_text("[core]\nbare = true\nrepositoryformatversion = 0\n")

    def store(kind: str, body: bytes) -> str:
        raw = f"{kind} {len(body)}\0".encode() + body
        oid = hashlib.sha1(raw).hexdigest()
        path = root / "objects" / oid[:2] / oid[2:]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(zlib.compress(raw))
        return oid

    blob = store("blob", b"client fetch fixture\n")
    tree = store("tree", b"100644 README\0" + bytes.fromhex(blob))
    commit = store("commit", (f"tree {tree}\n"
                              "author Fixture <fixture@example.invalid> 1 +0000\n"
                              "committer Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n").encode())
    (root / "refs/heads/main").write_text(commit + "\n")


def exercise(fg: str, chrome: str, node: str, root: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    state = root / "node"
    seed(root / "source")
    checked([fg, "init", state, TENANT, REPOSITORY, "sha1"], env)
    checked([fg, "import", state, TENANT, REPOSITORY, PRINCIPAL, "client-fetch-fixture", root / "source"], env)
    header = checked([fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                      "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    grants = root / "grants"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                  "read,issues-read,pulls-read\n")
    stop, out_path, err_path = root / "serve.stop", root / "serve.out", root / "serve.err"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", grants, "--allow-issues",
                          "--allow-pulls", "--allow-source", "--continuous", "--stop-file", stop]],
        env=env, stdout=out_path.open("w"), stderr=err_path.open("w"))
    summary: dict = {"type": "browser_client_fetch_summary"}
    try:
        url = None
        started = time.monotonic()
        while url is None and time.monotonic() - started < 60:
            require(process.poll() is None, "serve-http exited before readiness")
            for line in out_path.read_text().splitlines():
                if line.startswith("{") and "smart_http_listening" in line:
                    url = json.loads(line)["url"]
            time.sleep(0.05)
        require(url is not None, "no readiness report")
        probe = subprocess.run(
            [node, "--experimental-websocket", str(Path(__file__).with_name("browser_client_fetch_probe.mjs")),
             chrome, url.rstrip("/") + "/", token, str(root / "chrome-profile")],
            capture_output=True, text=True, timeout=TIMEOUT)
        lines = [line for line in probe.stdout.splitlines() if line.startswith("{")]
        require(lines, f"probe printed nothing: {probe.stderr[-2000:]}")
        summary["browser"] = json.loads(lines[-1])
        summary["browser_probe_exit"] = probe.returncode
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
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--summary", type=Path)
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-browser-client-fetch-"))
    try:
        summary = exercise(str(options.fg.resolve()), options.chrome, options.node, root)
    except BaseException:
        print(json.dumps({"type": "browser_client_fetch_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
