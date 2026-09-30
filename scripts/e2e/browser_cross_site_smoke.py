#!/usr/bin/env python3
"""A page on another origin cannot make Chrome change repository state.

frankengit-root-doctrine-x2mv.4.31. A persisted node with one imported commit
is served by the real `fg serve-http` with the issue and source surfaces
enabled. A second loopback listener serves an attacker page holding an issue
form aimed at the served API. browser_cross_site_probe.mjs loads that page in
an installed Chrome from another site and from the same site on another port,
posts the form both by fetch and by top-level submission, then makes the
permitted twins from the served issue and history pages with their own
clients. Afterwards a non-browser read lists the repository's issues.

Records facts as one JSON summary; suites/browser/cross_site.sh asserts.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
import secrets
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from browser_client_fetch_smoke import PRINCIPAL, REPOSITORY, TENANT, TIMEOUT, checked, require, seed


def attacker(page: bytes) -> http.server.ThreadingHTTPServer:
    """A loopback listener that serves only the attacker page."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server protocol
            if self.path != "/attack.html":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def log_message(self, *_: object) -> None:
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def issues(base: str, token: str) -> dict:
    """The repository's issue list, read by a client that is not a browser."""
    endpoint = urlsplit(base)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=TIMEOUT)
    try:
        connection.request("GET", endpoint.path + "api/v1/issues", headers={"Authorization": f"Bearer {token}"})
        reply = connection.getresponse()
        body = reply.read()
        require(reply.status == 200, f"issue list answered {reply.status}: {body[:300]!r}")
        return json.loads(body)
    finally:
        connection.close()


def exercise(fg: str, chrome: str, node: str, root: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    state = root / "node"
    seed(root / "source")
    checked([fg, "init", state, TENANT, REPOSITORY, "sha1"], env)
    checked([fg, "import", state, TENANT, REPOSITORY, PRINCIPAL, "cross-site-fixture", root / "source"], env)
    header = checked([fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                      "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    grants = root / "grants"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                  "read,issues-read,issues-write\n")
    stop, out_path, err_path = root / "serve.stop", root / "serve.out", root / "serve.err"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", grants, "--allow-issues",
                          "--allow-source", "--continuous", "--stop-file", stop]],
        env=env, stdout=out_path.open("w"), stderr=err_path.open("w"))
    summary: dict = {"type": "browser_cross_site_summary"}
    page_server = None
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
        base = url.rstrip("/") + "/"
        # Issue 2 is the forged target; the permitted twin opens issue 1.
        page = (f'<!doctype html><title>attacker</title><form method="post" action="{base}api/v1/issues/2/open">'
                '<input name="expected_version" value="0"><input name="title" value="forged">'
                '<input name="body" value="forged"></form>\n').encode()
        page_server = attacker(page)
        attacker_port = page_server.server_address[1]
        summary["attacker_port"] = attacker_port
        probe = subprocess.run(
            [node, "--experimental-websocket", str(Path(__file__).with_name("browser_cross_site_probe.mjs")),
             chrome, base, token, str(root / "chrome-profile"), str(attacker_port)],
            capture_output=True, text=True, timeout=TIMEOUT)
        lines = [line for line in probe.stdout.splitlines() if line.startswith("{")]
        require(lines, f"probe printed nothing: {probe.stderr[-2000:]}")
        summary["browser"] = json.loads(lines[-1])
        summary["browser_probe_exit"] = probe.returncode
        listed = issues(base, token)
        summary["issues"] = [{"number": i.get("number"), "title": i.get("title")} for i in listed.get("issues", [])]
        stop.touch()
        process.wait(timeout=120)
        summary["server_drained_exit"] = process.returncode
    finally:
        if page_server is not None:
            page_server.shutdown()
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
    root = Path(tempfile.mkdtemp(prefix="fg-browser-cross-site-"))
    try:
        summary = exercise(str(options.fg.resolve()), options.chrome, options.node, root)
    except BaseException:
        print(json.dumps({"type": "browser_cross_site_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
