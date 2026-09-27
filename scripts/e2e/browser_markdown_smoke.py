#!/usr/bin/env python3
"""Rendered issue Markdown in the real browser shell, under its real CSP.

frankengit-root-doctrine-x2mv.4.11 acceptance 1 and 4. A persisted node is
served by the real `fg serve-http`. An issue whose body mixes benign Markdown
with hostile HTML/SVG/URL constructs is opened over HTTP, then read back over
HTTP (render=html_safe) and through the browser shell in an installed Chrome,
driven by browser_issue_markdown_probe.mjs over the DevTools protocol.

Records facts as one JSON summary; suites/forge/browser_markdown_csp.sh asserts.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import secrets
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

TENANT, REPOSITORY, PRINCIPAL = "b1" * 16, "b2" * 16, "b3" * 16
TIMEOUT = 300
# Benign structure the rendering must keep, and hostile constructs it must
# neutralise. Each hostile construct would set window.__fgitPwned if active.
BODY = """## heading-marker

Some **bold-marker** and *em-marker* text with a [safe-link](https://example.com/ok).

- list-marker

<script>window.__fgitPwned = 'script'</script>

<img src="x" onerror="window.__fgitPwned = 'img'">

[js-link](javascript:window.__fgitPwned='link')

<svg><script>window.__fgitPwned = 'svg'</script></svg>

![data-image](data:text/html,<script>window.__fgitPwned='data'</script>)
"""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def run(args: list, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in args], env=env, capture_output=True, text=True,
                          timeout=TIMEOUT)


def checked(args: list, env: dict[str, str]) -> str:
    result = run(args, env)
    require(result.returncode == 0, f"{args[:3]!r} failed: {result.stderr[-2000:]}")
    return result.stdout.strip()


def api(url: str, path: str, token: str, fields: dict | None = None,
        key: str | None = None) -> tuple[int, str]:
    endpoint = urllib.parse.urlsplit(url)
    headers = {"Connection": "close", "Authorization": f"Bearer {token}"}
    body = None
    if key is not None:
        headers["Idempotency-Key"] = key
    if fields is not None:
        body = urllib.parse.urlencode(fields).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=TIMEOUT)
    try:
        connection.request("GET" if fields is None else "POST", endpoint.path + path,
                           body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read().decode("utf-8", "replace")
    finally:
        connection.close()


def document_csp(url: str, path: str) -> tuple[int, str | None]:
    """The Content-Security-Policy the server sends for one UI document."""
    endpoint = urllib.parse.urlsplit(url)
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=TIMEOUT)
    try:
        connection.request("GET", endpoint.path + path, headers={"Connection": "close"})
        response = connection.getresponse()
        response.read()
        return response.status, response.getheader("Content-Security-Policy")
    finally:
        connection.close()


def exercise(fg: str, chrome: str, node: str, root: Path) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    state = root / "node"
    checked([fg, "init", state, TENANT, REPOSITORY, "sha1"], env)
    header = checked([fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                      "--trusted-local", "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    grants = root / "grants"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                  "read,issues-read,issues-write\n")
    stop, out_path, err_path = root / "serve.stop", root / "serve.out", root / "serve.err"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", grants, "--allow-issues",
                          "--continuous", "--stop-file", stop]],
        env=env, stdout=out_path.open("w"), stderr=err_path.open("w"))
    summary: dict = {"type": "browser_markdown_summary"}
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
        status, reply = api(url, "/api/v1/issues/1/open", token,
                            {"expected_version": "0", "title": "Markdown under CSP", "body": BODY},
                            key="browser-markdown-open")
        require(status == 200, f"issue open failed: {status} {reply[:400]}")
        status, plain = api(url, "/api/v1/issues/1", token)
        status_rendered, rendered = api(url, "/api/v1/issues/1?render=html_safe", token)
        summary["http_plain_status"], summary["http_rendered_status"] = status, status_rendered
        issue = json.loads(rendered).get("issue", {})
        summary["http_canonical_body_unchanged"] = (
            json.loads(plain).get("issue", {}).get("body") == BODY and issue.get("body") == BODY)
        presentation = issue.get("body_rendered") or {}
        summary["http_source_sha256_matches"] = (
            presentation.get("source_sha256") == hashlib.sha256(BODY.encode()).hexdigest())
        summary["http_rendered_html"] = presentation.get("html")
        summary["http_ui_status"], summary["http_ui_csp"] = document_csp(url, "/ui/issues/")

        probe = subprocess.run(
            [node, "--experimental-websocket", str(Path(__file__).with_name("browser_issue_markdown_probe.mjs")),
             chrome, f"{url}/ui/issues/", token, "1", str(root / "chrome-profile")],
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
    root = Path(tempfile.mkdtemp(prefix="fg-browser-markdown-"))
    try:
        summary = exercise(str(options.fg.resolve()), options.chrome, options.node, root)
    except BaseException:
        print(json.dumps({"type": "browser_markdown_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
