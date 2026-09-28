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
import zlib
from pathlib import Path

TENANT, REPOSITORY, PRINCIPAL = "b1" * 16, "b2" * 16, "b3" * 16
TIMEOUT = 300
# Benign structure the rendering must keep, and hostile constructs it must
# neutralise. Each hostile construct would set window.__fgitPwned if active.
BODY = """## heading-marker

Some **bold-marker** and *em-marker* text with a [safe-link](https://example.com/ok).

- list-marker
- ünïcode-marker `cödé`

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


def span_facts(presentation: dict) -> dict:
    """Check every api_json node span against the canonical body's exact bytes."""
    facts: dict = {"api_json_profile": presentation.get("profile"),
                   "api_json_source_sha256_matches":
                       presentation.get("source_sha256") == hashlib.sha256(BODY.encode()).hexdigest()}
    content = presentation.get("content")
    if not content:
        facts["api_json_refusal"] = presentation.get("refusal")
        return facts
    source = BODY.encode()
    nodes = json.loads(content).get("nodes", [])
    bad, texts = [], []
    for node in nodes:
        span = node.get("span") or {}
        start, end = span.get("byte_start", -1), span.get("byte_end", -1)
        ok = 0 <= start <= end <= len(source)
        if ok:
            try:
                text = source[start:end].decode()
                ok = (len(source[:start].decode()) == span.get("char_start")
                      and len(source[:end].decode()) == span.get("char_end"))
            except UnicodeDecodeError:
                ok = False
        if not ok:
            bad.append(node.get("id"))
        else:
            texts.append([node.get("kind"), text])
    facts["api_json_nodes"] = len(nodes)
    facts["api_json_bad_spans"] = bad
    facts["api_json_span_texts"] = texts
    return facts


def seed(root: Path) -> dict:
    """A bare SHA-1 source with main and a topic branch one commit ahead."""
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

    def commit(tree: str, parents: list[str], message: str) -> str:
        return store("commit", (f"tree {tree}\n" + "".join(f"parent {p}\n" for p in parents)
                                + "author Fixture <fixture@example.invalid> 1 +0000\n"
                                + "committer Fixture <fixture@example.invalid> 1 +0000\n\n"
                                + message + "\n").encode())

    base_tree = store("tree", b"100644 README\0" + bytes.fromhex(store("blob", b"base\n")))
    topic_tree = store("tree", b"100644 README\0" + bytes.fromhex(store("blob", b"topic\n")))
    main = commit(base_tree, [], "base")
    topic = commit(topic_tree, [main], "topic")
    (root / "refs/heads/main").write_text(main + "\n")
    (root / "refs/heads/topic").write_text(topic + "\n")
    return {"main": main, "topic": topic}


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
    tips = seed(root / "source")
    checked([fg, "import", state, TENANT, REPOSITORY, PRINCIPAL, "browser-markdown-fixture",
             root / "source"], env)
    header = checked([fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                      "--trusted-local", "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    grants = root / "grants"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                  "read,issues-read,issues-write,pulls-read,pulls-write\n")
    stop, out_path, err_path = root / "serve.stop", root / "serve.out", root / "serve.err"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", grants, "--allow-issues",
                          "--allow-pulls", "--continuous", "--stop-file", stop]],
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
        status_tree, tree_reply = api(url, "/api/v1/issues/1?render=api_json", token)
        summary["http_api_json_status"] = status_tree
        summary.update(span_facts(json.loads(tree_reply).get("issue", {}).get("body_rendered") or {}))
        summary["http_ui_status"], summary["http_ui_csp"] = document_csp(url, "/ui/issues/")
        status_pr, pr_reply = api(url, "/api/v1/pulls/1/open", token,
                                  {"expected_version": "0", "object_format": "sha1",
                                   "source_ref": "refs/heads/topic", "target_ref": "refs/heads/main",
                                   "source_tip": tips["topic"], "target_tip": tips["main"],
                                   "title": "Markdown PR under CSP", "body": BODY},
                                  key="browser-markdown-pr-open")
        summary["http_pr_open_status"] = status_pr
        summary["http_pr_open_reply"] = pr_reply[:300] if status_pr != 200 else None
        status_pr_read, pr_read = api(url, "/api/v1/pulls/1?render=html_safe", token)
        pr_data = (json.loads(pr_read).get("pull_request") or {}).get("data") or {} if status_pr_read == 200 else {}
        pr_presentation = pr_data.get("body_rendered") or {}
        summary["http_pr_rendered_status"] = status_pr_read
        summary["http_pr_body_unchanged"] = pr_data.get("body") == BODY
        summary["http_pr_rendered_html"] = pr_presentation.get("html")
        summary["http_pr_source_sha256_matches"] = (
            pr_presentation.get("source_sha256") == hashlib.sha256(BODY.encode()).hexdigest())
        summary["http_pulls_ui_status"], summary["http_pulls_ui_csp"] = document_csp(url, "/ui/pulls/")

        probe = subprocess.run(
            [node, "--experimental-websocket", str(Path(__file__).with_name("browser_issue_markdown_probe.mjs")),
             chrome, f"{url}/ui/issues/", token, "1", str(root / "chrome-profile"),
             f"{url}/ui/pulls/", "1"],
            capture_output=True, text=True, timeout=TIMEOUT)
        lines = [line for line in probe.stdout.splitlines() if line.startswith("{")]
        require(lines, f"probe printed nothing: {probe.stderr[-2000:]}")
        summary["browser"] = json.loads(lines[-1])
        summary["browser_probe_exit"] = probe.returncode
        stop.touch()
        process.wait(timeout=120)
        summary["server_drained_exit"] = process.returncode
        # Determinism across processes: a second server process over the same
        # persisted node must derive byte-identical presentations.
        summary["cross_process"] = second_process_presentations(
            fg, env, state, grants, token, root,
            {"html_safe": presentation, "api_json": json.loads(tree_reply).get("issue", {}).get("body_rendered")})
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    return summary


def second_process_presentations(fg: str, env: dict[str, str], state: Path, grants: Path,
                                 token: str, root: Path, first: dict) -> dict:
    stop, out_path = root / "serve2.stop", root / "serve2.out"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", grants, "--allow-issues",
                          "--allow-pulls", "--continuous", "--stop-file", stop]],
        env=env, stdout=out_path.open("w"), stderr=(root / "serve2.err").open("w"))
    try:
        url = None
        started = time.monotonic()
        while url is None and time.monotonic() - started < 60:
            require(process.poll() is None, "second serve-http exited before readiness")
            for line in out_path.read_text().splitlines():
                if line.startswith("{") and "smart_http_listening" in line:
                    url = json.loads(line)["url"]
            time.sleep(0.05)
        require(url is not None, "no readiness report from the second server")
        facts = {}
        for profile, earlier in first.items():
            status, reply = api(url, f"/api/v1/issues/1?render={profile}", token)
            later = json.loads(reply).get("issue", {}).get("body_rendered")
            facts[profile] = status == 200 and earlier is not None and later == earlier
        stop.touch()
        process.wait(timeout=120)
        facts["drained_exit"] = process.returncode
        return facts
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


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
