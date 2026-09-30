#!/usr/bin/env python3
"""Every served page boots, connects, reads and writes in a real Chrome.

frankengit-root-doctrine-x2mv.4.46. One persisted node is seeded with a real
repository through stock git and `fg import`:
- three commits on main;
- `feature` and `topic` branches, one commit each off the second commit;
- a lightweight and an annotated tag;
- one issue and one pull request, opened through the HTTP API.
A full bundle of a `bundled` branch, made after the import, carries a commit
the node has never held, for the transfers page.

It is served by the real `fg serve-http` with every browser surface enabled.
browser_pages_probe.mjs drives each page through its own controls:
- a full-scope read;
- the same read, or the same write, with a token lacking the scope (the
  forbidden twin);
- then the write with the full token.
Afterwards this script reads every outcome back from the node, never from the
page: the forge rows through the HTTP API, and every ref and commit through a
stock git mirror clone, checked with `git fsck --strict`.

`--only` limits the run to named scenarios, as a development aid; the suite
always runs every page.

Records one JSON summary; suites/browser/pages.sh asserts.
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
from pathlib import Path

from browser_markdown_smoke import api, document_csp
from browser_client_fetch_smoke import require

TENANT, REPOSITORY, PRINCIPAL = "d1" * 16, "d2" * 16, "d3" * 16
TIMEOUT = 600
FULL_SCOPES = ("read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,"
               "reviews-read,reviews-write,merges-write")
READ_SCOPES = "read,issues-read,outcomes-read,pulls-read,reviews-read"
# No repository read at all: the forbidden twin of every read-only page.
OTHER_SCOPES = "issues-read"


def run(args: list, env: dict[str, str], cwd: Path | None = None) -> str:
    result = subprocess.run([str(a) for a in args], env=env, cwd=cwd, capture_output=True,
                            text=True, timeout=TIMEOUT)
    require(result.returncode == 0, f"{[str(a) for a in args[:4]]!r} failed: {result.stderr[-2000:]}")
    return result.stdout.strip()


def git_env(root: Path) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(HOME=str(root / "home"), GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_NAME="Pages Fixture", GIT_AUTHOR_EMAIL="pages@example.invalid",
               GIT_COMMITTER_NAME="Pages Fixture", GIT_COMMITTER_EMAIL="pages@example.invalid",
               GIT_AUTHOR_DATE="1700000000 +0000", GIT_COMMITTER_DATE="1700000000 +0000")
    (root / "home").mkdir(parents=True, exist_ok=True)
    return env


def seed(source: Path, env: dict[str, str]) -> dict:
    """A loose repository (fg import refuses packs) with branches and tags."""
    run(["git", "init", "-q", "-b", "main", source], env)
    for key, value in (("gc.auto", "0"), ("maintenance.auto", "false")):
        run(["git", "-C", source, "config", key, value], env)

    def commit(message: str, files: dict[str, str]) -> str:
        for name, text in files.items():
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        run(["git", "-C", source, "add", "-A"], env)
        run(["git", "-C", source, "commit", "-qm", message], env)
        return run(["git", "-C", source, "rev-parse", "HEAD"], env)

    first = commit("initial layout", {
        "README": "Pages fixture\nThe needle word is gazpacho.\n",
        "src/lib.rs": "pub fn answer() -> u32 {\n    42\n}\n",
        "docs/guide.md": "# Guide\n\nRead the source.\n",
    })
    second = commit("extend the guide", {"docs/guide.md": "# Guide\n\nRead the source twice.\n"})
    run(["git", "-C", source, "tag", "v1-light", first], env)
    run(["git", "-C", source, "tag", "-a", "v1", "-m", "release one", second], env)
    run(["git", "-C", source, "checkout", "-q", "-b", "feature"], env)
    feature = commit("feature work", {"src/feature.rs": "pub fn feature() {}\n"})
    run(["git", "-C", source, "checkout", "-q", "-b", "topic", second], env)
    topic = commit("topic work", {"src/topic.rs": "pub fn topic() {}\n"})
    run(["git", "-C", source, "checkout", "-q", "main"], env)
    main = commit("main moves on", {"README": "Pages fixture\nThe needle word is gazpacho.\nMore.\n"})
    return {"first": first, "second": second, "main": main, "feature": feature, "topic": topic}


def bundle(source: Path, env: dict[str, str], out: Path) -> str:
    """A full bundle of a branch whose tip the node has never seen."""
    run(["git", "-C", source, "checkout", "-q", "-b", "bundled", "main"], env)
    (source / "bundled.txt").write_text("Carried in by a bundle.\n")
    run(["git", "-C", source, "add", "bundled.txt"], env)
    run(["git", "-C", source, "commit", "-qm", "bundled work"], env)
    tip = run(["git", "-C", source, "rev-parse", "HEAD"], env)
    run(["git", "-C", source, "checkout", "-q", "main"], env)
    run(["git", "-C", source, "bundle", "create", out, "refs/heads/bundled"], env)
    return tip


def grant(path: Path, header: str, rows: list[tuple[str, str]]) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(header + "\n")
        for token, scopes in rows:
            out.write(f"{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} {scopes}\n")


def exercise(fg: str, chrome: str, node: str, root: Path, only: list[str]) -> dict:
    env = git_env(root)
    state = root / "node"
    tips = seed(root / "source", env)
    run([fg, "init", state, TENANT, REPOSITORY, "sha1"], env)
    run([fg, "import", state, TENANT, REPOSITORY, PRINCIPAL, "pages-fixture", root / "source"], env)
    tips["bundled"] = bundle(root / "source", env, root / "bundled.bundle")
    header = run([fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                  "--print-credentials-header"], env)
    tokens = {"full": secrets.token_hex(32), "read": secrets.token_hex(32),
              "other": secrets.token_hex(32)}
    grants = root / "grants"
    grant(grants, header, [(tokens["full"], FULL_SCOPES), (tokens["read"], READ_SCOPES),
                           (tokens["other"], OTHER_SCOPES)])
    stop, out_path, err_path = root / "serve.stop", root / "serve.out", root / "serve.err"
    process = subprocess.Popen(
        [str(a) for a in [fg, "serve-http", state, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--credentials-file", grants, "--allow-receive",
                          "--allow-issues", "--allow-pulls", "--allow-source", "--allow-outcomes",
                          "--continuous", "--stop-file", stop]],
        env=env, stdout=out_path.open("w"), stderr=err_path.open("w"))
    summary: dict = {"type": "browser_pages_summary", "tips": tips}
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
        status, reply = api(base.rstrip("/"), "/api/v1/issues/1/open", tokens["full"],
                            {"expected_version": "0", "title": "Seeded issue", "body": "Seeded body."},
                            key="pages-seed-issue")
        require(status == 200, f"seed issue failed: {status} {reply[:400]}")
        status, reply = api(base.rstrip("/"), "/api/v1/pulls/1/open", tokens["full"],
                            {"expected_version": "0", "object_format": "sha1",
                             "source_ref": "refs/heads/feature", "target_ref": "refs/heads/main",
                             "source_tip": tips["feature"], "target_tip": tips["main"],
                             "title": "Seeded pull request", "body": "Seeded PR body."},
                            key="pages-seed-pull")
        require(status == 200, f"seed pull request failed: {status} {reply[:400]}")
        summary["ui_status"], summary["ui_csp"] = document_csp(base.rstrip("/"), "/ui/")
        probe_config = root / "probe.json"
        probe_config.write_text(json.dumps({
            "chrome": chrome, "profileDir": str(root / "chrome-profile"), "base": base,
            "tokens": tokens, "seed": dict(tips, tenant=TENANT, repository=REPOSITORY),
            "files": {"bundle": str(root / "bundled.bundle")}, "only": only,
        }))
        probe = subprocess.run(
            [node, "--experimental-websocket", str(Path(__file__).with_name("browser_pages_probe.mjs")),
             probe_config], capture_output=True, text=True, timeout=TIMEOUT * 3)
        lines = [line for line in probe.stdout.splitlines() if line.startswith("{")]
        require(lines, f"probe printed nothing: {probe.stderr[-2000:]}")
        summary["browser"] = json.loads(lines[-1])
        summary["browser_probe_exit"] = probe.returncode
        summary["canonical"] = canonical(base.rstrip("/"), tokens["full"], env, root)
        stop.touch()
        process.wait(timeout=120)
        summary["server_drained_exit"] = process.returncode
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    return summary


def canonical(url: str, token: str, env: dict[str, str], root: Path) -> dict:
    """What the node says after the probe, never what a page displayed.

    The forge rows come from the HTTP API. Every ref and the shape of every
    commit a page wrote come from a stock git clone of the served repository,
    so a page cannot vouch for itself.
    """
    facts: dict = {}
    status, body = api(url, "/api/v1/issues", token)
    facts["issues_status"] = status
    facts["issues"] = sorted([row["number"], row["version"], row["title"]]
                             for row in json.loads(body)["issues"]) if status == 200 else body[:400]
    status, body = api(url, "/api/v1/pulls", token)
    facts["pulls_status"] = status
    facts["pulls"] = sorted([row["number"], row["version"], (row.get("data") or {}).get("title")]
                            for row in json.loads(body)["pull_requests"]) if status == 200 else body[:400]
    clone = root / "clone"
    run(["git", "-c", f"http.extraHeader=Authorization: Bearer {token}", "clone", "-q", "--mirror",
         url + "/", clone], env)
    listing = run(["git", "-C", clone, "for-each-ref", "--format=%(refname) %(objectname)"], env)
    facts["refs"] = dict(line.split(" ", 1) for line in listing.splitlines())

    def shape(rev: str) -> dict:
        parents = run(["git", "-C", clone, "rev-list", "--parents", "-n", "1", rev], env).split()[1:]
        files = run(["git", "-C", clone, "ls-tree", "-r", "--name-only", rev], env).splitlines()
        subject = run(["git", "-C", clone, "log", "-1", "--format=%s", rev], env)
        return {"commit": run(["git", "-C", clone, "rev-parse", rev], env), "parents": parents,
                "files": files, "subject": subject}

    for ref in ("refs/heads/main", "refs/heads/main~1", "refs/heads/fresh", "refs/heads/feature"):
        try:
            facts[ref] = shape(ref)
        except RuntimeError as error:
            facts[ref] = {"error": str(error)[:400]}
    fsck = subprocess.run(["git", "-C", str(clone), "fsck", "--strict", "--no-dangling"], env=env,
                          capture_output=True, text=True, timeout=TIMEOUT)
    facts["fsck"] = {"exit": fsck.returncode, "stderr": fsck.stderr[-800:]}
    return facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--node", default="node")
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--only", action="append", default=[],
                        help="run only this page scenario (repeatable; development aid)")
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-browser-pages-"))
    try:
        summary = exercise(str(options.fg.resolve()), options.chrome, options.node, root, options.only)
    except BaseException:
        print(json.dumps({"type": "browser_pages_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
