#!/usr/bin/env python3
"""Sequential stock fetches against one fg serve-http process.

frankengit-root-doctrine-x2mv.4.8 acceptance 2. One persisted node is served
twice by the real `fg` binary:

1. latency: N sequential stock `git fetch` runs and N raw smart-HTTP discovery
   round trips, each timed individually (raw samples are kept);
2. reopen count: M sequential stock `git fetch` runs with the server under
   `strace -f`, counting how often any server thread opens the authority
   database. A process that opens its repository node per request opens it
   at least once per HTTP connection; one that reuses opened nodes does not.

The latency phase runs without strace so tracing overhead never enters the
samples. The script records facts and prints one JSON summary;
scripts/e2e/suites/transport/smart_http_node_reuse.sh asserts on it.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path

TENANT, REPOSITORY = "d1" * 16, "d2" * 16
TIMEOUT = 600
DATABASE = "authority.fsqlite"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def git_env(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and not k.upper().endswith("_PROXY")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_NAME="Node reuse", GIT_AUTHOR_EMAIL="reuse@example.invalid",
               GIT_COMMITTER_NAME="Node reuse", GIT_COMMITTER_EMAIL="reuse@example.invalid",
               GIT_AUTHOR_DATE="2000-01-01T00:00:00+0000",
               GIT_COMMITTER_DATE="2000-01-01T00:00:00+0000")
    return env


def checked(args: list, env: dict[str, str]) -> str:
    result = subprocess.run([str(a) for a in args], env=env, capture_output=True, text=True,
                            timeout=TIMEOUT)
    require(result.returncode == 0, f"{args[:3]!r} failed: {result.stderr[-4000:]}")
    return result.stdout.strip()


@contextlib.contextmanager
def serve(fg: str, node: Path, root: Path, grants: Path, label: str, trace: Path | None):
    stop = root / f"stop-{label}"
    stdout, stderr = root / f"server-{label}.out", root / f"server-{label}.err"
    args = [fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
            "--credentials-file", grants, "--allow-receive", "--max-in-flight", "4",
            "--continuous", "--stop-file", stop]
    if trace is not None:
        args = ["strace", "-f", "-qq", "-e", "trace=open,openat,openat2", "-o", trace, *args]
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen([str(a) for a in args], stdout=out, stderr=err)
        try:
            started, ready = time.monotonic(), None
            while time.monotonic() - started < TIMEOUT and ready is None:
                for line in stdout.read_text().splitlines():
                    with contextlib.suppress(json.JSONDecodeError):
                        value = json.loads(line)
                        if value.get("type") == "smart_http_listening":
                            ready = value
                require(process.poll() is None, "HTTP server exited before readiness")
                time.sleep(0.02)
            require(ready is not None, "HTTP server never reported readiness")
            yield ready["url"]
            stop.touch(exist_ok=False)
            process.wait(timeout=180)
            require(process.returncode == 0,
                    f"server did not drain: {stderr.read_bytes()[-4000:]!r}")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def discovery(url: str, token: str) -> float:
    endpoint = urllib.parse.urlsplit(url)
    started = time.perf_counter()
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=TIMEOUT)
    try:
        connection.request("GET", endpoint.path + "/info/refs?service=git-upload-pack",
                           headers={"Authorization": f"Bearer {token}",
                                    "Git-Protocol": "version=2", "Connection": "close"})
        response = connection.getresponse()
        response.read()
        require(response.status == 200, f"discovery returned {response.status}")
    finally:
        connection.close()
    return time.perf_counter() - started


def percentile(samples: list[float], fraction: float) -> float:
    ordered = sorted(samples)
    return round(ordered[min(len(ordered) - 1, int(fraction * len(ordered)))], 6)


def database_opens(trace: Path, database: Path) -> int:
    """openat/open calls on the authority database file itself (not -wal/-shm)."""
    needle = f'"{database}"'
    return sum(1 for line in trace.read_text(errors="replace").splitlines()
               if needle in line and "open" in line and "ENOENT" not in line)


def exercise(fg: str, git: str, root: Path, fetches: int, traced: int) -> dict:
    env = git_env(root / "home")
    node = root / "node"
    checked([fg, "init", node, TENANT, REPOSITORY, "sha1"], env)
    header = checked([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                      "--trusted-local", "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    grants = root / "grants"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {'d3' * 16} "
                  "read,receive\n")
    auth = ["-c", f"http.extraHeader=Authorization: Bearer {token}"]

    source = root / "source"
    checked([git, "init", "-q", "-b", "main", source], env)
    (source / "README").write_text("node reuse\n")
    checked([git, "-C", source, "add", "README"], env)
    checked([git, "-C", source, "commit", "-qm", "base"], env)
    tip = checked([git, "-C", source, "rev-parse", "HEAD"], env)

    summary: dict = {"type": "smart_http_node_reuse_summary", "fetches": fetches,
                     "traced_fetches": traced}
    clone = root / "clone"
    with serve(fg, node, root, grants, "latency", None) as url:
        checked([git, *auth, "-C", source, "push", "-q", url, "HEAD:refs/heads/main"], env)
        checked([git, *auth, "clone", "-q", url, clone], env)
        require(checked([git, "-C", clone, "rev-parse", "refs/remotes/origin/main"], env) == tip,
                "the clone does not hold the pushed commit")
        fetch_samples = []
        for _ in range(fetches):
            started = time.perf_counter()
            checked([git, *auth, "-C", clone, "fetch", "-q", "origin"], env)
            fetch_samples.append(time.perf_counter() - started)
        discovery_samples = [discovery(url, token) for _ in range(fetches)]
    summary["fetch_seconds"] = [round(s, 6) for s in fetch_samples]
    summary["discovery_seconds"] = [round(s, 6) for s in discovery_samples]
    for name, samples in (("fetch", fetch_samples), ("discovery", discovery_samples)):
        summary[f"{name}_p50_s"] = percentile(samples, 0.50)
        summary[f"{name}_p99_s"] = percentile(samples, 0.99)

    if shutil.which("strace") is None:
        summary["reopen_evidence"] = "unsupported: strace is not installed"
        return summary
    trace = root / "openat.trace"
    with serve(fg, node, root, grants, "traced", trace) as url:
        checked([git, "-C", clone, "remote", "set-url", "origin", url], env)
        for _ in range(traced):
            checked([git, *auth, "-C", clone, "fetch", "-q", "origin"], env)
    lines = trace.read_text(errors="replace").splitlines()
    if not lines or all("ptrace" in line.lower() for line in lines[:3]):
        summary["reopen_evidence"] = "unsupported: strace could not trace the server"
        return summary
    summary["reopen_evidence"] = "strace"
    # Each stock `git fetch` makes two HTTP connections (discovery, ls-refs).
    summary["traced_connections"] = 2 * traced
    summary["database_opens"] = database_opens(trace, node / DATABASE)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--git", default="git")
    parser.add_argument("--fetches", type=int, default=1000)
    parser.add_argument("--traced-fetches", type=int, default=200)
    parser.add_argument("--summary", type=Path, help="also write the JSON summary here")
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-node-reuse-"))
    try:
        summary = exercise(options.fg, options.git, root, options.fetches,
                           options.traced_fetches)
    except BaseException:
        print(json.dumps({"type": "smart_http_node_reuse_failed", "artifacts": str(root)}),
              flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")


if __name__ == "__main__":
    main()
