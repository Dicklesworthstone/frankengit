#!/usr/bin/env python3
"""Stock `git push` reports a refused graph per ref, over HTTP and git://.

frankengit-87c7 acceptance 1 (Smart HTTP, `fg serve-http`) and
frankengit-root-doctrine-x2mv.4.49 acceptance 3 (git daemon, `fg serve
--receive-principal`). On a fresh node per transport, stock git pushes:
- an ordinary branch (the baseline);
- a commit whose tree holds a file-mode entry naming a TREE object (the
  typed-graph "file kind" case). Stock git hashes and sends it; the node's
  typed-graph validation refuses it as EvidenceInvalid. Git must print a
  `[remote rejected]` line for that ref and exit 1, and nothing publishes.
  (Stock git cannot push a ref at a missing object: it checks its own
  objects before sending, so a refused graph is the stock-client case.);
- the permitted twin: another ordinary new branch, which publishes.

Records facts as one JSON summary, keyed `<transport>_<fact>`;
suites/transport/stock_push_verdicts.sh asserts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path

from continuous_http_smoke import private_file
from smart_http_smoke import PRINCIPAL, REPOSITORY, TENANT, isolated_environment, require
from stock_http_push_faults import checked, generation, run


def source_with_refused_graph(git: str, source: Path, env: dict[str, str]) -> str:
    """A repository with one ordinary commit and a file-kind malformed child."""
    checked([git, "init", "-q", "-b", "main", source], env)
    (source / "a.txt").write_text("base\n")
    checked([git, "-C", source, "add", "a.txt"], env)
    checked([git, "-C", source, "commit", "-qm", "base"], env)
    empty_tree = checked([git, "-C", source, "hash-object", "-t", "tree", "-w", "--literally",
                          "/dev/null"], env)
    entry = b"100644 f\0" + bytes.fromhex(empty_tree)
    malformed = subprocess.run([git, "-C", str(source), "hash-object", "-t", "tree", "-w",
                                "--literally", "--stdin"], input=entry, env=env,
                               capture_output=True, timeout=60)
    require(malformed.returncode == 0, f"hash-object failed: {malformed.stderr[-500:]!r}")
    tree = malformed.stdout.decode().strip()
    return checked([git, "-C", source, "commit-tree", tree, "-p", "HEAD", "-m", "file-kind"], env)


def serve(fg: str, transport: str, node: Path, root: Path, env: dict[str, str]):
    """Start a continuous listener; return (process, remote URL, stop file, stderr path)."""
    stop, out, err = root / f"{transport}.stop", root / f"{transport}.out", root / f"{transport}.err"
    if transport == "http":
        header = checked([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                          "--trusted-local", "--print-credentials-header"], env)
        token = secrets.token_hex(32)
        table = root / "credentials"
        private_file(table, f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                     "read,receive\n")
        args = [fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                "--credentials-file", table, "--allow-receive", "--continuous", "--stop-file", stop]
        ready_type = "smart_http_listening"
    else:
        args = [fg, "serve", node, TENANT, REPOSITORY, "127.0.0.1:0", "--receive-principal",
                PRINCIPAL, "--continuous", "--stop-file", stop]
        ready_type = "git_daemon_listening"
    process = subprocess.Popen([str(a) for a in args], env=env, stdout=out.open("w"),
                               stderr=err.open("w"))
    record = None
    started = time.monotonic()
    while record is None and time.monotonic() - started < 60:
        require(process.poll() is None, f"{transport} listener exited before readiness")
        for line in out.read_text().splitlines():
            if line.startswith("{") and ready_type in line:
                record = json.loads(line)
        time.sleep(0.05)
    require(record is not None, f"no {transport} readiness report")
    if transport == "http":
        remote = f"http://git:{token}@{record['url'].split('://', 1)[1]}"
    else:
        remote = f"git://{record['address']}/{REPOSITORY}.git"
    return process, remote, stop, err


def campaign(fg: str, git: str, transport: str, root: Path, env: dict[str, str]) -> dict:
    node = root / f"{transport}-node"
    checked([fg, "init", node, TENANT, REPOSITORY, "sha1"], env)
    source = root / f"{transport}-source"
    bad = source_with_refused_graph(git, source, env)
    process, remote, stop, err = serve(fg, transport, node, root, env)
    facts: dict = {}
    try:
        def push(refspec: str) -> subprocess.CompletedProcess:
            return run([git, "-C", source, "push", remote, refspec], env)

        def tip(ref: str) -> str | None:
            line = checked([git, "ls-remote", remote, ref], env)
            return line.split()[0] if line else None

        facts["base_push_exit"] = push("HEAD:refs/heads/main").returncode
        before = generation(fg, node, env)

        refused = push(f"{bad}:refs/heads/bad")
        facts["refused_push_exit"] = refused.returncode
        facts["refused_push_stderr"] = refused.stderr[-2000:]
        facts["refused_per_ref"] = bool(re.search(
            r"\[remote rejected\] +\S+ -> bad \(object graph failed validation", refused.stderr))
        facts["refused_not_transport_error"] = not re.search(
            r"remote error|unexpected disconnect|RPC failed|the remote end hung up", refused.stderr)
        facts["refused_ref_absent"] = tip("refs/heads/bad") is None
        facts["refused_generation_unchanged"] = generation(fg, node, env) == before

        permitted = push("HEAD:refs/heads/good")
        facts["permitted_push_exit"] = permitted.returncode
        facts["permitted_published"] = tip("refs/heads/good") == checked(
            [git, "-C", source, "rev-parse", "HEAD"], env)
        facts["permitted_generation_advanced"] = generation(fg, node, env) == before + 1
        stop.touch()
        process.wait(timeout=120)
        facts["server_drained_exit"] = process.returncode
        facts["server_log"] = err.read_text()[-2000:]
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    return {f"{transport}_{key}": value for key, value in facts.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--summary", type=Path)
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-stock-push-verdicts-"))
    try:
        env = isolated_environment(root / "home")
        fg = str(options.fg.resolve())
        summary: dict = {"type": "stock_push_verdicts_summary",
                         "git": checked([options.git, "--version"], env)}
        for transport in ("http", "git"):
            summary.update(campaign(fg, options.git, transport, root, env))
        summary["http_server_log_reports_per_ref_refusal"] = (
            "refused every command per ref" in summary["http_server_log"])
    except BaseException:
        print(json.dumps({"type": "stock_push_verdicts_failed", "artifacts": str(root)}),
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
