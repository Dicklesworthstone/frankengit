#!/usr/bin/env python3
"""A stock `git fetch` of a changed large file receives a thin pack.

frankengit-pazc acceptance 2 (and the served half of 3). Over `fg serve`
(git://) and `fg serve-http`, and over protocol 0, 1 and 2, a stock clone is
brought one commit behind: a 60,000-line file shifted by a few lines. Then
`git fetch` runs, and the raw received pack is captured (GIT_TRACE_PACKFILE).
Recorded facts:
- the received pack's size, and the raw clone pack's size for scale;
- that the fetched head equals the source head;
- that `git fsck --strict` passes: stock git completed the thin pack against
  the objects it holds.

The twin, over git://: `git fetch-pack` without `--thin` asks for a
self-contained pack. `git index-pack --stdin` (no --fix-thin) must accept it
alone, which a thin pack would fail.

Records one JSON summary; suites/transport/thin_fetch.sh asserts.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path

from smart_http_smoke import TENANT, REPOSITORY, isolated_environment, require
from stock_http_push_faults import checked, run
from stock_push_verdicts import serve

LINES = 60_000


def write_file(path: Path, shift: int) -> None:
    path.write_text("".join(
        f"line {line:07d} of a large line-oriented file that changes by a shift\n"
        for line in range(shift, shift + LINES)))


def campaign(fg: str, git: str, transport: str, root: Path, env: dict[str, str]) -> dict:
    node = root / f"{transport}-node"
    checked([fg, "init", node, TENANT, REPOSITORY, "sha1"], env)
    source = root / f"{transport}-source"
    checked([git, "init", "-q", "-b", "main", source], env)
    write_file(source / "big.txt", 0)
    checked([git, "-C", source, "add", "big.txt"], env)
    checked([git, "-C", source, "commit", "-qm", "base"], env)
    process, remote, stop, _err = serve(fg, transport, node, root, env)
    facts: dict = {}
    try:
        checked([git, "-C", source, "push", "-q", remote, "main:refs/heads/main"], env)
        for protocol in (0, 1, 2):
            label = f"v{protocol}"
            clone = root / f"{transport}-{label}.git"
            clone_pack = root / f"{transport}-{label}-clone.pack"
            checked([git, "-c", f"protocol.version={protocol}", "clone", "-q", "--bare",
                     remote, clone], dict(env, GIT_TRACE_PACKFILE=str(clone_pack)))
            # The raw received clone pack: a small clone may be stored loose.
            clone_bytes = clone_pack.stat().st_size
            write_file(source / "big.txt", protocol + 3)
            checked([git, "-C", source, "commit", "-qam", f"shift for {label}"], env)
            checked([git, "-C", source, "push", "-q", remote, "main:refs/heads/main"], env)
            received = root / f"{transport}-{label}.pack"
            fetch_env = dict(env, GIT_TRACE_PACKFILE=str(received))
            fetched = run([git, "-C", clone, "-c", f"protocol.version={protocol}", "fetch", "-q",
                           "--no-tags", remote, "main:refs/heads/main"], fetch_env)
            facts[f"{label}_fetch_exit"] = fetched.returncode
            facts[f"{label}_received_pack_bytes"] = received.stat().st_size if received.exists() else None
            facts[f"{label}_clone_pack_bytes"] = clone_bytes
            head = checked([git, "-C", clone, "rev-parse", "refs/heads/main"], env)
            facts[f"{label}_head_matches"] = head == checked([git, "-C", source, "rev-parse", "HEAD"], env)
            facts[f"{label}_fsck_exit"] = run([git, "-C", clone, "fsck", "--strict"], env).returncode
        if transport == "git":
            # Twin: fetch-pack without --thin asks for a self-contained pack,
            # which index-pack must accept alone (no --fix-thin).
            stale = root / "git-twin.git"
            checked([git, "init", "-q", "--bare", stale], env)
            base = checked([git, "-C", source, "rev-parse", "HEAD~1"], env)
            checked([git, "-C", source, "push", "-q", stale, f"{base}:refs/heads/main"], env)
            twin_pack = root / "git-twin.pack"
            twin_env = dict(env, GIT_TRACE_PACKFILE=str(twin_pack))
            twin = run([git, "-C", stale, "fetch-pack", "--no-progress", remote, "refs/heads/main"],
                       twin_env)
            facts["twin_fetch_pack_exit"] = twin.returncode
            facts["twin_received_pack_bytes"] = twin_pack.stat().st_size if twin_pack.exists() else None
            index_dir = root / "git-twin-index.git"
            checked([git, "init", "-q", "--bare", index_dir], env)
            indexed = subprocess.run([git, "-C", str(index_dir), "index-pack", "--stdin"],
                                     input=twin_pack.read_bytes() if twin_pack.exists() else b"",
                                     env=env, capture_output=True, timeout=300)
            facts["twin_self_contained"] = indexed.returncode == 0
        stop.touch()
        process.wait(timeout=120)
        facts["server_drained_exit"] = process.returncode
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
    root = Path(tempfile.mkdtemp(prefix="fg-thin-fetch-"))
    try:
        env = isolated_environment(root / "home")
        fg = str(options.fg.resolve())
        summary: dict = {"type": "thin_fetch_summary",
                         "git": checked([options.git, "--version"], env)}
        for transport in ("git", "http"):
            summary.update(campaign(fg, options.git, transport, root, env))
    except BaseException:
        print(json.dumps({"type": "thin_fetch_failed", "artifacts": str(root)}), flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
