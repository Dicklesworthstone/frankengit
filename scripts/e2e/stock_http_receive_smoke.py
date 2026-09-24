#!/usr/bin/env python3
"""Stock receive and restart/replay campaign against the real fg binary.

No Rust build and no substitute server. Reuses smart_http_smoke's isolated
configuration, real process lifecycle, token provisioning and drain checks.
Requires --fg; without that executable this campaign cannot claim a pass.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

from smart_http_smoke import (
    Commands, REPOSITORY, SECRETS, TENANT, isolated_environment,
    redact, require, seed, server,
)

DISCOVERY = "/info/refs?service=git-receive-pack"
MAX_RESPONSE = 1024 * 1024


def exchange(base: str, target: str, token: str | None, *, body: bytes | None = None,
             key: str | None = None) -> tuple[int, dict[str, str], bytes]:
    endpoint = urllib.parse.urlsplit(base)
    require(endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1",
            "campaign refuses non-loopback HTTP")
    headers = {"Connection": "close"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if key is not None:
        headers["Idempotency-Key"] = key
    if body is not None:
        headers["Content-Type"] = "application/x-git-receive-pack-request"
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=30)
    try:
        connection.request("GET" if body is None else "POST", target, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read(MAX_RESPONSE + 1)
        require(len(payload) <= MAX_RESPONSE, "HTTP response exceeded campaign bound")
        return response.status, {k.lower(): v for k, v in response.getheaders()}, payload
    finally:
        connection.close()


def attempt(base: str, token: str) -> tuple[str, str]:
    route = urllib.parse.urlsplit(base).path
    status, headers, body = exchange(base, route + DISCOVERY, token)
    require(status == 307 and body == b"", "stock discovery did not produce a bodyless redirect")
    require(headers.get("cache-control") == "no-store", "retry discovery was cacheable")
    location = headers.get("location", "")
    match = re.fullmatch(re.escape(route) + r"/\.fgit-receive/([0-9a-f]{64})" + re.escape(DISCOVERY), location)
    require(match is not None, "redirect escaped the repository or changed the receive operation")
    key = "fg-http-v1-" + match[1]
    require(headers.get("idempotency-key") == key, "redirect did not report its exact retry key")
    return location[:-len(DISCOVERY)] + "/git-receive-pack", key


def delete_request(oid: str, fmt: str) -> bytes:
    require(len(oid) == (40 if fmt == "sha1" else 64), "object format and tip disagree")
    capabilities = "report-status delete-refs atomic"
    if fmt == "sha256":
        capabilities += " object-format=sha256"
    command = f"{oid} {'0' * len(oid)} refs/heads/topic\0{capabilities}\n".encode("ascii")
    return f"{len(command) + 4:04x}".encode("ascii") + command + b"0000"


def read_refs(commands: Commands, token: str, url: str) -> dict[str, str]:
    refs = {}
    for line in commands.remote_git(token, 2, "ls-remote", url).splitlines():
        oid, separator, name = line.partition("\t")
        require(bool(separator) and bool(name) and name not in refs,
                "malformed or duplicate advertised ref")
        refs[name] = oid
    return refs


def has_ref(commands: Commands, token: str, url: str, name: str, tip: str) -> bool:
    return read_refs(commands, token, url).get(name) == tip


def exercise(fg: str, git: str, root: Path, fmt: str, timeout: int) -> dict[str, object]:
    root.mkdir()
    commands = Commands(git, isolated_environment(root / "home"), timeout)
    token = secrets.token_hex(32)
    SECRETS.append(token)
    token_file = root / "token"
    with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(token + "\n")
    commands.run([fg, "init", str(root / "state"), TENANT, REPOSITORY, fmt])
    source, initial = seed(commands, root, fmt)
    body = delete_request(initial, fmt)
    with server(fg, commands, root, token_file, receive=True) as url:
        # No Idempotency-Key in any stock Git command, including repeated work.
        commands.remote_git(token, 0, "-C", str(source), "push", url, "HEAD:refs/heads/topic")
        require(has_ref(commands, token, url, "refs/heads/topic", initial), "first stock push missing")
        commands.remote_git(token, 1, "-C", str(source), "push", url, ":refs/heads/topic")
        require("refs/heads/topic" not in read_refs(commands, token, url), "stock deletion missing")
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/topic")
        require(has_ref(commands, token, url, "refs/heads/topic", initial), "identical stock recreation aliased old work")
        rpc, key = attempt(url, token)
        other_rpc, other_key = attempt(url, token)
        require(rpc != other_rpc and key != other_key, "independent discoveries reused an attempt")
        discovery = rpc[:-len("/git-receive-pack")] + DISCOVERY
        require(exchange(url, discovery, None)[0] == 401, "scoped URL authenticated discovery")
        require(exchange(url, discovery, token)[0] == 200, "authenticated scoped discovery failed")
        require(exchange(url, rpc, None, body=body)[0] == 401, "scoped URL authenticated a mutation")
        require(exchange(url, rpc, token, body=body, key="different")[0] == 400,
                "a conflicting header replaced the scoped identity")
        require(has_ref(commands, token, url, "refs/heads/topic", initial), "refusal changed canonical refs")
        status, _, acknowledgement = exchange(url, rpc, token, body=body)
        require(status == 200 and b"ok refs/heads/topic\n" in acknowledgement
                and b"ng refs/heads/topic" not in acknowledgement,
                "scoped native receive did not acknowledge deletion")
        require("refs/heads/topic" not in read_refs(commands, token, url), "acknowledged deletion not visible")

    # Recreate under a NEW discovery, then replay the OLD deletion at its SAME
    # URL. It must recover the old ACK, not delete the newly recreated branch.
    with server(fg, commands, root, token_file, receive=True) as url:
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/topic")
        require(has_ref(commands, token, url, "refs/heads/topic", initial), "restart recreation failed")
        status, _, replayed = exchange(url, rpc, token, body=body)
        require(status == 200 and replayed == acknowledgement, "restart did not recover the exact terminal reply")
        require(has_ref(commands, token, url, "refs/heads/topic", initial), "old replay deleted newer branch state")
        # Two different ref effects still go through the existing atomic path.
        commands.remote_git(token, 2, "-C", str(source), "push", "--atomic", url,
                            "HEAD:refs/heads/one", "HEAD:refs/heads/two")
        require(all(has_ref(commands, token, url, name, initial)
                    for name in ("refs/heads/one", "refs/heads/two")), "atomic stock push lost an effect")
        clone = root / "clone"
        commands.remote_git(token, 2, "clone", "--branch", "topic", url, str(clone))
        require(commands.local_git("-C", str(clone), "rev-parse", "HEAD") == initial, "clone-back identity differs")
        require((clone / "README").read_bytes() == (source / "README").read_bytes(), "clone-back content differs")
        commands.local_git("-C", str(clone), "fsck", "--strict")

    with server(fg, commands, root, token_file, receive=False) as url:
        route = urllib.parse.urlsplit(url).path
        require(exchange(url, route + DISCOVERY, token)[0] == 403, "readonly service issued a write attempt")
        require(exchange(url, rpc, token, body=body)[0] == 403, "old attempt bypassed readonly policy")
        require(has_ref(commands, token, url, "refs/heads/topic", initial), "readonly refusal changed refs")
    return {"type": "stock_http_receive_passed", "format": fmt, "tip": initial,
            "checks": ["stock-create-delete-recreate", "independent-discoveries",
                       "per-request-auth", "conflicting-key-refusal", "native-delete",
                       "restart-replay-preserves-newer-state", "atomic-multiref",
                       "clone-back-fsck", "readonly-refusal", "all-listeners-drained"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--format", action="append", choices=("sha1", "sha256"), dest="formats")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--artifact-dir", type=Path, help="new directory; retained on failure")
    args = parser.parse_args()
    require(1 <= args.timeout <= 600, "timeout must be in 1..600")
    fg = args.fg.resolve(strict=True)
    require(fg.is_file() and os.access(fg, os.X_OK), "--fg must name a built executable")
    git = shutil.which(args.git)
    require(git is not None, "Git client not found")
    root = args.artifact_dir
    if root is None:
        root = Path(tempfile.mkdtemp(prefix="fg-stock-http-receive-"))
    else:
        root.mkdir(parents=True, exist_ok=False)
    with fg.open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    try:
        commands = Commands(git, isolated_environment(root / "home"), args.timeout)
        print(json.dumps({"type": "stock_http_receive_started", "fg_binary_sha256": digest,
                          "git_version": commands.local_git("--version"), "artifacts": str(root)}), flush=True)
        for fmt in dict.fromkeys(args.formats or ["sha1", "sha256"]):
            print(json.dumps(exercise(str(fg), git, root / fmt, fmt, args.timeout)), flush=True)
        return 0
    except BaseException:
        print(f"stock HTTP receive artifacts retained at {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError, http.client.HTTPException) as error:
        print(redact(f"stock HTTP receive FAILED: {error}"), file=sys.stderr)
        raise SystemExit(1)
