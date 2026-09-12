#!/usr/bin/env python3
"""Pinned, sandboxed partial-clone client. Tooling only; no ambient Git fallback."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
PIN = "git-2.54.0"


def refuse(message):
    raise ValueError(message)


def main():
    args = sys.argv[1:]
    if len(args) < 3:
        refuse("usage: RUN clone|shallow-clone|depth|deepen|unshallow|fetch|read|checkout|inventory|history|fsck CLIENT [ENDPOINT REPOSITORY VERSION VALUE]")
    run_arg, operation, client, *extra = args
    if operation not in {"clone", "shallow-clone", "depth", "deepen", "unshallow", "fetch", "fetch-private", "read", "checkout", "inventory", "history", "fsck"}:
        refuse("unsupported client operation")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", client):
        refuse("client directory must be a bounded simple label")
    root = Path(os.environ.get("FGIT_ORACLE_ROOT", str(Path.home() / ".cache/frankengit/git-oracle"))).resolve(strict=True)
    runs = (root / "runs").resolve(strict=True)
    run = Path(run_arg).resolve(strict=True)
    if run == runs or not run.is_relative_to(runs):
        refuse("run must be inside the pinned oracle's run directory")
    for component in [run / "work", run / "home"]:
        if component.is_symlink() or not component.is_dir():
            refuse("oracle workspace and home must be real directories")
    work = run / "work"
    destination = work / client
    cloning = operation in {"clone", "shallow-clone"}
    if cloning:
        if destination.exists() or destination.is_symlink():
            refuse("clone destination must be absent")
    elif destination.is_symlink() or not destination.is_dir():
        refuse("existing client must be a real directory")
    network = operation in {"clone", "shallow-clone", "depth", "deepen", "unshallow", "fetch", "fetch-private", "read", "checkout"}
    config = [("core.hooksPath", "/home/oracle/empty-hooks"), ("credential.helper", "")]
    if network:
        if len(extra) != 4:
            refuse("network operation needs endpoint, repository, protocol, and filter/object")
        endpoint, repository, protocol, value = extra
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", endpoint)
        if not match or not 1 <= int(match[1]) <= 65535:
            refuse("only a numeric loopback endpoint is admitted")
        if not re.fullmatch(r"/[0-9a-f]{32}\.git", repository) or protocol not in {"0", "1", "2"}:
            refuse("repository or protocol does not match the fixed Git-daemon profile")
        url = "git://" + endpoint + repository
        config.append(("protocol.version", protocol))
        if operation in {"read", "checkout"}:
            config += [("remote.origin.url", url), ("remote.origin.promisor", "true")]
        if operation in {"depth", "deepen", "unshallow", "fetch", "fetch-private"}:
            config.append(("remote.origin.url", url))
        if operation == "shallow-clone":
            depth = re.fullmatch(r"([1-9][0-9]{0,9})(?:,(blob:none|tree:0))?", value)
            if not depth or int(depth[1]) > 2147483647:
                refuse("shallow clone needs a bounded positive depth and optional campaign filter")
            command = ["clone", "--no-local", "--no-checkout", "--single-branch", "--branch=public", "--depth=" + depth[1]]
            if depth[2]:
                command.append("--filter=" + depth[2])
            command += [url, client]
        elif operation in {"depth", "deepen"}:
            if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) > 2147483647:
                refuse("absolute depth must be a bounded positive integer")
            flag = "--deepen=" if operation == "deepen" else "--depth="
            command = ["fetch", "--no-tags", flag + value, "origin"]
        elif operation == "fetch-private":
            if value != "1":
                refuse("multi-branch campaign admits only depth one")
            command = ["fetch", "--no-tags", "--depth=1", "origin", "refs/heads/private:refs/remotes/origin/private"]
        elif operation in {"unshallow", "fetch"}:
            if value != "-":
                refuse("this fetch operation takes only the fixed no-value marker")
            command = ["fetch", "--no-tags"]
            if operation == "unshallow":
                command.append("--unshallow")
            command.append("origin")
        elif operation == "clone":
            if value not in {"blob:none", "tree:0", "tree:1", "blob:limit=21", "combine:tree:1+blob:none"}:
                refuse("filter is outside the pinned campaign")
            command = ["clone", "--no-local", "--no-checkout", "--filter=" + value, url, client]
        else:
            if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
                refuse("lazy read needs a complete native object identity")
            command = ["cat-file", "blob", value] if operation == "read" else ["checkout", "--detach", "--force", value]
    else:
        if extra:
            refuse("file-only operation takes no extra arguments")
        command = {"inventory": ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
                   "history": ["rev-list", "refs/remotes/origin/public"],
                   "fsck": ["fsck", "--strict"]}[operation]
    subprocess.run([str(HERE / "oracle.sh"), "verify", PIN], check=True, stdout=sys.stderr, timeout=60)
    install = root / "installs" / PIN
    receipt = (install / "receipt.tsv").read_text()
    binary_digest = hashlib.sha256((install / "bin/git").read_bytes()).hexdigest()
    transcript_dir = run / "transcripts"
    transcript_dir.mkdir(exist_ok=True)
    label = operation + "-" + client + "-" + str(time.time_ns())
    packet_log = transcript_dir / (label + ".packets")
    sandbox = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all"]
    if network:
        sandbox.append("--share-net")
    sandbox += ["--clearenv", "--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin",
                "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
                "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/home",
                "--bind", str(run / "home"), "/home/oracle", "--bind", str(work), "/work",
                "--bind", str(transcript_dir), "/transcripts", "--ro-bind", str(install), "/oracle",
                "--chdir", "/work" if cloning else "/work/" + client]
    environment = {
        "HOME": "/home/oracle", "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TEMPLATE_DIR": "/home/oracle/template",
        "GIT_EXEC_PATH": "/oracle/libexec/git-core", "GIT_CEILING_DIRECTORIES": "/work",
        "GIT_ALLOW_PROTOCOL": "git" if network else "file", "GIT_ASKPASS": "/bin/false",
        "GIT_TERMINAL_PROMPT": "0", "GIT_TRACE_PACKET": "/transcripts/" + packet_log.name,
        "GIT_CONFIG_COUNT": str(len(config)),
    }
    if not network:
        environment["GIT_NO_LAZY_FETCH"] = "1"
    for index, (key, value) in enumerate(config):
        environment["GIT_CONFIG_KEY_" + str(index)] = key
        environment["GIT_CONFIG_VALUE_" + str(index)] = value
    for key, value in environment.items():
        sandbox += ["--setenv", key, value]
    sandbox += ["--", "/oracle/bin/git", *command]
    started = time.monotonic()
    try:
        result = subprocess.run(sandbox, capture_output=True, timeout=60)
        code, stdout, stderr = result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired as error:
        code, stdout, stderr = 124, error.stdout or b"", error.stderr or b""
    (transcript_dir / (label + ".stdout")).write_bytes(stdout)
    (transcript_dir / (label + ".stderr")).write_bytes(stderr)
    summary = {"script": "partial_clone_client", "operation": operation, "client": client,
               "pin": PIN, "binary_sha256": binary_digest, "source_receipt_sha256": hashlib.sha256(receipt.encode()).hexdigest(),
               "command": command, "exit": code, "duration_ms": int((time.monotonic()-started)*1000),
               "stdout_sha256": hashlib.sha256(stdout).hexdigest(), "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
               "packet_transcript": str(packet_log)}
    (transcript_dir / (label + ".json")).write_text(json.dumps(summary, sort_keys=True) + "\n")
    sys.stderr.buffer.write(stderr)
    print(json.dumps(summary, sort_keys=True), file=sys.stderr)
    sys.stdout.buffer.write(stdout)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print("FGIT_PARTIAL_ORACLE_UNAVAILABLE:", error, file=sys.stderr)
        sys.exit(69)
