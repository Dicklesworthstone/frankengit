#!/usr/bin/env python3
"""Capability advertisements of one node over fg serve-http, fg serve and fg serve-ssh.

frankengit-root-doctrine-x2mv.4.8 acceptance 4. The same persisted node is
served in turn by each transport, and stock git's packet trace records what
each one advertises:

- upload_v2: the protocol-v2 capability block (`git ls-remote`, v2);
- upload_v0: the capability list on the first advertised ref (v0);
- receive_v0: the receive-pack capability list (`git push --dry-run`, v0).

The script records the three sets per transport, and their differences, as
one JSON summary; scripts/e2e/suites/transport/capability_parity.sh asserts
that every difference is empty.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import tempfile
import time
from pathlib import Path

TENANT, REPOSITORY, PRINCIPAL = "f1" * 16, "f2" * 16, "f3" * 16
TIMEOUT = 300
PROBES = ("upload_v2", "upload_v0", "receive_v0")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def git_env(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and not k.upper().endswith("_PROXY")}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_NAME="Parity", GIT_AUTHOR_EMAIL="parity@example.invalid",
               GIT_COMMITTER_NAME="Parity", GIT_COMMITTER_EMAIL="parity@example.invalid")
    return env


def run(args: list, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run([str(a) for a in args], env=env, capture_output=True, text=True,
                          timeout=TIMEOUT)


def checked(args: list, env: dict[str, str]) -> str:
    result = run(args, env)
    require(result.returncode == 0, f"{args[:3]!r} failed: {result.stderr[-2000:]}")
    return result.stdout.strip()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_listening(port: int, process: subprocess.Popen) -> None:
    started = time.monotonic()
    while time.monotonic() - started < 60:
        require(process.poll() is None, "server exited before it listened")
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.2):
            return
        time.sleep(0.05)
    raise RuntimeError(f"nothing listened on {port}")


def received(trace: str) -> list[str]:
    """Packet payloads the client received, in order (NUL shown as \\0)."""
    return [m.group(1) for m in re.finditer(r"packet:\s+\S+< (.*)", trace)]


def capabilities(name: str, lines: list[str]) -> list[str]:
    if name == "upload_v2":
        require("version 2" in lines, "no protocol v2 advertisement")
        block = []
        for line in lines[lines.index("version 2") + 1:]:
            if line == "0000":
                break
            block.append(line)
        return sorted(set(block) - {"version 2"})
    first = next((line for line in lines if "\\0" in line), None)
    require(first is not None, f"{name}: no capability-bearing ref line")
    return sorted(first.split("\\0", 1)[1].split())


def probe(root: Path, label: str, url: str, env: dict[str, str], extra: list[str],
          source: Path) -> dict[str, list[str]]:
    commands = {
        "upload_v2": ("2", ["ls-remote", url]),
        "upload_v0": ("0", ["ls-remote", url]),
        "receive_v0": ("0", ["push", "--dry-run", "--porcelain", url, "HEAD:refs/heads/parity"]),
    }
    found = {}
    for name in PROBES:
        version, command = commands[name]
        trace = root / f"trace-{label}-{name}"
        result = run(["git", *extra, "-c", f"protocol.version={version}", "-C", source, *command],
                     dict(env, GIT_TRACE_PACKET=str(trace)))
        require(result.returncode == 0, f"{label} {name} failed: {result.stderr[-2000:]}")
        found[name] = capabilities(name, received(trace.read_text(errors="replace")))
    return found


@contextlib.contextmanager
def spawned(args: list, root: Path, label: str):
    out, err = (root / f"{label}.out").open("wb"), (root / f"{label}.err").open("wb")
    process = subprocess.Popen([str(a) for a in args], stdout=out, stderr=err)
    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                process.wait(timeout=30)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        out.close()
        err.close()


def exercise(fg: str, root: Path) -> dict:
    env = git_env(root / "home")
    node = root / "node"
    checked([fg, "init", node, TENANT, REPOSITORY, "sha1"], env)
    source = root / "source"
    checked(["git", "init", "-q", "-b", "main", source], env)
    (source / "README").write_text("capability parity\n")
    checked(["git", "-C", source, "add", "README"], env)
    checked(["git", "-C", source, "commit", "-qm", "base"], env)
    checked([fg, "import", node, TENANT, REPOSITORY, PRINCIPAL, "parity-import", source], env)
    summary: dict = {"type": "capability_parity_summary", "git": checked(["git", "--version"], env)}
    found: dict[str, dict[str, list[str]]] = {}

    # Smart HTTP.
    header = checked([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                      "--trusted-local", "--print-credentials-header"], env)
    token = secrets.token_hex(32)
    grants = root / "grants"
    with os.fdopen(os.open(grants, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(f"{header}\n{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} "
                  "read,receive\n")
    stop = root / "http.stop"
    with spawned([fg, "serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0", "--trusted-local",
                  "--credentials-file", grants, "--allow-receive", "--continuous",
                  "--stop-file", stop], root, "http") as process:
        url = None
        started = time.monotonic()
        while url is None and time.monotonic() - started < 60:
            require(process.poll() is None, "serve-http exited before readiness")
            for line in (root / "http.out").read_text().splitlines():
                with contextlib.suppress(json.JSONDecodeError):
                    value = json.loads(line)
                    if value.get("type") == "smart_http_listening":
                        url = value["url"]
            time.sleep(0.05)
        require(url is not None, "serve-http never reported readiness")
        found["http"] = probe(root, "http", url, env,
                              ["-c", f"http.extraHeader=Authorization: Bearer {token}"], source)
        stop.touch()
        process.wait(timeout=120)

    # Guarded raw Git (git://).
    port = free_port()
    with spawned([fg, "serve", node, TENANT, REPOSITORY, f"127.0.0.1:{port}",
                  "--max-sessions", "16", "--max-in-flight", "1",
                  "--receive-principal", PRINCIPAL], root, "git") as process:
        wait_listening(port, process)
        found["git"] = probe(root, "git", f"git://127.0.0.1:{port}/{REPOSITORY}.git", env, [],
                             source)

    # SSH.
    key = root / "client"
    checked(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", key, "-C", "parity", "-q"], env)
    public = base64.b64decode(key.with_suffix(".pub").read_text().split()[1])[-32:].hex()
    deploy = root / "deploy_keys"
    deploy.write_text(f"{public} {PRINCIPAL} read,write\n")
    host = root / "host_key.hex"
    host.write_text(secrets.token_hex(32))
    port = free_port()
    with spawned([fg, "serve-ssh", node, TENANT, REPOSITORY, f"127.0.0.1:{port}",
                  "--host-key-file", host, "--deploy-keys-file", deploy, "--allow-receive",
                  "--max-sessions", "16", "--max-in-flight", "1"], root, "ssh") as process:
        wait_listening(port, process)
        ssh = (f"ssh -p {port} -i {key} -o StrictHostKeyChecking=no "
               "-o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR")
        found["ssh"] = probe(root, "ssh", f"ssh://git@127.0.0.1:{port}/{REPOSITORY}.git",
                             dict(env, GIT_SSH_COMMAND=ssh), [], source)

    summary["capabilities"] = found
    for name in PROBES:
        union = set().union(*(set(found[t][name]) for t in found))
        summary[f"{name}_differences"] = {
            transport: sorted(union - set(found[transport][name])) for transport in found
            if union - set(found[transport][name])
        }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", required=True)
    parser.add_argument("--summary", type=Path)
    options = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="fg-capability-parity-"))
    try:
        summary = exercise(options.fg, root)
    except BaseException:
        print(json.dumps({"type": "capability_parity_failed", "artifacts": str(root)}),
              flush=True)
        raise
    summary["artifacts"] = str(root)
    text = json.dumps(summary, sort_keys=True)
    print(text, flush=True)
    if options.summary is not None:
        options.summary.write_text(text + "\n")


if __name__ == "__main__":
    main()
