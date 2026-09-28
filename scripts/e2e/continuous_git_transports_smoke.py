#!/usr/bin/env python3
"""Continuous raw Git/SSH stock-client campaign for x2mv.4.32 acceptance 1..4.

Requires an explicitly prebuilt fg, stock Git, OpenSSH and Python 3.10+.
Default scope is one SHA-1 repository per transport; repeat --format to select
both native identity domains. All commands, stderr, packet traces, barrier
records, server receipts and assertion NDJSON remain in --artifacts. No build,
mock server, external service or production Git subprocess is involved.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

from smart_http_smoke import Commands, PRINCIPAL, REPOSITORY, TENANT, isolated_environment, require, seed

BEAD = "frankengit-root-doctrine-x2mv.4.32"
CYCLES = 70
SESSION_SECONDS = 30
DRAIN_SECONDS = 120
PROXY = Path(__file__).with_name("continuous_git_proxy.py").resolve()


def private_file(path: Path, text: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(text)


def proxy_program(path: Path, mode: str) -> Path:
    """GIT_PROXY_COMMAND names one program, run without a shell, as
    `<program> <host> <port>`; a command line with arguments cannot be exec'd
    ("cannot exec '... proxy.py raw': No such file or directory"). This private
    wrapper is that program."""
    command = shlex.join([sys.executable, str(PROXY), mode])
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700), "w") as out:
        out.write(f'#!/bin/sh\nexec {command} "$@"\n')
    return path


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        hasher = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
        return hasher.hexdigest()


class Evidence:
    def __init__(self, root: Path, revision: str, binary_digest: str):
        self.root = root
        self.identity = {"bead": BEAD, "source_revision": revision,
                         "fg_binary_sha256": binary_digest}

    def emit(self, kind: str, **fields) -> None:
        line = json.dumps({"type": kind, **self.identity, **fields}, sort_keys=True)
        with (self.root / "evidence.ndjson").open("a") as out:
            out.write(line + "\n")
        print(line, flush=True)


class Child:
    """Own one process group and keep complete stdout/stderr even on failure."""
    def __init__(self, commands: "LoggedCommands", args: list[str], env: dict[str, str]):
        self.owner, self.args = commands, args
        commands.serial += 1
        stem = f"{commands.serial:04d}"
        self.stdout = commands.logs / f"{stem}.stdout"
        self.stderr = commands.logs / f"{stem}.stderr"
        self.started = time.monotonic()
        self.recorded = False
        with self.stdout.open("wb") as out, self.stderr.open("wb") as err:
            self.process = subprocess.Popen(args, env=env, stdin=subprocess.DEVNULL,
                                            stdout=out, stderr=err, start_new_session=True)

    def __enter__(self) -> "Child":
        return self

    def __exit__(self, *_exc) -> None:
        # Every invocation gets its own group, including Git's ssh/proxy child.
        # Cleanup never supplies a successful graceful-stop assertion.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGTERM)
        if self.process.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.process.wait(timeout=3)
        with contextlib.suppress(ProcessLookupError):
            os.killpg(self.process.pid, signal.SIGKILL)
        self.process.wait(timeout=5)
        self.record()

    def record(self) -> None:
        if self.recorded:
            return
        entry = {"args": self.args, "exit_code": self.process.returncode,
                 "elapsed_seconds": round(time.monotonic() - self.started, 6),
                 "stdout": str(self.stdout), "stderr": str(self.stderr),
                 "stdout_sha256": digest(self.stdout), "stderr_sha256": digest(self.stderr)}
        with (self.owner.logs / "commands.ndjson").open("a") as out:
            out.write(json.dumps(entry, sort_keys=True) + "\n")
        self.recorded = True

    def finish(self, *, check: bool = True, timeout: float | None = None) -> str:
        self.process.wait(timeout=self.owner.timeout if timeout is None else timeout)
        self.record()
        require(not check or self.process.returncode == 0,
                f"command exited {self.process.returncode}: {self.args!r}\n"
                f"stderr artifact: {self.stderr}\n{self.stderr.read_text(errors='replace')[-8000:]}")
        return self.stdout.read_text(errors="replace").strip()


class LoggedCommands(Commands):
    def __init__(self, git: str, env: dict[str, str], timeout: int, logs: Path):
        super().__init__(git, env, timeout)
        self.logs, self.serial = logs, 0
        logs.mkdir()

    def start(self, args: list[str], *, env: dict[str, str] | None = None) -> Child:
        return Child(self, args, self.env if env is None else env)

    def run(self, args: list[str], *, env: dict[str, str] | None = None) -> str:
        with self.start(args, env=env) as child:
            return child.finish()

    def git_args(self, *args: str) -> list[str]:
        return [self.git, "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                "-c", "protocol.version=2", *args]

    def local_git(self, *args: str) -> str:
        return self.run(self.git_args(*args))


def records(path: Path) -> list[dict]:
    # `fg` retains its human-readable final CliOutcome line after the two
    # structured lifecycle records. Do not mistake it for a JSON parse error.
    return [json.loads(line) for line in path.read_text().splitlines()
            if line.startswith("{") and line.endswith("}")]


class Service:
    def __init__(self, fg: str, commands: LoggedCommands, root: Path, transport: str,
                 ssh: str, keygen: str):
        self.fg, self.commands, self.root, self.transport = fg, commands, root, transport
        self.ssh_base: list[str] = []
        self.listening = "git_daemon_listening" if transport == "git" else "ssh_listening"
        self.drained = "git_daemon_drained" if transport == "git" else "ssh_drained"
        self.credentials = ["--receive-principal", PRINCIPAL]
        if transport == "ssh":
            key, host, deploy = root / "client", root / "host-key", root / "deploy-keys"
            commands.run([keygen, "-t", "ed25519", "-N", "", "-f", str(key), "-C", "continuous-e2e"])
            encoded = key.with_suffix(".pub").read_text().split()
            require(encoded[0] == "ssh-ed25519", "oracle generated an unexpected key type")
            blob = base64.b64decode(encoded[1], validate=True)
            require(blob[:19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x20" and len(blob) == 51,
                    "oracle public key has an unexpected encoding")
            private_file(deploy, f"{blob[-32:].hex()} {PRINCIPAL} read,write\n")
            private_file(host, secrets.token_hex(32) + "\n")
            self.credentials = ["--host-key-file", str(host), "--deploy-keys-file", str(deploy),
                                "--allow-receive"]
            # The generated host is intentionally test-local. Ignore ambient
            # SSH config/agents and retain all host-key/connection diagnostics.
            self.ssh_base = [ssh, "-F", os.devnull, "-i", str(key), "-o", "IdentitiesOnly=yes",
                             "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
                             "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}",
                             "-o", f"GlobalKnownHostsFile={os.devnull}", "-o", "ConnectTimeout=5"]

    def arguments(self, stop: Path) -> list[str]:
        return [self.fg, "serve" if self.transport == "git" else "serve-ssh",
                str(self.root / "state"), TENANT, REPOSITORY, "127.0.0.1:0",
                *self.credentials, "--continuous", "--stop-file", str(stop),
                "--max-in-flight", "2", "--session-timeout-secs", str(SESSION_SECONDS),
                "--session-secs-per-mib", "0", "--session-max-extension-secs", "0"]

    def environment(self) -> dict[str, str]:
        env = self.commands.env.copy()
        if self.transport == "ssh":
            env.update(GIT_SSH_COMMAND=shlex.join(self.ssh_base), GIT_SSH_VARIANT="ssh")
        return env

    def remote(self, *args: str) -> str:
        return self.commands.run(self.commands.git_args(*args), env=self.environment())

    @contextlib.contextmanager
    def running(self, label: str):
        stop = self.root / f"{label}.stop"
        with self.commands.start(self.arguments(stop)) as child:
            deadline = time.monotonic() + self.commands.timeout
            ready = []
            while time.monotonic() < deadline:
                ready = [r for r in records(child.stdout) if r.get("type") == self.listening]
                if ready:
                    break
                require(child.process.poll() is None,
                        f"{self.transport} exited before readiness: {child.stderr.read_text()[-8000:]}")
                time.sleep(0.02)
            require(len(ready) == 1, "missing or duplicate continuous readiness")
            record = ready[0]
            require(record.get("schema_version") == 1 and record.get("lifetime") == "continuous",
                    "listener did not select continuous lifetime")
            enabled = "receive_enabled" if self.transport == "git" else "allow_receive"
            require(record.get(enabled) is True, "listener did not enable explicit receive policy")
            require(re.fullmatch(r"[0-9a-f]{32}", record.get("repository_incarnation", "")) is not None,
                    "readiness did not bind a repository incarnation")
            host, port = record["address"].rsplit(":", 1)
            require(host == "127.0.0.1" and 1 <= int(port) <= 65535, "listener is not test-local")
            url = (f"git://{host}:{port}/{REPOSITORY}.git" if self.transport == "git"
                   else f"ssh://git@{host}:{port}/{REPOSITORY}.git")
            yield child, url, stop, (host, int(port))
            require(child.process.poll() == 0, "test did not observe a clean service stop")

    def settle(self, child: Child, stopped: float, minimum: int) -> dict:
        remaining = DRAIN_SECONDS - (time.monotonic() - stopped)
        require(remaining > 0, "drain deadline expired before join")
        child.finish(timeout=remaining)
        elapsed = time.monotonic() - stopped
        require(elapsed <= DRAIN_SECONDS, "continuous service exceeded its configured finite drain envelope")
        receipts = [r for r in records(child.stdout) if r.get("type") == self.drained]
        require(len(receipts) == 1, "missing or duplicate final drain summary")
        receipt = receipts[0]
        require(receipt.get("schema_version") == 1 and receipt.get("lifetime") == "continuous",
                "drain summary lost its continuous-lifetime binding")
        for name in ("accepted", "completed_transports", "refused_transports"):
            require(type(receipt.get(name)) is int and receipt[name] >= 0, "invalid drain count")
        require(receipt["accepted"] == receipt["completed_transports"] + receipt["refused_transports"],
                "drain left accepted transports unsettled")
        require(receipt["accepted"] >= minimum and receipt["completed_transports"] >= minimum,
                "drain summary did not account for the completed stock-client campaign")
        return {"receipt": receipt, "signal_to_exit_seconds": round(elapsed, 6),
                "drain_bound_seconds": DRAIN_SECONDS, "stdout": str(child.stdout),
                "stderr": str(child.stderr)}


def refs(service: Service, url: str, selected: list[str]) -> dict[str, str]:
    result = {}
    for line in service.remote("ls-remote", "--refs", url, *selected).splitlines():
        oid, name = line.split("\t")
        require(name in selected and name not in result, "unexpected or duplicate selected ref")
        result[name] = oid
    require(set(result) == set(selected), "canonical discovery omitted a selected ref")
    return result


def commit(commands: LoggedCommands, source: Path, label: str) -> str:
    with (source / "README").open("a") as out:
        out.write(f"continuous stock-client {label}\n")
    commands.local_git("-C", str(source), "add", "README")
    commands.local_git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-m", label)
    return commands.local_git("-C", str(source), "rev-parse", "HEAD")


def campaign(service: Service, child: Child, url: str, source: Path, fmt: str,
             evidence: Evidence) -> dict:
    commands = service.commands
    fetcher = service.root / "fetcher"
    commands.local_git("init", "--bare", f"--object-format={fmt}", str(fetcher))
    for cycle in range(1, CYCLES + 1):
        tip = commit(commands, source, f"cycle-{cycle:03d}")
        service.remote("-C", str(source), "push", "--porcelain", url, "HEAD:refs/heads/main")
        service.remote("-C", str(fetcher), "fetch", "--no-tags", url,
                       "refs/heads/main:refs/heads/tracked-main")
        require(commands.local_git("-C", str(fetcher), "rev-parse", "FETCH_HEAD") == tip,
                "incremental fetch selected the wrong commit")
        clone = service.root / f"clone-{cycle:03d}"
        service.remote("clone", "--branch", "main", "--single-branch", url, str(clone))
        require(commands.local_git("-C", str(clone), "rev-parse", "HEAD") == tip,
                "fresh clone selected the wrong commit")
        if cycle in (1, CYCLES):
            commands.local_git("-C", str(clone), "fsck", "--strict")
        shutil.rmtree(clone)
        require(child.process.poll() is None, "continuous service retired during sequential stock sessions")
        if cycle % 10 == 0:
            evidence.emit("continuous_git_progress", transport=service.transport, format=fmt,
                          sequential_stock_sessions=cycle * 3, cycles=cycle)
    commands.local_git("-C", str(fetcher), "fsck", "--strict")
    return {"stock_sessions": CYCLES * 3, "pushes": CYCLES, "incremental_fetches": CYCLES,
            "fresh_clones": CYCLES, "final_tip": tip}


def closed_while_held(address: tuple[str, int], server: Child, push: Child) -> dict:
    deadline, attempts = time.monotonic() + 5, 0
    while time.monotonic() < deadline:
        require(server.process.poll() is None and push.process.poll() is None,
                "server or held push exited before listener-close observation and PACK release")
        attempts += 1
        try:
            with socket.create_connection(address, timeout=0.5):
                pass
        except ConnectionRefusedError:
            require(server.process.poll() is None and push.process.poll() is None,
                    "connection was refused only after the active child had already exited")
            return {"new_connection": "ECONNREFUSED", "attempts": attempts,
                    "server_alive": True, "push_alive": True, "pack_released": False}
        except TimeoutError as error:
            raise RuntimeError("new connection hung during drain") from error
        time.sleep(0.02)
    raise RuntimeError("listener stayed open while its accepted push was held during drain")


def held_push(service: Service, server: Child, url: str, address: tuple[str, int],
              source: Path, label: str, stop_signal: bool) -> dict:
    commands = service.commands
    selected = [f"refs/heads/{label}-a", f"refs/heads/{label}-b"]
    before = commands.local_git("-C", str(source), "rev-parse", "HEAD")
    service.remote("-C", str(source), "push", "--porcelain", "--atomic", url,
                   *(f"HEAD:{name}" for name in selected))
    after = commit(commands, source, label)
    ready, release, trace = (service.root / f"{label}.{extension}"
                             for extension in ("ready.json", "release", "packet-trace"))
    env = service.environment()
    env.update(FG_CONTINUOUS_BARRIER_READY=str(ready), FG_CONTINUOUS_BARRIER_RELEASE=str(release),
               FG_CONTINUOUS_PROXY_TIMEOUT=str(max(180, commands.timeout)), GIT_TRACE_PACKET=str(trace))
    if service.transport == "git":
        env["GIT_PROXY_COMMAND"] = str(proxy_program(service.root / f"{label}.git-proxy", "raw"))
    else:
        env["GIT_SSH_COMMAND"] = shlex.join([sys.executable, str(PROXY), "ssh", *service.ssh_base])
    args = commands.git_args("-C", str(source), "push", "--porcelain", "--atomic", url,
                             *(f"HEAD:{name}" for name in selected))
    with commands.start(args, env=env) as push:
        deadline = time.monotonic() + SESSION_SECONDS
        while not ready.exists() and time.monotonic() < deadline:
            require(push.process.poll() is None and server.process.poll() is None,
                    f"push/server exited before PACK barrier; stderr: {push.stderr.read_text()[-8000:]}")
            time.sleep(0.02)
        require(ready.is_file(), "stock push did not reach its command/PACK barrier")
        barrier = json.loads(ready.read_text())
        require(barrier.get("atomic") is True and barrier.get("command_refs") == selected
                and barrier.get("forwarded_pack_header_bytes") == 12 and barrier.get("pack_objects", 0) > 0,
                "barrier does not describe the exact two-ref stock push")
        require(refs(service, url, selected) == dict.fromkeys(selected, before),
                "incomplete PACK partially published an atomic ref update")
        if stop_signal:
            stopped = time.monotonic()
            server.process.send_signal(signal.SIGTERM)
            closed = closed_while_held(address, server, push)
        else:
            require(server.process.poll() is None and push.process.poll() is None,
                    "no-signal twin ended before release")
            stopped, closed = None, None
        # Release immediately after observing closed admission, while the real
        # accepted stock push is still waiting for its remaining PACK bytes.
        private_file(release, "release remaining stock Git PACK bytes\n")
        result = push.finish(check=False, timeout=DRAIN_SECONDS)
        require(trace.is_file(), "stock client did not record report-status packets")
        received = re.findall(r"packet:\s+\S+< (.*)", trace.read_text(errors="replace"))
        ok = [name for name in selected if f"ok {name}" in received]
        ng = [name for name in selected if any(line.startswith(f"ng {name} ") for line in received)]
        if push.process.returncode == 0:
            require(ok == selected and not ng, "successful stock push lacks exact per-ref report-status")
            outcome, expected = "completed", after
        else:
            require(stop_signal and ng == selected and not ok,
                    f"held push failed without a typed atomic report-status verdict: {result}\n"
                    f"{push.stderr.read_text(errors='replace')[-8000:]}")
            outcome, expected = "typed_refusal", before
        receipt = None
        if stop_signal:
            assert stopped is not None
            receipt = service.settle(server, stopped, CYCLES * 3)
        else:
            require(refs(service, url, selected) == dict.fromkeys(selected, expected),
                    "permitted twin did not publish both refs exactly")
            require(server.process.poll() is None, "same held-push run without a signal stopped serving")
        return {"outcome": outcome, "refs": selected, "before": before, "after": after,
                "expected": expected, "barrier": barrier, "barrier_artifact": str(ready),
                "report_status_trace": str(trace), "new_connection_during_drain": closed,
                "drain": receipt}


def exercise(fg: str, git: str, ssh: str, keygen: str, root: Path, transport: str,
             fmt: str, timeout: int, evidence: Evidence) -> dict:
    root.mkdir(parents=True)
    commands = LoggedCommands(git, isolated_environment(root / "home"), timeout, root / "commands")
    commands.run([fg, "init", str(root / "state"), TENANT, REPOSITORY, fmt])
    source, _ = seed(commands, root, fmt)
    commands.run([fg, "import", str(root / "state"), TENANT, REPOSITORY, PRINCIPAL,
                  "continuous-initial-import", str(source)])
    service = Service(fg, commands, root, transport, ssh, keygen)
    preexisting = root / "preexisting.stop"
    private_file(preexisting, "already requested stop\n")
    with commands.start(service.arguments(preexisting)) as refused:
        refused.finish(check=False)
        require(refused.process.returncode != 0 and not records(refused.stdout),
                "preexisting stop-file control did not refuse before readiness")
        require(preexisting.read_text() == "already requested stop\n", "startup replaced the stop request")
    with service.running("campaign") as (server, url, _stop, address):
        sequential = campaign(service, server, url, source, fmt, evidence)
        evidence.emit("continuous_git_acceptance", acceptance=1, transport=transport, format=fmt,
                      assertion_id=f"FG-GIT-CONTINUOUS-032-1-{transport}-{fmt}", **sequential)
        twin = held_push(service, server, url, address, source, "permitted", False)
        evidence.emit("continuous_git_acceptance", acceptance=4, transport=transport, format=fmt,
                      assertion_id=f"FG-GIT-CONTINUOUS-032-4-{transport}-{fmt}",
                      scope="real held-push permitted twin; lifetime unit tests belong to native crate lane", **twin)
        terminated = held_push(service, server, url, address, source, "sigterm", True)
    # Reopen canonical state through the real service and verify both atomic
    # targets plus closure integrity with an independent stock clone/fsck.
    with service.running("restart-sigint") as (server, url, _stop, _address):
        require(refs(service, url, terminated["refs"]) == dict.fromkeys(terminated["refs"], terminated["expected"]),
                "restart exposed a partial or lost atomic outcome after SIGTERM")
        require(refs(service, url, twin["refs"]) == dict.fromkeys(twin["refs"], twin["expected"]),
                "restart lost the no-signal twin's acknowledged update")
        recovered = root / "recovered"
        service.remote("clone", "--branch", "sigterm-a", url, str(recovered))
        require(commands.local_git("-C", str(recovered), "rev-parse", "HEAD") == terminated["expected"],
                "restart clone did not select the canonical atomic target")
        commands.local_git("-C", str(recovered), "fsck", "--strict")
        stopped = time.monotonic()
        server.process.send_signal(signal.SIGINT)
        interrupted = service.settle(server, stopped, 3)
    evidence.emit("continuous_git_acceptance", acceptance=2, transport=transport, format=fmt,
                  assertion_id=f"FG-GIT-CONTINUOUS-032-2-{transport}-{fmt}",
                  restart_atomic_refs=True, stock_clone_fsck=True, **terminated)
    evidence.emit("continuous_git_acceptance", acceptance=3, transport=transport, format=fmt,
                  assertion_id=f"FG-GIT-CONTINUOUS-032-3-{transport}-{fmt}",
                  **terminated["new_connection_during_drain"])
    with service.running("stop-file") as (server, url, stop, _address):
        require(refs(service, url, ["refs/heads/main"])["refs/heads/main"] == sequential["final_tip"],
                "idle restart lost the sequential campaign's main ref")
        stopped = time.monotonic()
        private_file(stop, "normal stop-file drain\n")
        stopped_file = service.settle(server, stopped, 1)
        require(stop.is_file(), "service removed its operator stop request")
    return {"transport": transport, "format": fmt, "acceptance_1": True, "acceptance_2": True,
            "acceptance_3": True, "acceptance_4_permitted_twin": True, "sequential": sequential,
            "sigterm": terminated, "permitted_twin": twin, "sigint": interrupted,
            "stop_file": stopped_file, "artifacts": str(root)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--ssh", default="ssh")
    parser.add_argument("--ssh-keygen", default="ssh-keygen")
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--format", action="append", choices=("sha1", "sha256"), dest="formats")
    parser.add_argument("--transport", action="append", choices=("git", "ssh"), dest="transports")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    require(os.name == "posix", "native signal/process-group campaign requires POSIX")
    # A suite-runner timeout must unwind the owned process contexts, because
    # Git/SSH/server groups intentionally have separate sessions. Default
    # signal termination of this Python parent would bypass their cleanup.
    def cancelled(signum, _frame):
        raise RuntimeError(f"campaign interrupted by {signal.Signals(signum).name}")
    signal.signal(signal.SIGTERM, cancelled)
    signal.signal(signal.SIGINT, cancelled)
    require(1 <= args.timeout <= 600, "timeout must be in 1..600")
    fg = args.fg.resolve(strict=True)
    require(fg.is_file() and os.access(fg, os.X_OK), "FG_BIN must be an executable file")
    git, ssh, keygen = (shutil.which(value) for value in (args.git, args.ssh, args.ssh_keygen))
    require(git is not None and ssh is not None and keygen is not None, "stock Git/OpenSSH tools are missing")
    root = (args.artifacts or Path(tempfile.mkdtemp(prefix="fg-continuous-git-"))).resolve()
    root.mkdir(parents=True, exist_ok=True)
    require(not any(root.iterdir()), "artifact directory must be empty to prevent evidence mixing")
    metadata = LoggedCommands(git, isolated_environment(root / "home"), args.timeout, root / "metadata")
    revision = metadata.local_git("-C", str(Path(__file__).resolve().parents[2]), "rev-parse", "HEAD")
    evidence = Evidence(root, revision, digest(fg))
    try:
        evidence.emit("continuous_git_transports_started", artifacts=str(root),
                      git_version=metadata.local_git("--version"), git_binary_sha256=digest(Path(git)),
                      source_dirty=bool(metadata.local_git("-C", str(Path(__file__).resolve().parents[2]),
                                                           "status", "--porcelain")),
                      harness_sha256=digest(Path(__file__)), proxy_sha256=digest(PROXY),
                      formats=list(dict.fromkeys(args.formats or ["sha1"])),
                      transports=list(dict.fromkeys(args.transports or ["git", "ssh"])),
                      session_timeout_seconds=SESSION_SECONDS, session_work_extension_seconds=0,
                      drain_bound_seconds=DRAIN_SECONDS, stock_sessions_per_transport=CYCLES * 3)
        # OpenSSH reports its version to stderr, which is retained in metadata.
        metadata.run([ssh, "-V"])
        rows = []
        for fmt in dict.fromkeys(args.formats or ["sha1"]):
            for transport in dict.fromkeys(args.transports or ["git", "ssh"]):
                rows.append(exercise(str(fg), git, ssh, keygen, root / f"{transport}-{fmt}",
                                     transport, fmt, args.timeout, evidence))
        summary = {"type": "continuous_git_transports_summary", **evidence.identity,
                   "artifacts": str(root), "results": rows,
                   "non_claim": "Loopback native process/stock-client evidence; lifetime unit tests run in the owning crate lane."}
        destination = args.summary or root / "summary.json"
        destination.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n")
        evidence.emit("continuous_git_transports_completed", summary=str(destination), results=len(rows))
        return 0
    except BaseException as error:
        evidence.emit("continuous_git_transports_failed", error=str(error), artifacts=str(root))
        raise


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"continuous Git/SSH smoke FAILED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
