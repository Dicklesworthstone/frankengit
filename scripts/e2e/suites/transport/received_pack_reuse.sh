#!/usr/bin/env bash
# e2e: stock-client push -> first clone in one long-lived serving process,
# with received-pack reuse enabled and disabled over git://, HTTP and SSH.
# Bead: frankengit-1tl9
#
# The SHA-1 fixture has eight 64 KiB blob versions and verified stock-Git
# deltas. Every case starts with empty storage, pushes that complete history,
# immediately mirror-clones, then pushes one increment, fetches and makes a
# fresh full mirror. Each result must have exactly the source refs and native
# reachable object IDs and pass git fsck --strict. The independent computation
# cache is disabled in both twins. Native node tests check actual cache hits;
# this suite checks stock-client compatibility, not hits or performance.
# FG_BIN must name an already-built binary. No build is performed here.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init received-pack-reuse
fge_kind e2e-binary
fge_context bead frankengit-1tl9
fge_context evidence_class e2e_binary_stock_client
fge_context non_claim 'Recorded host Git/OpenSSH versions, SHA-1 and loopback only; no pinned differential, cache-hit, restart-persistence or performance claim.'
fge_phase setup

FG_BIN="${FG_BIN:-}"
[ -n "$FG_BIN" ] && [ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
for tool in git ssh ssh-keygen python3 timeout; do
  command -v "$tool" >/dev/null || fge_die "required stock-client tool is missing: $tool"
done
fge_context git_version "$(git --version)"
fge_context ssh_version "$(ssh -V 2>&1)"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir received-pack-reuse)"

# Keep this campaign in one suite file. The driver owns every subprocess group,
# records complete command logs, and kills all owned groups before responding to
# the outer deadline. Thus a failed client cannot leave a continuous fg behind.
cat > "$WORK/driver.py" <<'PY'
from __future__ import annotations

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
import subprocess
import sys
import time
from urllib.parse import urlsplit

TENANT, REPOSITORY, PRINCIPAL = "c1" * 16, "c2" * 16, "c3" * 16
OWNED: set[subprocess.Popen] = set()
GIT = shutil.which("git")
BASE_ENV = {
    key: value for key, value in os.environ.items()
    if not key.startswith("GIT_") and not key.upper().endswith("_PROXY")
}
BASE_ENV.update(
    GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
    GIT_TERMINAL_PROMPT="0", LC_ALL="C", TZ="UTC",
    GIT_AUTHOR_NAME="Received pack fixture",
    GIT_AUTHOR_EMAIL="received-pack@example.invalid",
    GIT_COMMITTER_NAME="Received pack fixture",
    GIT_COMMITTER_EMAIL="received-pack@example.invalid",
    GIT_AUTHOR_DATE="946684800 +0000", GIT_COMMITTER_DATE="946684800 +0000",
)


def kill_owned(process: subprocess.Popen) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def interrupted(signum, _frame) -> None:
    # Kill all groups up front, including a server while a client is active.
    # The timeout wrapper's later SIGKILL cannot strand either group.
    for process in tuple(OWNED):
        kill_owned(process)
    raise RuntimeError(f"campaign interrupted by signal {signum}")


signal.signal(signal.SIGTERM, interrupted)
signal.signal(signal.SIGINT, interrupted)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def private_file(path: Path, text: str) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as out:
        out.write(text)


class Commands:
    def __init__(self, root: Path):
        self.logs = root / "commands"
        self.logs.mkdir()
        self.serial = 0

    def run(self, args: list[str], *, env=None, timeout=60) -> str:
        self.serial += 1
        stem = self.logs / f"{self.serial:03d}"
        stdout, stderr = stem.with_suffix(".out"), stem.with_suffix(".err")
        with stdout.open("wb") as out, stderr.open("wb") as err:
            process = subprocess.Popen(args, env=BASE_ENV if env is None else env,
                                       stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                       start_new_session=True)
        OWNED.add(process)
        try:
            process.wait(timeout=timeout)
            require(process.returncode == 0,
                    f"command failed ({process.returncode}): {args!r}\n"
                    f"stderr: {stderr}\n{stderr.read_text(errors='replace')[-4000:]}")
            return stdout.read_text(errors="replace").strip()
        finally:
            kill_owned(process)
            process.wait(timeout=5)
            OWNED.discard(process)
            with (self.logs / "commands.ndjson").open("a") as out:
                out.write(json.dumps({"argv": args, "exit_code": process.returncode,
                                      "stdout": str(stdout), "stderr": str(stderr)}) + "\n")

    def git(self, *args: str, env=None) -> str:
        return self.run([GIT, "-c", "gc.auto=0", "-c", "maintenance.auto=false",
                         "-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false",
                         "-c", f"core.hooksPath={os.devnull}", "-c", "pack.threads=1",
                         "-c", "protocol.version=2", *args], env=env)


def commit(commands: Commands, source: Path, version: int) -> None:
    env = BASE_ENV.copy()
    stamp = f"{946684800 + version * 60} +0000"
    env.update(GIT_AUTHOR_DATE=stamp, GIT_COMMITTER_DATE=stamp)
    (source / "VERSION").write_text(f"{version}\n")
    commands.git("-C", str(source), "add", "data.bin", "VERSION")
    commands.git("-C", str(source), "commit", "-q", "-m", f"version {version}", env=env)


def mutate(source: Path, version: int) -> None:
    data = bytearray((source / "data.bin").read_bytes())
    patch = b"".join(hashlib.sha256(f"edit-{version}-{i}".encode()).digest() for i in range(8))
    start = version * 4096
    data[start:start + len(patch)] = patch
    (source / "data.bin").write_bytes(data)


def fixture(root: Path) -> None:
    commands = Commands(root)
    source = root / "source"
    commands.git("init", "-q", "-b", "main", "--object-format=sha1", str(source))
    (source / "data.bin").write_bytes(b"".join(
        hashlib.sha256(b"received-pack-reuse-v1" + i.to_bytes(4, "big")).digest()
        for i in range(2048)
    ))
    for version in range(8):
        if version:
            mutate(source, version)
        commit(commands, source, version)
    commands.git("-C", str(source), "tag", "-a", "seed", "HEAD~4", "-m", "seed history")
    commands.git("-C", str(source), "repack", "-adf", "--window=10", "--depth=10")
    indexes = list((source / ".git/objects/pack").glob("*.idx"))
    require(len(indexes) == 1, "fixture did not produce exactly one stock-Git pack")
    listing = commands.git("verify-pack", "-v", str(indexes[0]))
    deltas = [line for line in listing.splitlines()
              if re.match(r"^[0-9a-f]{40} blob ", line) and len(line.split()) == 7]
    require(bool(deltas), "fixture has no verified blob deltas")
    (root / "fixture.json").write_text(json.dumps({
        "blob_bytes": 65536, "versions": 8, "blob_deltas": len(deltas),
        "tip": commands.git("-C", str(source), "rev-parse", "HEAD"),
        "git_version": commands.git("--version"),
    }, indent=2) + "\n")


def records(path: Path) -> list[dict]:
    result = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue  # Includes incomplete readiness writes and final CliOutcome.
        if isinstance(record, dict):
            result.append(record)
    return result


def exercise(fg: str, fixture_root: Path, root: Path, transport: str, budget: str) -> None:
    root.mkdir()
    commands = Commands(root)
    source, first, fresh = root / "source", root / "first.git", root / "fresh.git"
    shutil.copytree(fixture_root / "source", source)
    summary = {"transport": transport, "received_pack_cache_mib": int(budget),
               "format": "sha1", "checks": {}, "passed": False}
    result_file = root / "result.json"

    def check(name: str, condition: bool, detail: str) -> None:
        summary["checks"][name] = {"ok": bool(condition), "detail": detail}
        result_file.write_text(json.dumps(summary, indent=2) + "\n")
        require(condition, f"{name}: {detail}")

    def compare(label: str, mirror: Path) -> None:
        source_refs = commands.git("-C", str(source), "for-each-ref", "--format=%(objectname) %(refname)")
        mirror_refs = commands.git("-C", str(mirror), "for-each-ref", "--format=%(objectname) %(refname)")
        (root / f"{label}.source.refs").write_text(source_refs + "\n")
        (root / f"{label}.mirror.refs").write_text(mirror_refs + "\n")
        check(f"{label}-refs", mirror_refs == source_refs, "all pushed refs equal the source")
        source_ids = sorted(commands.git("-C", str(source), "rev-list", "--objects", "--all", "--no-object-names").splitlines())
        mirror_ids = sorted(commands.git("-C", str(mirror), "rev-list", "--objects", "--all", "--no-object-names").splitlines())
        (root / f"{label}.source.objects").write_text("\n".join(source_ids) + "\n")
        (root / f"{label}.mirror.objects").write_text("\n".join(mirror_ids) + "\n")
        check(f"{label}-objects", mirror_ids == source_ids, "exact reachable native object-ID set")
        commands.git("-C", str(mirror), "fsck", "--strict")
        check(f"{label}-fsck", True, "git fsck --strict succeeded")

    remote_env = BASE_ENV.copy()
    credentials = ["--receive-principal", PRINCIPAL]
    server_command, listening, drained = "serve", "git_daemon_listening", "git_daemon_drained"
    if transport == "http":
        server_command, listening, drained = "serve-http", "smart_http_listening", "smart_http_drained"
        token = secrets.token_hex(32)
        private_file(root / "token", token + "\n")
        credentials = ["--trusted-local", "--token-file", str(root / "token"),
                       "--principal", PRINCIPAL, "--allow-receive"]
        # The token is absent from argv, command logs and persistent Git config.
        remote_env.update(GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="http.extraHeader",
                          GIT_CONFIG_VALUE_0=f"Authorization: Bearer {token}",
                          GIT_CONFIG_KEY_1="http.proxy", GIT_CONFIG_VALUE_1="")
    elif transport == "ssh":
        server_command, listening, drained = "serve-ssh", "ssh_listening", "ssh_drained"
        key = root / "client"
        commands.run([shutil.which("ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
                      "-f", str(key), "-C", "received-pack-reuse"])
        public = key.with_suffix(".pub").read_text().split()
        blob = base64.b64decode(public[1], validate=True)
        require(public[0] == "ssh-ed25519" and len(blob) == 51
                and blob[:19] == b"\0\0\0\x0bssh-ed25519\0\0\0\x20",
                "unexpected stock OpenSSH public-key encoding")
        private_file(root / "host-key", secrets.token_hex(32) + "\n")
        private_file(root / "deploy-keys", f"{blob[-32:].hex()} {PRINCIPAL} read,write\n")
        credentials = ["--host-key-file", str(root / "host-key"),
                       "--deploy-keys-file", str(root / "deploy-keys"), "--allow-receive"]
        remote_env.update(GIT_SSH_VARIANT="ssh", GIT_SSH_COMMAND=shlex.join([
            shutil.which("ssh"), "-F", os.devnull, "-i", str(key),
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}",
            "-o", f"GlobalKnownHostsFile={os.devnull}", "-o", "ConnectTimeout=5",
        ]))

    commands.run([fg, "init", str(root / "storage"), TENANT, REPOSITORY, "sha1"])
    stop, stdout, stderr = root / "stop", root / "server.out", root / "server.err"
    args = [fg, server_command, str(root / "storage"), TENANT, REPOSITORY, "127.0.0.1:0",
            *credentials, "--continuous", "--stop-file", str(stop), "--max-in-flight", "2",
            "--session-timeout-secs", "30", "--received-pack-cache-mib", budget,
            "--pack-cache-mib", "0"]
    if transport == "http":
        args += ["--processing-timeout-secs", "60"]
    else:
        args += ["--session-secs-per-mib", "0", "--session-max-extension-secs", "0"]
    (root / "server-argv.json").write_text(json.dumps(args, indent=2) + "\n")
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(args, env=BASE_ENV, stdin=subprocess.DEVNULL,
                                   stdout=out, stderr=err, start_new_session=True)
    OWNED.add(process)
    summary["server_pid"] = process.pid
    try:
        ready = []
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(process.poll() is None,
                    f"server exited before readiness: {stderr.read_text(errors='replace')[-4000:]}")
            ready = [row for row in records(stdout) if row.get("type") == listening]
            if ready:
                break
            time.sleep(0.02)
        enabled_field = "allow_receive" if transport == "ssh" else "receive_enabled"
        check("continuous", len(ready) == 1 and ready[0].get("lifetime") == "continuous"
              and ready[0].get(enabled_field) is True, "one continuous listener with explicit receive authority")
        if transport == "http":
            url = ready[0]["url"]
        else:
            address = ready[0]["address"]
            url = f"{transport}://{'git@' if transport == 'ssh' else ''}{address}/{REPOSITORY}.git"
        endpoint = urlsplit(url)
        require(endpoint.hostname == "127.0.0.1" and endpoint.scheme == transport
                and endpoint.port is not None and 1 <= endpoint.port <= 65535
                and endpoint.path == f"/{REPOSITORY}.git", "listener returned a foreign endpoint")

        def remote(*arguments: str) -> None:
            require(process.poll() is None, "the original serving process exited before client work")
            commands.git(*arguments, env=remote_env)
            require(process.poll() is None, "the original serving process exited during client work")

        remote("-C", str(source), "push", "--no-thin", url,
               "refs/heads/main:refs/heads/main", "refs/tags/seed:refs/tags/seed")
        # No earlier clone/fetch/export warms this process's upload path.
        remote("clone", "--mirror", url, str(first))
        compare("first", first)

        mutate(source, 8)
        commit(commands, source, 8)
        # Stock Git may send an external-base thin delta here. The updated
        # selection also differs from the first receipt: fallback must work.
        remote("-C", str(source), "push", url, "refs/heads/main:refs/heads/main")
        remote("-C", str(first), "fetch", "--prune", "origin")
        compare("fetch", first)
        remote("clone", "--mirror", url, str(fresh))
        compare("fresh", fresh)
        check("same-process", process.poll() is None, "push, first clone, increment, fetch and full clone used one process")

        private_file(stop, "all stock-client checks completed\n")
        process.wait(timeout=30)
        receipt = [row for row in records(stdout) if row.get("type") == drained]
        check("drain", process.returncode == 0 and len(receipt) == 1
              # HTTP's drain schema omits lifetime; its readiness was checked.
              and (transport == "http" or receipt[0].get("lifetime") == "continuous")
              and receipt[0].get("accepted", -1) == receipt[0].get("completed_transports", -2) + receipt[0].get("refused_transports", -3)
              and receipt[0].get("completed_transports", 0) >= 5,
              "server stopped cleanly and settled every accepted transport")
        summary["passed"] = True
    finally:
        kill_owned(process)
        process.wait(timeout=5)
        OWNED.discard(process)
        result_file.write_text(json.dumps(summary, indent=2) + "\n")


try:
    mode, fg_arg, fixture_arg, *case_args = sys.argv[1:]
    fg_path = str(Path(fg_arg).resolve(strict=True))
    fixture_path = Path(fixture_arg).resolve()
    if mode == "fixture":
        fixture(fixture_path)
    elif mode == "case":
        case_root, transport_name, cache_budget = case_args
        require(transport_name in ("git", "http", "ssh") and cache_budget in ("128", "0"),
                "invalid campaign case")
        exercise(fg_path, fixture_path, Path(case_root).resolve(), transport_name, cache_budget)
    else:
        raise RuntimeError("unknown campaign mode")
except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
    print(f"received-pack reuse stock-client campaign failed: {error}", file=sys.stderr)
    raise SystemExit(1)
finally:
    for child in tuple(OWNED):
        kill_owned(child)
        with contextlib.suppress(subprocess.TimeoutExpired):
            child.wait(timeout=5)
PY

mkdir "$WORK/fixture"
fge_capture fixture timeout --kill-after=10s 60s python3 "$WORK/driver.py" fixture "$FG_BIN" "$WORK/fixture" || true
fge_assert_exit RPR-fixture 0 "$FGE_LAST_EXIT" 'eight deterministic 64 KiB blob versions include verified stock-Git deltas'
[ "$FGE_LAST_EXIT" -eq 0 ] || fge_die 'cannot run transport twins without the delta-bearing fixture'
fge_artifact "$WORK/fixture/fixture.json" json

for transport in git http ssh; do
  for budget in 128 0; do
    label="$transport-$budget"
    case_root="$WORK/$label"
    fge_phase action
    fge_note "$label" "same-process push/first clone/incremental fetch/full clone, received-pack cache ${budget} MiB"
    # The whole small case has a 90-second ceiling; each child command has a
    # 60-second ceiling. The driver's signal handler contains all owned groups.
    fge_capture "$label" timeout --kill-after=10s 90s python3 "$WORK/driver.py" case \
      "$FG_BIN" "$WORK/fixture" "$case_root" "$transport" "$budget" || true
    fge_assert_exit "RPR-$label-run" 0 "$FGE_LAST_EXIT" 'the bounded stock-client transport case completed'
    fge_phase assert
    rows=$(python3 - "$case_root/result.json" <<'PY'
import json, sys
try:
    checks = json.load(open(sys.argv[1]))["checks"]
except (OSError, ValueError, KeyError):
    checks = {}
expected = ["continuous", "same-process", "drain"]
expected += [f"{stage}-{check}" for stage in ("first", "fetch", "fresh")
             for check in ("refs", "objects", "fsck")]
for name in expected:
    row = checks.get(name, {})
    print(name + "\t" + ("true" if row.get("ok") is True else "false"))
PY
)
    while IFS=$'\t' read -r check ok; do
      fge_assert_eq "RPR-$label-$check" true "$ok" "$label: $check"
    done <<< "$rows"
    if [ -f "$case_root/result.json" ]; then
      fge_artifact "$case_root/result.json" json
    fi
    for log in server-argv.json server.out server.err; do
      if [ -f "$case_root/$log" ]; then
        fge_artifact "$case_root/$log"
      fi
    done
  done
done

fge_phase teardown
