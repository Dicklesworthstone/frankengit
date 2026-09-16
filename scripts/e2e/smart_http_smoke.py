#!/usr/bin/env python3
"""Run real stock-Git interoperability against an already-built fg serve-http.

Requires Python 3.11+. No Rust build is performed and no substitute Git server
is used. All state, credentials and Git configuration are isolated in a
 temporary directory.
Usage: python3 scripts/e2e/smart_http_smoke.py --fg /absolute/path/to/fg
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

TENANT, REPOSITORY, PRINCIPAL = "c1" * 16, "c2" * 16, "c3" * 16
SECRETS: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def redact(text: str) -> str:
    for secret in SECRETS:
        text = text.replace(secret, "[REDACTED]")
    return text


def isolated_environment(root: Path) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and not k.upper().endswith("_PROXY")}
    env.update(HOME=str(root), XDG_CONFIG_HOME=str(root), GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0",
               GIT_AUTHOR_NAME="HTTP test", GIT_AUTHOR_EMAIL="http@example.test",
               GIT_COMMITTER_NAME="HTTP test", GIT_COMMITTER_EMAIL="http@example.test",
               GIT_AUTHOR_DATE="2000-01-01T00:00:00+0000",
               GIT_COMMITTER_DATE="2000-01-01T00:00:00+0000")
    return env


class Commands:
    def __init__(self, git: str, env: dict[str, str], timeout: int):
        self.git, self.env, self.timeout = git, env, timeout

    def run(self, args: list[str], *, env: dict[str, str] | None = None) -> str:
        result = subprocess.run(args, env=self.env if env is None else env,
                                capture_output=True, text=True, timeout=self.timeout)
        require(result.returncode == 0,
                redact(f"command failed ({result.returncode}): {args!r}\n"
                       f"{result.stdout[-8000:]}\n{result.stderr[-8000:]}"))
        return result.stdout.strip()

    def local_git(self, *args: str) -> str:
        return self.run([self.git, *args])

    def remote_git(self, token: str, version: int, *args: str, key: str | None = None) -> str:
        # Credentials stay out of argv and all persistent Git configuration.
        env = self.env.copy()
        config = [("http.extraHeader", f"Authorization: Bearer {token}"),
                  ("protocol.version", str(version)), ("http.proxy", "")]
        if key is not None:
            config.append(("http.extraHeader", f"Idempotency-Key: {key}"))
        env["GIT_CONFIG_COUNT"] = str(len(config))
        for index, (name, value) in enumerate(config):
            env[f"GIT_CONFIG_KEY_{index}"] = name
            env[f"GIT_CONFIG_VALUE_{index}"] = value
        return self.run([self.git, *args], env=env)


def seed(commands: Commands, root: Path, fmt: str) -> tuple[Path, str]:
    source = root / "source"
    commands.local_git("init", "-b", "main", f"--object-format={fmt}", str(source))
    (source / "README").write_text("native HTTP smoke\n" + "base content\n" * 2048)
    commands.local_git("-C", str(source), "add", "README")
    commands.local_git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-m", "initial")
    return source, commands.local_git("-C", str(source), "rev-parse", "HEAD")


@contextlib.contextmanager
def server(fg: str, commands: Commands, root: Path, token_file: Path,
           *, receive: bool):
    label = "writable" if receive else "readonly"
    stdout_path, stderr_path = root / f"{label}.out", root / f"{label}.err"
    args = [fg, "serve-http", str(root / "state"), TENANT, REPOSITORY, "127.0.0.1:0",
            "--trusted-local", "--token-file", str(token_file), "--principal", PRINCIPAL,
            "--idle-timeout-secs", "15", "--session-timeout-secs", "60",
            "--processing-timeout-secs", "60", "--max-sessions", "512", "--max-in-flight", "4"]
    if receive:
        args.append("--allow-receive")
    with stdout_path.open("w", encoding="utf-8") as out, stderr_path.open("w", encoding="utf-8") as err:
        process = subprocess.Popen(args, stdout=out, stderr=err, env=commands.env)
        try:
            start = time.monotonic()
            ready = None
            while time.monotonic() - start < commands.timeout:
                for line in stdout_path.read_text().splitlines():
                    try:
                        candidate = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if candidate.get("type") == "smart_http_listening":
                        ready = candidate
                        break
                if ready is not None:
                    break
                require(process.poll() is None,
                        redact("fg exited before HTTP readiness:\n" + stderr_path.read_text()[-8000:]))
                time.sleep(0.02)
            require(ready is not None, "fg did not report HTTP readiness before the deadline")
            url = ready["url"]
            require(url.startswith("http://127.0.0.1:") and url.endswith(f"/{REPOSITORY}.git"),
                    "fg returned an unexpected endpoint")
            require(ready["receive_enabled"] == receive, "wrong HTTP write policy")
            yield url
            # A clean lane waits for the listener's own idle retirement and drain,
            # not SIGTERM. Failure cleanup below never earns a successful result.
            process.wait(timeout=90)
            require(process.returncode == 0,
                    redact("HTTP service failed:\n" + stderr_path.read_text()[-8000:]))
            records = [json.loads(line) for line in stdout_path.read_text().splitlines() if line]
            drained = [record for record in records if record.get("type") == "smart_http_drained"]
            require(len(drained) == 1, "HTTP parent did not report a completed drain")
            receipt = drained[0]
            require(receipt["accepted"] == receipt["completed_transports"] + receipt["refused_transports"],
                    "HTTP drain did not settle all accepted connections")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def http_status(url: str, headers: dict[str, str]) -> int:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as response:
        try:
            return response.code
        finally:
            response.close()


def exercise(fg: str, git: str, root: Path, fmt: str, timeout: int) -> None:
    root.mkdir()
    commands = Commands(git, isolated_environment(root / "home"), timeout)
    token = secrets.token_hex(32)
    SECRETS.append(token)
    token_file = root / "token"
    with os.fdopen(os.open(token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
        output.write(token + "\n")
    commands.run([fg, "init", str(root / "state"), TENANT, REPOSITORY, fmt])
    source, initial = seed(commands, root, fmt)
    with server(fg, commands, root, token_file, receive=True) as url:
        require(http_status(url + "/info/refs?service=git-upload-pack", {}) == 401,
                "unauthenticated discovery disclosed repository state")
        require(http_status(url + "/info/refs?service=git-upload-pack", {"X-Forwarded-User": "admin"}) == 401,
                "forwarded identity bypassed authentication")
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/main", key="initial-push")
        clones = []
        for version in (0, 1, 2):
            clone = root / f"clone-v{version}"
            commands.remote_git(token, version, "clone", "--branch", "main", url, str(clone))
            require(commands.local_git("-C", str(clone), "rev-parse", "HEAD") == initial,
                    f"protocol v{version} clone selected the wrong commit")
            require((clone / "README").read_bytes() == (source / "README").read_bytes(), "clone changed bytes")
            commands.local_git("-C", str(clone), "fsck", "--strict")
            clones.append(clone)
        with (source / "README").open("a") as output:
            output.write("incremental update\n")
        commands.local_git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-am", "incremental")
        tip = commands.local_git("-C", str(source), "rev-parse", "HEAD")
        commands.remote_git(token, 2, "-C", str(source), "push", url, "HEAD:refs/heads/main", key="incremental-push")
        for version, clone in enumerate(clones):
            commands.remote_git(token, version, "-C", str(clone), "fetch", url, "refs/heads/main")
            require(commands.local_git("-C", str(clone), "rev-parse", "FETCH_HEAD") == tip, "incremental fetch selected the wrong tip")
            commands.local_git("-C", str(clone), "fsck", "--strict")
        shallow = root / "shallow"
        commands.remote_git(token, 2, "clone", "--depth", "1", "--branch", "main", url, str(shallow))
        require(commands.local_git("-C", str(shallow), "rev-list", "--count", "HEAD") == "1", "shallow clone ignored its boundary")
        commands.local_git("-C", str(shallow), "fsck", "--strict")
        commands.local_git("-C", str(source), "-c", "tag.gpgsign=false", "tag", "-a", "http-release", "-m", "HTTP release")
        commands.remote_git(token, 2, "-C", str(source), "push", url, "refs/tags/http-release", key="tag-push")
        for version in (0, 1, 2):
            refs = commands.remote_git(token, version, "ls-remote", url)
            require(f"{tip}\trefs/tags/http-release^{{}}" in refs.splitlines(), "annotated tag discovery omitted its verified peel")
        commands.remote_git(token, 2, "-C", str(source), "push", url, ":refs/tags/http-release", key="tag-delete")
        refs = commands.remote_git(token, 2, "ls-remote", url)
        require("refs/tags/http-release" not in refs, "delete-only push left the tag visible")
    with server(fg, commands, root, token_file, receive=False) as url:
        headers = {"Authorization": f"Bearer {token}"}
        require(http_status(url + "/info/refs?service=git-receive-pack", headers) == 403,
                "read-only HTTP service advertised writes")
        refs = commands.remote_git(token, 2, "ls-remote", url)
        require(f"{tip}\trefs/heads/main" in refs.splitlines(), "restart lost a durably published branch")
    print(json.dumps({"type": "smart_http_smoke_passed", "format": fmt,
                      "initial_commit": initial, "final_commit": tip,
                      "protocols": [0, 1, 2]}), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True, type=Path, help="already-built fg executable")
    parser.add_argument("--git", default="git", help="stock Git oracle executable")
    parser.add_argument("--format", action="append", choices=("sha1", "sha256"), dest="formats")
    parser.add_argument("--timeout", type=int, default=180, help="per-command timeout in seconds (1..600)")
    options = parser.parse_args()
    require(1 <= options.timeout <= 600, "timeout must be in 1..600")
    fg = options.fg.resolve(strict=True)
    require(fg.is_file() and os.access(fg, os.X_OK), "--fg must be an executable file")
    git = shutil.which(options.git)
    require(git is not None, "stock Git executable was not found")
    with fg.open("rb") as binary:
        digest = hashlib.file_digest(binary, "sha256").hexdigest()
    with tempfile.TemporaryDirectory(prefix="fg-smart-http-smoke-") as temp:
        root = Path(temp)
        commands = Commands(git, isolated_environment(root / "home"), options.timeout)
        print(json.dumps({"type": "smart_http_smoke_started", "fg_binary_sha256": digest,
                          "git_version": commands.local_git("--version")}), flush=True)
        for fmt in dict.fromkeys(options.formats or ["sha1", "sha256"]):
            exercise(str(fg), git, root / fmt, fmt, options.timeout)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(redact(f"smart HTTP smoke FAILED: {error}"), file=sys.stderr)
        raise SystemExit(1)
