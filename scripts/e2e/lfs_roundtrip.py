#!/usr/bin/env python3
"""Exercise native Git LFS basic transfer with an installed stock git-lfs client.

Uses only an explicitly prebuilt fg, isolated repositories and loopback sockets.
Records the installed client versions and binary digest; this is interoperability
evidence, not a pinned-client differential or full FG-053 acceptance campaign.
All command logs and listener drain receipts remain in --artifact-dir on failure.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse

from continuous_git_transports_smoke import LoggedCommands, digest, private_file, records
from smart_http_smoke import PRINCIPAL, REPOSITORY, SECRETS, TENANT, isolated_environment, redact, require

MEDIA = "application/vnd.git-lfs+json"
MAX_REPLY = 2 * 1024 * 1024
SCOPES = {"full": "read,receive,lfs-read,lfs-write", "git": "read,receive",
          "read": "lfs-read", "write": "lfs-write"}


def object_id(data: bytes) -> dict:
    return {"oid": hashlib.sha256(data).hexdigest(), "size": len(data)}


def exchange(url: str, method: str, token: str | None, data: bytes | None = None,
             *, media: str = MEDIA, headers: dict | None = None) -> tuple[int, bytes]:
    endpoint = urllib.parse.urlsplit(url)
    require(endpoint.scheme == "http" and endpoint.hostname == "127.0.0.1"
            and not endpoint.username and not endpoint.password, "non-local or credential-bearing action URL")
    request_headers = {"Connection": "close", "Accept": MEDIA}
    if data is not None:
        request_headers["Content-Type"] = media
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    request_headers.update(headers or {})
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=30)
    try:
        connection.request(method, endpoint.path, body=data, headers=request_headers)
        response = connection.getresponse()
        body = response.read(MAX_REPLY + 1)
        require(len(body) <= MAX_REPLY, "LFS response exceeded the campaign bound")
        return response.status, body
    finally:
        connection.close()


def batch(url: str, token: str | None, operation: str, objects: list[dict],
          *, expected: int = 200, **options) -> dict:
    body = {"operation": operation, "transfers": ["basic"], "objects": objects, **options}
    status, response = exchange(url + "/info/lfs/objects/batch", "POST", token,
                                json.dumps(body).encode())
    require(status == expected, f"{operation} batch returned {status}, expected {expected}: {response!r}")
    result = json.loads(response)
    if expected == 200:
        require(result.get("transfer") == "basic", "server did not select basic transfer")
        require(result.get("hash_algo", "sha256") == "sha256", "server changed LFS hash domain")
        require([(o.get("oid"), o.get("size")) for o in result["objects"]]
                == [(o["oid"], o["size"]) for o in objects], "batch changed object identity/order")
    return result


def action(url: str, entry: dict, name: str) -> str:
    href = entry["actions"][name]["href"]
    require(href.startswith(url + "/info/lfs/objects/"), "action left the selected repository/origin")
    require(all(secret not in href for secret in SECRETS), "action URL disclosed a credential")
    return href


def grants(path: Path, header: str, tokens: dict[str, str], *, omit: str | None = None) -> None:
    replacement = path.with_suffix(".next")
    private_file(replacement, header + "\n" + "".join(
        f"{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} {SCOPES[name]}\n"
        for name, token in tokens.items() if name != omit))
    replacement.replace(path)


@contextlib.contextmanager
def server(fg: str, commands: LoggedCommands, root: Path, table: Path, label: str,
           *, lfs: bool, receive: bool):
    stop = root / f"{label}.stop"
    args = [fg, "serve-http", str(root / "state"), TENANT, REPOSITORY, "127.0.0.1:0",
            "--trusted-local", "--credentials-file", str(table), "--continuous",
            "--stop-file", str(stop), "--max-in-flight", "4",
            "--session-timeout-secs", "30", "--processing-timeout-secs", "90"]
    if lfs:
        args.extend(["--lfs-root", str(root / "fabric")])
    if receive:
        args.append("--allow-receive")
    with commands.start(args) as child:
        try:
            end = time.monotonic() + commands.timeout
            ready = []
            while time.monotonic() < end:
                ready = [r for r in records(child.stdout) if r.get("type") == "smart_http_listening"]
                if ready:
                    break
                require(child.process.poll() is None,
                        "fg exited before readiness: " + child.stderr.read_text(errors="replace")[-8000:])
                time.sleep(0.02)
            require(len(ready) == 1, "missing or duplicate HTTP readiness")
            require(ready[0].get("lifetime") == "continuous", "listener lifetime was not continuous")
            require(ready[0].get("lfs_enabled") == lfs and ready[0].get("receive_enabled") == receive,
                    "HTTP service enablement did not match explicit options")
            url = ready[0]["url"]
            require(url.startswith("http://127.0.0.1:") and url.endswith(f"/{REPOSITORY}.git"),
                    "listener returned an unexpected repository URL")
            yield url
            private_file(stop, "LFS campaign completed; drain accepted transports\n")
            child.finish(timeout=90)
            receipts = [r for r in records(child.stdout) if r.get("type") == "smart_http_drained"]
            require(len(receipts) == 1, "missing or duplicate native HTTP drain receipt")
            receipt = receipts[0]
            require(receipt["accepted"] == receipt["completed_transports"] + receipt["refused_transports"],
                    "listener left accepted transports unsettled")
        finally:
            # A failed assertion still requests bounded graceful shutdown. The
            # owned Child context terminates/reaps its group if that cannot finish;
            # forced cleanup never supplies a successful drain assertion.
            if child.process.poll() is None:
                if not stop.exists():
                    private_file(stop, "LFS campaign failure cleanup\n")
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.process.wait(timeout=10)


def truncated_upload(url: str, token: str, data: bytes) -> None:
    endpoint = urllib.parse.urlsplit(url)
    with socket.create_connection((endpoint.hostname, endpoint.port), timeout=30) as stream:
        stream.sendall((f"PUT {endpoint.path} HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                        f"Authorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\n"
                        f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n").encode()
                       + data[:len(data) // 2])
        stream.shutdown(socket.SHUT_WR)
        response = http.client.HTTPResponse(stream)
        try:
            response.begin()
            require(400 <= response.status < 500, "truncated upload was acknowledged or treated as server success")
            require(len(response.read(MAX_REPLY + 1)) <= MAX_REPLY, "unbounded interrupted-upload response")
        finally:
            response.close()


def verify_transfer_edges(url: str, tokens: dict[str, str], known: dict, payload: bytes) -> None:
    full, reader, writer = tokens["full"], tokens["read"], tokens["write"]
    missing = object_id(b"not uploaded")
    response = batch(url, reader, "download", [known, missing])
    known_url = action(url, response["objects"][0], "download")
    require(response["objects"][1].get("error", {}).get("code") == 404,
            "one missing object did not receive an independent 404")
    require(exchange(known_url, "GET", reader) == (200, payload), "read grant did not return exact binary bytes")
    for token, expected in ((None, 401), (tokens["git"], 403), (writer, 403)):
        status, body = exchange(known_url, "GET", token)
        require(status == expected and payload not in body, "unauthorized download disclosed object bytes")
        batch(url, token, "download", [known], expected=expected)
    batch(url, reader, "upload", [known], expected=403)

    candidate_bytes = b"\0safe retry with exact content identity\xff" * 97
    candidate = object_id(candidate_bytes)
    entry = batch(url, writer, "upload", [candidate])["objects"][0]
    put, verify = action(url, entry, "upload"), action(url, entry, "verify")
    require(exchange(put, "PUT", reader, candidate_bytes, media="application/octet-stream")[0] == 403,
            "read grant gained upload authority")
    for bad in (b"x" * len(candidate_bytes), candidate_bytes[:-1]):
        require(exchange(put, "PUT", writer, bad, media="application/octet-stream")[0] == 400,
                "digest or declared-size mismatch was accepted")
        require(batch(url, reader, "download", [candidate])["objects"][0].get("error", {}).get("code") == 404,
                "invalid upload became visible")
    truncated_upload(put, writer, candidate_bytes)
    require(batch(url, reader, "download", [candidate])["objects"][0].get("error", {}).get("code") == 404,
            "interrupted upload became visible")
    for _ in range(2):
        require(exchange(put, "PUT", writer, candidate_bytes, media="application/octet-stream")[0] == 200,
                "same-object retry was not accepted idempotently")
    require(exchange(verify, "POST", writer, json.dumps(candidate).encode())[0] == 200,
            "exact upload verification failed")
    for wrong in ({**candidate, "oid": known["oid"]}, {**candidate, "size": candidate["size"] + 1}):
        require(exchange(verify, "POST", writer, json.dumps(wrong).encode())[0] == 400,
                "verify accepted a different digest or size")
    require("actions" not in batch(url, writer, "upload", [candidate])["objects"][0],
            "completed upload was needlessly scheduled again")
    download = action(url, batch(url, reader, "download", [candidate])["objects"][0], "download")
    require(exchange(download, "GET", reader) == (200, candidate_bytes), "retry changed stored bytes")

    foreign = url.replace(REPOSITORY + ".git", "f0" * 16 + ".git")
    status, refused = exchange(foreign + "/info/lfs/objects/batch", "POST", full,
                               json.dumps({"operation": "download", "objects": [known]}).encode())
    require(status == 404 and payload not in refused,
            "foreign repository route exposed LFS custody")
    batch(url, full, "download", [known], transfers=["tus"], expected=400)
    batch(url, full, "download", [known], hash_algo="sha1", expected=400)
    oversized = {"oid": "01" * 32, "size": 64 * 1024 * 1024 + 1}
    require(batch(url, writer, "upload", [oversized])["objects"][0].get("error", {}).get("code") == 413,
            "oversized object did not receive a bounded per-item refusal")
    status, raw = exchange(url + "/info/lfs/objects/batch", "POST", full,
                           json.dumps({"operation": "download", "objects": [known]}).encode(),
                           headers={"Host": "untrusted.example"})
    require(status == 200, "Host-spoof test did not reach the LFS batch response")
    action(url, json.loads(raw)["objects"][0], "download")


def exercise(fg: str, git: str, root: Path, fmt: str, timeout: int) -> dict:
    root.mkdir(mode=0o700)
    commands = LoggedCommands(git, isolated_environment(root / "home"), timeout, root / "commands")
    tokens = {name: secrets.token_hex(32) for name in SCOPES}
    SECRETS.extend(tokens.values())
    commands.run([fg, "init", str(root / "state"), TENANT, REPOSITORY, fmt])
    header = commands.run([fg, "serve-http", str(root / "state"), TENANT, REPOSITORY,
                           "127.0.0.1:0", "--trusted-local", "--print-credentials-header"])
    table = root / "credentials"
    grants(table, header, tokens)
    (root / "fabric").mkdir(mode=0o700)
    source = root / "source"
    commands.local_git("init", "-b", "main", f"--object-format={fmt}", str(source))
    commands.local_git("-C", str(source), "lfs", "install", "--local")
    commands.local_git("-C", str(source), "lfs", "track", "*.bin")
    payload = bytes(range(256)) * 1024 + b"\0native Git LFS binary round trip\xff"
    known = object_id(payload)
    (source / "asset.bin").write_bytes(payload)
    commands.local_git("-C", str(source), "add", ".gitattributes", "asset.bin")
    commands.local_git("-C", str(source), "-c", "commit.gpgsign=false", "commit", "-m", "tracked LFS asset")
    pointer = commands.local_git("-C", str(source), "show", "HEAD:asset.bin")
    require(pointer == f"version https://git-lfs.github.com/spec/v1\noid sha256:{known['oid']}\nsize {known['size']}",
            "stock git-lfs did not create the expected SHA-256 pointer")
    tip = commands.local_git("-C", str(source), "rev-parse", "HEAD")

    with server(fg, commands, root, table, "upload", lfs=True, receive=True) as url:
        commands.local_git("-C", str(source), "remote", "add", "origin", url)
        commands.remote_git(tokens["full"], 2, "-C", str(source), "push", "origin", "HEAD:refs/heads/main")
        require("actions" not in batch(url, tokens["write"], "upload", [known])["objects"][0],
                "stock pre-push hook did not upload the tracked object")
        verify_transfer_edges(url, tokens, known, payload)
        grants(table, header, tokens, omit="full")
        batch(url, tokens["full"], "download", [known], expected=401)
        direct = f"{url}/info/lfs/objects/{known['oid']}/{known['size']}"
        require(exchange(direct, "GET", tokens["full"])[0] == 401, "revoked action credential was cached")
        grants(table, header, tokens)
        batch(url, tokens["full"], "download", [known])

    # A fresh node and independent clone must obtain bytes from durable fabric,
    # not the original client cache. LFS writes do not require Git receive.
    with server(fg, commands, root, table, "restart", lfs=True, receive=False) as url:
        clone = root / "clone"
        commands.remote_git(tokens["full"], 2, "clone", "--no-checkout", "--branch", "main", url, str(clone))
        commands.local_git("-C", str(clone), "lfs", "install", "--local")
        skip_smudge = commands.env.copy()
        skip_smudge["GIT_LFS_SKIP_SMUDGE"] = "1"
        commands.run([git, "-C", str(clone), "checkout", "--force", "main"], env=skip_smudge)
        commands.remote_git(tokens["full"], 2, "-C", str(clone), "lfs", "pull", "origin", "main")
        require((clone / "asset.bin").read_bytes() == payload, "restarted clone/pull changed binary content")
        require(commands.local_git("-C", str(clone), "rev-parse", "HEAD") == tip, "clone changed Git identity")
        require(commands.local_git("-C", str(clone), "show", "HEAD:asset.bin") == pointer,
                "server rewrote the native Git pointer")
        commands.local_git("-C", str(clone), "lfs", "fsck")
        commands.local_git("-C", str(clone), "fsck", "--strict")
        extra = b"artifact custody independent of receive-pack"
        item = object_id(extra)
        put = action(url, batch(url, tokens["write"], "upload", [item])["objects"][0], "upload")
        require(exchange(put, "PUT", tokens["write"], extra, media="application/octet-stream")[0] == 200,
                "disabled Git receive incorrectly disabled LFS write grants")

    with server(fg, commands, root, table, "disabled", lfs=False, receive=False) as url:
        batch(url, tokens["full"], "download", [known], expected=403)
        require(exchange(f"{url}/info/lfs/objects/{known['oid']}/{known['size']}", "GET", tokens["full"])[0] == 403,
                "default-disabled service disclosed retained LFS content")
    return {"type": "lfs_roundtrip_passed", "format": fmt, "tip": tip, "lfs_object": known,
            "checks": ["stock-lfs-push", "durable-restart-clone-pull", "pointer-and-binary-identity",
                       "independent-scopes", "revocation", "per-object-missing", "digest-and-size-refusal",
                       "interrupted-upload-retry", "idempotent-upload", "verify", "foreign-repository",
                       "unsupported-transfer-and-hash", "bounded-object-size", "untrusted-host",
                       "independent-receive-policy", "default-disabled", "all-listeners-drained"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", type=Path, required=True)
    parser.add_argument("--git", default="git")
    parser.add_argument("--format", choices=("sha1", "sha256"), action="append", dest="formats")
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--artifact-dir", type=Path, help="new directory, retained for diagnostics")
    args = parser.parse_args()
    require(1 <= args.timeout <= 600, "command timeout must be in 1..600 seconds")
    fg = args.fg.resolve(strict=True)
    git = shutil.which(args.git)
    require(fg.is_file() and os.access(fg, os.X_OK) and git is not None, "prebuilt fg or stock Git missing")
    root = args.artifact_dir
    if root is None:
        root = Path(tempfile.mkdtemp(prefix="fg-lfs-roundtrip-"))
    else:
        root.mkdir(parents=True, mode=0o700, exist_ok=False)
    try:
        commands = LoggedCommands(git, isolated_environment(root / "home"), args.timeout, root / "commands")
        print(json.dumps({"type": "lfs_roundtrip_started", "fg_binary_sha256": digest(fg),
                          "git_version": commands.local_git("--version"),
                          "git_lfs_version": commands.local_git("lfs", "version"),
                          "artifacts": str(root), "non_claim": "installed-client interoperability; not pinned differential"}), flush=True)
        for fmt in dict.fromkeys(args.formats or ["sha1", "sha256"]):
            print(json.dumps(exercise(str(fg), git, root / fmt, fmt, args.timeout)), flush=True)
        return 0
    except BaseException:
        print(f"LFS round-trip artifacts retained at {root}", file=sys.stderr)
        raise


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise InterruptedError(f"LFS campaign received signal {signum}; draining owned children")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError, http.client.HTTPException) as error:
        print(redact(f"LFS round trip FAILED: {error}"), file=sys.stderr)
        raise SystemExit(1)
