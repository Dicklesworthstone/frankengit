#!/usr/bin/env python3
"""Real fg serve-http and fg verify-read, using native Git objects, no Git subprocess.

The trusted head comes from a separate trusted-local fg show process. Proof
responses do not supply it. Artifacts remain under --work-dir on failure.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import subprocess
import time
from urllib.parse import urlsplit

from source_browse_smoke import loose, tree

TENANT, REPOSITORY, PRINCIPAL = "b1" * 16, "b2" * 16, "b3" * 16


class Commands:
    def __init__(self, binary: Path, root: Path):
        self.binary, self.root, self.sequence = binary, root, 0

    def run(self, args, expected=0):
        self.sequence += 1
        result = subprocess.run([str(self.binary), *map(str, args)], capture_output=True, timeout=180)
        (self.root / f"command-{self.sequence:03}.stdout").write_bytes(result.stdout)
        (self.root / f"command-{self.sequence:03}.stderr").write_bytes(result.stderr)
        assert result.returncode == expected, (args, result.returncode, result.stdout[-4096:], result.stderr[-8192:])
        if expected != 0:
            assert not result.stdout, "refused proof command emitted output bytes"
        return result


@contextlib.contextmanager
def server(commands: Commands, node: Path, credentials: Path, label: str):
    root = commands.root
    stdout, stderr, stop = root / f"{label}.stdout", root / f"{label}.stderr", root / f"{label}.stop"
    args = [str(commands.binary), "serve-http", str(node), TENANT, REPOSITORY,
            "127.0.0.1:0", "--trusted-local", "--credentials-file", str(credentials),
            "--allow-source", "--continuous", "--stop-file", str(stop),
            "--max-in-flight", "2", "--session-timeout-secs", "60"]
    with stdout.open("wb") as out, stderr.open("wb") as err:
        process = subprocess.Popen(args, stdout=out, stderr=err)
        try:
            ready = None
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                for line in stdout.read_text().splitlines():
                    record = json.loads(line)
                    if record.get("type") == "smart_http_listening":
                        ready = record
                        break
                if ready:
                    break
                assert process.poll() is None, stderr.read_text()
                time.sleep(0.02)
            assert ready and ready["source_enabled"] is True, "proof server did not become ready"
            yield ready["url"]
            stop.touch(exist_ok=False)
            process.wait(timeout=90)
            assert process.returncode == 0, stderr.read_text()
            drained = [json.loads(line) for line in stdout.read_text().splitlines()
                       if json.loads(line).get("type") == "smart_http_drained"]
            assert len(drained) == 1
            assert drained[0]["accepted"] == drained[0]["completed_transports"] + drained[0]["refused_transports"]
        finally:
            if process.poll() is None:
                if not stop.exists():
                    stop.touch()
                try:
                    process.wait(timeout=90)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
                    raise RuntimeError("proof server failed its drain deadline; artifacts retained")


def proof(url: str, token: str, head: str, path: bytes) -> tuple[int, bytes]:
    selected = urlsplit(url)
    assert selected.scheme == "http" and selected.hostname == "127.0.0.1"
    target = (selected.path + "/api/v1/source/verified-blob?ref_hex="
              + b"refs/heads/main".hex() + "&path_hex=" + path.hex() + "&expected_head=" + head)
    connection = http.client.HTTPConnection(selected.hostname, selected.port, timeout=60)
    try:
        connection.request("GET", target, headers={"Authorization": "Bearer " + token,
                           "User-Agent": "FrankenGit-E2E/0.0.1", "Connection": "close"})
        response = connection.getresponse()
        body = response.read(32 * 1024 * 1024 + 128 * 1024 + 1)
        assert len(body) <= 32 * 1024 * 1024 + 128 * 1024
        assert int(response.getheader("Content-Length")) == len(body)
        if response.status == 200:
            assert response.getheader("Content-Type") == "application/vnd.frankengit.verified-blob"
        return response.status, body
    finally:
        connection.close()


def campaign(binary: Path, root: Path, fmt: str, entries: int):
    root.mkdir()
    commands = Commands(binary, root)
    source, node = root / "source", root / "node"
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    (source / "config").write_text("[core]\nbare = true\nrepositoryformatversion = "
        + ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat = sha256\n"))
    payload = b"\0\xffnative proof bytes\r\nwithout-final"
    blob = loose(source, fmt, "blob", payload)
    path = f"file-{entries - 1:05}".encode()
    root_tree = loose(source, fmt, "tree", tree([(f"file-{number:05}".encode(), b"100644", blob)
                                                for number in range(entries)]))
    commit = loose(source, fmt, "commit", f"tree {root_tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\nproof fixture\n".encode())
    (source / "refs/heads/main").write_text(commit + "\n")
    commands.run(["init", node, TENANT, REPOSITORY, fmt, "--root-layout", "ref-merkle-v1"])
    commands.run(["import", node, TENANT, REPOSITORY, PRINCIPAL, "proof-source", source])
    common = [node, TENANT, REPOSITORY, "--trusted-local", "--ref", "refs/heads/main", "--object-format", fmt]
    # A selected-file grant avoids the distinct local root-listing scope limit
    # while still pinning authority independently from the HTTP proof server.
    pin_query = ["show", *common, "--path-hex", path.hex(), "--max-bytes", "1"]
    selected = json.loads(commands.run(pin_query).stdout)
    trusted = selected["snapshot_token"]
    assert selected["source_commit"] == commit
    token = secrets.token_hex(32)
    token_file = root / "reader.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    header = commands.run(["serve-http", node, TENANT, REPOSITORY, "127.0.0.1:0",
                           "--trusted-local", "--print-credentials-header"]).stdout
    credentials = root / "credentials"
    credentials.write_bytes(header + f"{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} read\n".encode())
    credentials.chmod(0o600)
    proof_file = root / "source.proof"
    expectations = ["--trusted-head", trusted, "--ref", "refs/heads/main", "--path-hex", path.hex()]
    with server(commands, node, credentials, "initial") as url:
        start = time.perf_counter_ns()
        result = commands.run(["verify-read", "--url", url, "--token-file", token_file, *expectations])
        fetch_verify_ns = time.perf_counter_ns() - start
        assert result.stdout == payload
        destination = root / "verified.bin"
        receipt = json.loads(commands.run(["verify-read", "--url", url, "--token-file", token_file,
                                          *expectations, "--output", destination]).stdout)
        assert destination.read_bytes() == payload and receipt["verified"] is True
        assert receipt["object_id"] == blob and receipt["source_commit"] == commit
        status, frame = proof(url, token, trusted, path)
        assert status == 200
        proof_file.write_bytes(frame)
        assert proof(url, "0" * 64, trusted, path)[0] == 401
    verify_samples = []
    for _ in range(3):
        start = time.perf_counter_ns()
        result = commands.run(["verify-read", "--input", proof_file, *expectations])
        verify_samples.append(time.perf_counter_ns() - start)
        assert result.stdout == payload
    tampered = root / "tampered.proof"
    changed = bytearray(frame)
    changed[-1] ^= 1
    tampered.write_bytes(changed)
    refusal = json.loads(commands.run(["verify-read", "--input", tampered, *expectations], 2).stderr)
    assert refusal["verified"] is False
    assert refusal["code"] in ("invalid_envelope", "verification_refused")
    wrong = expectations.copy()
    wrong[-1] = b"other".hex()
    assert json.loads(commands.run(["verify-read", "--input", proof_file, *wrong], 2).stderr)["verified"] is False
    # A new canonical ref publication advances the independently obtained head.
    # Old bytes stay valid only under the old pin; they cannot answer the new pin.
    commands.run(["branch", "create", node, TENANT, REPOSITORY,
                  "--trusted-local", "--principal", PRINCIPAL,
                  "--idempotency-key", "advance-proof-pin",
                  "--ref", "refs/heads/proof-pin-advance", "--target", commit,
                  "--object-format", fmt])
    current = json.loads(commands.run(pin_query).stdout)["snapshot_token"]
    assert current != trusted
    newer = expectations.copy()
    newer[1] = current
    refusal = json.loads(commands.run(["verify-read", "--input", proof_file, *newer], 2).stderr)
    assert refusal["verified"] is False and "HeadMismatch" in refusal["error"]
    with server(commands, node, credentials, "advanced") as url:
        refusal = json.loads(commands.run(["verify-read", "--url", url, "--token-file", token_file,
                                          *expectations], 2).stderr)
        assert refusal["code"] == "http_status" and "409" in refusal["error"]
        assert commands.run(["verify-read", "--url", url, "--token-file", token_file, *newer]).stdout == payload
    print(json.dumps({"type": "verified_blob_http_campaign", "object_format": fmt,
        "tree_entries": entries, "frame_bytes": len(frame), "blob_bytes": len(payload),
        "fetch_and_verify_process_ns": fetch_verify_ns, "verify_file_process_ns": verify_samples,
        "independent_pin": True, "tamper_refused": True, "stale_pin_refused": True,
        "drained": True}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fg", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    binary = args.fg.resolve(strict=True)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    for fmt, entries in [("sha1", 4), ("sha256", 4), ("sha256", 10_000)]:
        campaign(binary, args.work_dir / f"{fmt}-{entries}", fmt, entries)


if __name__ == "__main__":
    main()
