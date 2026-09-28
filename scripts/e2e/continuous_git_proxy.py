#!/usr/bin/env python3
"""Test-only stock-Git byte relay with a receive PACK-header barrier.

Used by continuous_git_transports_smoke.py as GIT_PROXY_COMMAND (raw Git) or
GIT_SSH_COMMAND (a cleartext stdio wrapper around the real OpenSSH client).
The relay never creates a Git command, PACK, advertisement, or report-status.
It forwards the client's complete atomic command section and 12-byte PACK
header, then withholds the remaining client bytes until the harness releases
it. Thus a barrier is evidence of a real advertised, authenticated where
applicable, in-flight stock-client push, not a sleep timed around a fast push.
"""
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import time

LIMIT = 4 * 1024 * 1024
CHUNK = 16 * 1024


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


class Prefix:
    def __init__(self, raw: bool):
        self.state = "greeting" if raw else "commands"
        self.pending = bytearray()
        self.commands: list[str] = []
        self.prefix_bytes = 0
        self.pack_objects = 0

    def consume(self, data: bytes) -> bytes:
        """Return only prefix bytes; retain PACK content until release."""
        self.pending.extend(data)
        result = bytearray()
        while self.state != "held":
            if self.state == "pack":
                if len(self.pending) < 12:
                    break
                header = bytes(self.pending[:12])
                require(header[:4] == b"PACK", "stock push did not supply a PACK")
                require(int.from_bytes(header[4:8], "big") in (2, 3), "invalid PACK version")
                self.pack_objects = int.from_bytes(header[8:12], "big")
                require(self.pack_objects > 0, "barrier requires a nonempty stock PACK")
                result.extend(header)
                del self.pending[:12]
                self.state = "held"
                break
            if len(self.pending) < 4:
                break
            spelling = self.pending[:4]
            require(all(c in b"0123456789abcdefABCDEF" for c in spelling), "invalid pkt-line header")
            size = int(spelling, 16)
            require(size == 0 or 4 <= size <= 65520, "invalid receive pkt-line length")
            if size == 0:
                require(self.state == "commands" and len(self.commands) == 2,
                        "held push must contain exactly two atomic ref commands")
                result.extend(self.pending[:4])
                del self.pending[:4]
                self.state = "pack"
                continue
            if len(self.pending) < size:
                break
            packet = bytes(self.pending[:size])
            del self.pending[:size]
            self.prefix_bytes += size
            require(self.prefix_bytes <= LIMIT, "receive command prefix exceeds test bound")
            payload = packet[4:]
            if self.state == "greeting":
                require(payload.startswith(b"git-receive-pack /"), "proxy is only for receive-pack")
                self.state = "commands"
            else:
                command, _, capabilities = payload.partition(b"\0")
                fields = command.rstrip(b"\n").split(b" ")
                require(len(fields) == 3 and fields[2].startswith(b"refs/heads/"),
                        "unexpected receive command")
                if not self.commands:
                    require(b"atomic" in capabilities.split(), "held stock push did not negotiate atomic")
                    require(any(c in capabilities.split() for c in (b"report-status", b"report-status-v2")),
                            "held stock push did not negotiate report-status")
                self.commands.append(fields[2].decode("ascii"))
                require(len(self.commands) <= 2, "too many receive commands at barrier")
            result.extend(packet)
        return bytes(result)


def relay(mode: str, arguments: list[str]) -> int:
    ready = Path(os.environ["FG_CONTINUOUS_BARRIER_READY"])
    release = Path(os.environ["FG_CONTINUOUS_BARRIER_RELEASE"])
    timeout = int(os.environ.get("FG_CONTINUOUS_PROXY_TIMEOUT", "180"))
    require(1 <= timeout <= 600, "invalid proxy timeout")
    require(not ready.exists() and not release.exists(), "barrier controls already exist")
    deadline = time.monotonic() + timeout
    connection = None
    ssh = None
    try:
        if mode == "raw":
            require(len(arguments) == 2 and arguments[0] == "127.0.0.1", "proxy target must be loopback")
            connection = socket.create_connection((arguments[0], int(arguments[1])), timeout=10)
            reader = writer = connection.fileno()
        else:
            require(mode == "ssh" and bool(arguments), "missing system ssh command")
            # stderr is inherited into the stock Git invocation's captured log.
            ssh = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            assert ssh.stdin is not None and ssh.stdout is not None
            reader, writer = ssh.stdout.fileno(), ssh.stdin.fileno()
        for fd in set((0, 1, reader, writer)):
            os.set_blocking(fd, False)
        prefix = Prefix(mode == "raw")
        to_server, to_client = bytearray(), bytearray()
        marked = released = input_eof = output_eof = write_closed = False
        server_bytes = 0
        while not (output_eof and not to_client):
            require(time.monotonic() < deadline, "stock Git barrier relay exceeded its finite deadline")
            if prefix.state == "held" and not to_server and not marked:
                require(server_bytes > 0, "barrier lacks an actual server advertisement")
                record = {"type": "stock_git_pack_barrier", "schema_version": 1,
                          "transport": mode, "command_refs": prefix.commands,
                          "atomic": True, "forwarded_pack_header_bytes": 12,
                          "pack_objects": prefix.pack_objects,
                          "server_bytes_received": server_bytes,
                          "retained_pack_bytes": len(prefix.pending)}
                temporary = ready.with_name(ready.name + ".tmp")
                with temporary.open("x") as out:
                    out.write(json.dumps(record, sort_keys=True) + "\n")
                temporary.replace(ready)
                marked = True
            if marked and not released and release.is_file():
                to_server.extend(prefix.pending)
                prefix.pending.clear()
                released = True
            if input_eof and not to_server and not write_closed:
                if connection is not None:
                    connection.shutdown(socket.SHUT_WR)
                else:
                    assert ssh is not None and ssh.stdin is not None
                    ssh.stdin.close()
                write_closed = True
            reads, writes = [], []
            if not output_eof and len(to_client) < CHUNK * 4:
                reads.append(reader)
            if not input_eof and len(to_server) < CHUNK * 4 and (prefix.state != "held" or released):
                reads.append(0)
            if to_client:
                writes.append(1)
            if to_server and not write_closed:
                writes.append(writer)
            readable, writable, _ = select.select(reads, writes, [], 0.02)
            if reader in readable:
                block = os.read(reader, CHUNK)
                if block:
                    server_bytes += len(block)
                    to_client.extend(block)
                else:
                    output_eof = True
            if 0 in readable:
                block = os.read(0, CHUNK)
                if block:
                    to_server.extend(block if released else prefix.consume(block))
                else:
                    input_eof = True
                    require(released, "stock client closed input before the PACK barrier was released")
            if writer in writable and to_server:
                written = os.write(writer, to_server[:CHUNK])
                del to_server[:written]
            if 1 in writable and to_client:
                written = os.write(1, to_client[:CHUNK])
                del to_client[:written]
        require(marked and released, "server ended the held push before harness release")
        if ssh is not None:
            return ssh.wait(timeout=10)
        return 0
    finally:
        if connection is not None:
            connection.close()
        if ssh is not None:
            if ssh.stdin is not None:
                ssh.stdin.close()
            if ssh.stdout is not None:
                ssh.stdout.close()
            if ssh.poll() is None:
                ssh.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    ssh.wait(timeout=3)
            if ssh.poll() is None:
                ssh.kill()
                ssh.wait(timeout=5)


if __name__ == "__main__":
    try:
        require(len(sys.argv) >= 2, "missing proxy mode")
        raise SystemExit(relay(sys.argv[1], sys.argv[2:]))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"continuous Git test relay failed: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
