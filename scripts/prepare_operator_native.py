#!/usr/bin/env python3
"""Install this build's trusted fg for operator checks; never execute Cargo output.

Cargo/RCH may return a group-writable executable. Preserve that delivery and
pin identical bytes in an owner-private snapshot. The build remains the trust
boundary; this is installation, not authentication of an arbitrary executable.
Snapshots stay in the private target for replay and are never source artifacts.
"""
import hashlib
import hmac
import os
from pathlib import Path
import stat
import sys
import tempfile

MAX_EXECUTABLE_BYTES = 2 * 1024**3


def identity(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_uid)


def stream_digest(stream, expected_bytes):
    if not 0 <= expected_bytes <= MAX_EXECUTABLE_BYTES:
        raise ValueError("invalid native verification length")
    digest = hashlib.sha256()
    remaining = expected_bytes
    while remaining:
        chunk = stream.read(min(1024 * 1024, remaining))
        if not chunk:
            raise ValueError("native executable changed while verifying")
        remaining -= len(chunk)
        digest.update(chunk)
    # A changing file cannot extend this verification pass beyond its original
    # size. One additional byte distinguishes exact EOF from late growth.
    if stream.read(1):
        raise ValueError("native executable changed while verifying")
    return digest.hexdigest()


def prepare(source, target):
    for value in (source, target):
        if not Path(value).is_absolute() or any(ord(c) < 32 or ord(c) == 127 for c in str(value)):
            raise ValueError("expected absolute native source/target paths")
    source, target = Path(source), Path(target).resolve(strict=True)
    if source.is_symlink() or not source.resolve(strict=True).is_relative_to(target):
        raise ValueError("native executable escapes its Cargo target")
    named = source.lstat()
    if not stat.S_ISREG(named.st_mode):
        raise ValueError("invalid returned native executable")
    with open(source, "rb", opener=lambda path, flags: os.open(
            path, flags | os.O_NOFOLLOW | os.O_NONBLOCK)) as inp:
        before = os.fstat(inp.fileno())
        if (identity(before) != identity(named) or not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111
                or before.st_uid not in (0, os.geteuid())
                or not 0 < before.st_size <= MAX_EXECUTABLE_BYTES):
            raise ValueError("invalid returned native executable")
        directory = Path(tempfile.mkdtemp(prefix=".operator-native-", dir=target))
        installed = directory / source.name
        # Keep an incomplete copy non-executable, including on interruption.
        with open(installed, "xb", opener=lambda path, flags: os.open(
                path, flags | os.O_NOFOLLOW, 0o600)) as out:
            digest, copied = hashlib.sha256(), 0
            while chunk := inp.read(1024 * 1024):
                copied += len(chunk)
                if copied > before.st_size:
                    raise ValueError("native executable changed while installing")
                digest.update(chunk)
                out.write(chunk)
            out.flush()
            os.fsync(out.fileno())
            inp.seek(0)
            if (copied != before.st_size
                    or not hmac.compare_digest(stream_digest(inp, before.st_size), digest.hexdigest())
                    or identity(os.fstat(inp.fileno())) != identity(before)
                    or identity(source.lstat()) != identity(before)):
                raise ValueError("native executable changed while installing")
            with installed.open("rb") as check:
                if not hmac.compare_digest(stream_digest(check, before.st_size), digest.hexdigest()):
                    raise ValueError("installed native executable differs from its source")
            os.fchmod(out.fileno(), 0o500)
            os.fsync(out.fileno())
        for parent in (directory, target):
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    print(f"verify: installed returned native sha256={digest.hexdigest()} bytes={copied} "
          f"source_mode={stat.S_IMODE(before.st_mode):04o} mode=0500 at {installed}", file=sys.stderr)
    return installed


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3:
            raise ValueError("usage: prepare_operator_native.py EXECUTABLE CARGO_TARGET")
        print(prepare(*sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"verify: native installation refused: {error}", file=sys.stderr)
        sys.exit(2)
