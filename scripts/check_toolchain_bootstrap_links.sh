#!/usr/bin/env bash
# Read-only preflight for the transport links used to bootstrap the pinned Rust.
# Consumer: verify.sh docs and operators without rustup. This catches missing,
# ambiguous, floating, or stale bootstrap metadata before any Cargo invocation.
# It does not download, authenticate an archive, or authorize a pin advancement.
# Delete this check together with tooling-rust-bootstrap-links.md if that
# transport-only note is retired; rust-toolchain.toml remains the sole pin.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
usage() { printf 'usage: %s [--root <repository>]\n' "$0"; }
case "$#" in
  0) ;;
  1)
    case "$1" in
      -h|--help) usage; exit 0 ;;
      *) usage >&2; exit 2 ;;
    esac
    ;;
  2)
    [ "$1" = --root ] && [ -n "$2" ] || { usage >&2; exit 2; }
    ROOT="$2"
    ;;
  *) usage >&2; exit 2 ;;
esac

PYTHON="${PYTHON_BIN:-python3}"
command -v "$PYTHON" >/dev/null 2>&1 || {
  printf 'toolchain-bootstrap: unavailable: Python 3.11+ is required\n' >&2
  exit 2
}
exec "$PYTHON" - "$ROOT" <<'PY'
import collections
import datetime
import pathlib
import re
import sys

try:
    import tomllib
except ImportError:
    print("toolchain-bootstrap: unavailable: Python 3.11+ is required", file=sys.stderr)
    sys.exit(2)

LIMIT = 1024 * 1024
root = pathlib.Path(sys.argv[1])

def refuse(message):
    print(f"toolchain-bootstrap: refused: {message}", file=sys.stderr)
    sys.exit(3)

def read_text(name):
    try:
        with (root / name).open("rb") as stream:
            raw = stream.read(LIMIT + 1)
        if len(raw) > LIMIT:
            refuse(f"{name}: exceeds {LIMIT}-byte metadata limit")
        return raw.decode("utf-8")
    except (OSError, UnicodeError) as error:
        refuse(f"{name}: cannot read UTF-8 metadata: {error}")

try:
    manifest = tomllib.loads(read_text("rust-toolchain.toml"))
except tomllib.TOMLDecodeError as error:
    refuse(f"rust-toolchain.toml: invalid TOML: {error}")

toolchain = manifest.get("toolchain")
channel = toolchain.get("channel") if isinstance(toolchain, dict) else None
if not isinstance(channel, str) or not re.fullmatch(r"nightly-\d{4}-\d{2}-\d{2}", channel):
    refuse("rust-toolchain.toml: toolchain.channel must be one dated nightly-YYYY-MM-DD")
date_text = channel.removeprefix("nightly-")
try:
    datetime.date.fromisoformat(date_text)
except ValueError:
    refuse(f"rust-toolchain.toml: invalid calendar date in {channel!r}")

note = read_text("tooling-rust-bootstrap-links.md")
declared = re.findall(r"`(nightly(?:-[^`\s]*)?)`", note)
if declared != [channel]:
    refuse(f"bootstrap note must declare exactly `{channel}`; found {declared!r}")

archive = f"https://static.rust-lang.org/dist/{date_text}/rust-nightly-x86_64-unknown-linux-gnu.tar.xz"
expected = collections.Counter([archive, archive + ".sha256"])
actual = collections.Counter(re.findall(r"https?://[^\s<>()\[\]\"'`]+", note))
if actual != expected:
    missing = sorted((expected - actual).elements())
    unexpected = sorted((actual - expected).elements())
    refuse(f"bootstrap URLs do not match {channel}; missing={missing!r}; unexpected={unexpected!r}")

print(f"toolchain-bootstrap: consistent pin and two transport URLs: {channel}")
PY
