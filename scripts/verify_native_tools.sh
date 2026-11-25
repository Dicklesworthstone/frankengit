#!/usr/bin/env bash
# Source from a verifier whose working directory is the repository root.
# AGENTS.md §16.2: builds use the caller's Cargo/RCH routing and private target
# directory. Never force a local compiler here. Tools that inspect this checkout
# are built for the CALLER's host, returned by Cargo/RCH, then executed here:
# `cargo run` could instead inspect a worker's filtered copy (notably no Beads).
# Explicit input roots also avoid embedded worker CARGO_MANIFEST_DIR paths.
VERIFY_NATIVE_HOST=''
VERIFY_TARGET_DIRECTORY=''

prepare_native_tools() {
  [[ -n "$VERIFY_NATIVE_HOST" && -n "$VERIFY_TARGET_DIRECTORY" ]] && return 0
  if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
    printf 'verify: set CARGO_TARGET_DIR to a pane-private durable target directory (AGENTS.md 16.2)\n' >&2
    return 2
  fi
  local compiler_version metadata
  compiler_version="$(rustc -vV)" || return
  VERIFY_NATIVE_HOST="$(printf '%s\n' "$compiler_version" | sed -n 's/^host: //p')"
  if ! [[ "${VERIFY_NATIVE_HOST}" =~ ^[a-zA-Z0-9_]+(-[a-zA-Z0-9_]+)+$ ]]; then
    printf 'verify: cannot determine one native caller host from rustc -vV\n' >&2
    return 2
  fi
  metadata="$(cargo metadata --locked --no-deps --format-version 1)" || return
  VERIFY_TARGET_DIRECTORY="$(printf '%s' "$metadata" | "${PYTHON_BIN:-python3}" -c '
import json, os, sys
try:
    target = json.load(sys.stdin)["target_directory"]
    if not isinstance(target, str) or not os.path.isabs(target) or any(c in target for c in "\0\r\n"):
        raise ValueError("expected an absolute target_directory without control separators")
except (ValueError, KeyError, TypeError) as error:
    print(f"verify: invalid Cargo target metadata: {error}", file=sys.stderr)
    sys.exit(2)
print(target)
')"
}

native_binary_path() {
  local suffix='' profile="${2:-debug}"
  case "${VERIFY_NATIVE_HOST}" in *-windows-*) suffix='.exe' ;; esac
  printf '%s/%s/%s/%s%s\n' "$VERIFY_TARGET_DIRECTORY" "$VERIFY_NATIVE_HOST" "$profile" "$1" "$suffix"
}

build_native_tools() {
  # RCH estimates and forwards Cargo's argv. An ambient CARGO_BUILD_JOBS may
  # not reach the worker, so make the caller's requested compiler cap explicit
  # for both actual compilation and its matching scheduler reservation.
  if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
    cargo build --locked --target "$VERIFY_NATIVE_HOST" --jobs "$CARGO_BUILD_JOBS" "$@"
  else
    cargo build --locked --target "$VERIFY_NATIVE_HOST" "$@"
  fi
}

# Return the built executable on stdout. Build diagnostics stay on stderr.
verified_tool_path() {
  local package="$1" binary="$2" executable
  prepare_native_tools || return
  build_native_tools -p "$package" --bin "$binary" >&2 || return
  executable="$(native_binary_path "$binary")" || return
  if [[ ! -x "$executable" ]]; then
    printf 'verify: no returned native executable at %s\n' "$executable" >&2
    return 1
  fi
  printf '%s\n' "$executable"
}

run_native_tool() {
  local executable
  prepare_native_tools || return
  executable="$(verified_tool_path "$1" "$2")" || return
  shift 2
  "$executable" "$@"
}
