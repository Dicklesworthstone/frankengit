#!/usr/bin/env bash
# Read-only compatibility launcher for graph-aware `bv` robot modes.
#
# FrankenGit's authoritative Beads tracker uses the repository-owned
# `batch_pending` state for work awaiting independent batch verification.
# `bv` v0.22.0 predates that state and otherwise drops every such record before
# computing graph metrics. This launcher presents `bv` with a private, ephemeral
# projection in which only the exact status field `batch_pending` is represented
# as `review`: still non-closed and dependency-blocking, but neither claimable
# nor counted as active implementation.
#
# The authoritative `.beads/issues.jsonl` is never modified. `br` remains the
# source of truth for readiness and claims; this script exists only so `bv` can
# rank the complete dependency graph.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/bv_compat.sh --robot-<mode> [bv robot-mode arguments]

Runs a read-only bv robot command against a private compatibility projection of
.beads/issues.jsonl. Caller-supplied --db options and non-robot modes are refused.

Environment:
  BV_BIN           bv executable (default: bv)
  PYTHON_BIN       Python 3 executable (default: python3)
  FGIT_REPO_ROOT   explicit FrankenGit checkout root (default: git top-level)
USAGE
}

die() {
  printf 'bv-compat: REFUSED: %s\n' "$1" >&2
  exit 2
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die 'neither sha256sum nor shasum is available'
  fi
}

if [ $# -eq 0 ]; then
  usage
  exit 2
fi

case "${1-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

robot_mode=0
for argument in "$@"; do
  case "$argument" in
    --db|--db=*) die 'caller-supplied --db is forbidden; the launcher owns the projection path' ;;
    --robot-*|robot-*) robot_mode=1 ;;
  esac
done
[ "$robot_mode" -eq 1 ] || die 'only bv robot/read-only modes are allowed'

if [ -n "${FGIT_REPO_ROOT:-}" ]; then
  repo_root="$(cd "$FGIT_REPO_ROOT" 2>/dev/null && pwd -P)" || die "cannot enter FGIT_REPO_ROOT '$FGIT_REPO_ROOT'"
else
  command -v git >/dev/null 2>&1 || die 'git is required to locate the repository root'
  repo_root="$(git rev-parse --show-toplevel 2>/dev/null)" || die 'not inside a Git worktree; set FGIT_REPO_ROOT explicitly'
  repo_root="$(cd "$repo_root" && pwd -P)"
fi

source_file="$repo_root/.beads/issues.jsonl"
[ -f "$source_file" ] || die "authoritative tracker is missing at $source_file"
[ ! -L "$source_file" ] || die 'authoritative tracker must not be a symbolic link'

bv_bin="${BV_BIN:-bv}"
python_bin="${PYTHON_BIN:-python3}"
if [[ "$bv_bin" == */* ]]; then
  [ -x "$bv_bin" ] || die "BV_BIN '$bv_bin' is not executable"
else
  bv_bin="$(command -v "$bv_bin" 2>/dev/null)" || die "bv executable '${BV_BIN:-bv}' is not on PATH"
fi
if [[ "$python_bin" == */* ]]; then
  [ -x "$python_bin" ] || die "PYTHON_BIN '$python_bin' is not executable"
else
  python_bin="$(command -v "$python_bin" 2>/dev/null)" || die "Python executable '${PYTHON_BIN:-python3}' is not on PATH"
fi

umask 077
tmp_parent="${TMPDIR:-/tmp}"
[ -d "$tmp_parent" ] || die "temporary parent '$tmp_parent' does not exist"
tmp_dir="$(mktemp -d "$tmp_parent/frankengit-bv-compat.XXXXXX")" || die 'cannot create private temporary directory'
projection="$tmp_dir/issues.jsonl"
metadata="$tmp_dir/projection.meta"

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  rm -rf -- "$tmp_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

source_hash_before="$(hash_file "$source_file")"

"$python_bin" - "$source_file" "$projection" "$metadata" <<'PY'
import json
import os
import sys

source_path, projection_path, metadata_path = sys.argv[1:]
source_count = 0
projected_count = 0
mapped_count = 0
remaining_batch_pending = 0

with open(source_path, "r", encoding="utf-8", newline="") as source, open(
    projection_path, "x", encoding="utf-8", newline="\n"
) as destination:
    for line_number, raw_line in enumerate(source, 1):
        if not raw_line.strip():
            raise SystemExit(f"blank tracker record at line {line_number}")
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"malformed tracker JSON at line {line_number}: {error.msg}") from error
        if not isinstance(record, dict):
            raise SystemExit(f"tracker record at line {line_number} is not an object")
        status = record.get("status")
        if not isinstance(status, str):
            raise SystemExit(f"tracker record at line {line_number} has no string status")

        source_count += 1
        if status == "batch_pending":
            record["status"] = "review"
            mapped_count += 1
            destination.write(json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=False))
            destination.write("\n")
        else:
            destination.write(raw_line)
            if not raw_line.endswith("\n"):
                destination.write("\n")
        projected_count += 1

os.chmod(projection_path, 0o400)

with open(projection_path, "r", encoding="utf-8") as projection_check:
    for line_number, raw_line in enumerate(projection_check, 1):
        try:
            record = json.loads(raw_line)
        except json.JSONDecodeError as error:
            raise SystemExit(f"projected tracker JSON malformed at line {line_number}: {error.msg}") from error
        if record.get("status") == "batch_pending":
            remaining_batch_pending += 1

with open(metadata_path, "x", encoding="ascii", newline="\n") as metadata:
    metadata.write(f"source_records={source_count}\n")
    metadata.write(f"projected_records={projected_count}\n")
    metadata.write(f"mapped_batch_pending={mapped_count}\n")
    metadata.write(f"remaining_batch_pending={remaining_batch_pending}\n")
PY

# Parse only the four fixed numeric fields emitted above; anything else is a
# projection-construction failure, not a best-effort warning.
source_records=''
projected_records=''
mapped_batch_pending=''
remaining_batch_pending=''
while IFS='=' read -r key value; do
  case "$key" in
    source_records) source_records="$value" ;;
    projected_records) projected_records="$value" ;;
    mapped_batch_pending) mapped_batch_pending="$value" ;;
    remaining_batch_pending) remaining_batch_pending="$value" ;;
    *) die "unexpected projection metadata key '$key'" ;;
  esac
done < "$metadata"

case "$source_records:$projected_records:$mapped_batch_pending:$remaining_batch_pending" in
  *[!0-9:]*|'') die 'projection metadata is incomplete or non-numeric' ;;
esac
[ "$source_records" -eq "$projected_records" ] || die "projection record count drifted: source=$source_records projected=$projected_records"
[ "$remaining_batch_pending" -eq 0 ] || die "projection retained $remaining_batch_pending batch_pending record(s)"
[ "$(hash_file "$source_file")" = "$source_hash_before" ] || die 'authoritative tracker changed while the projection was being built'

printf 'bv-compat: projected %s batch_pending record(s) to review across %s tracker record(s)\n' \
  "$mapped_batch_pending" "$source_records" >&2

set +e
(
  cd "$repo_root" || exit 2
  "$bv_bin" --db "$projection" "$@"
)
bv_status=$?
set -e

source_hash_after="$(hash_file "$source_file")"
if [ "$source_hash_after" != "$source_hash_before" ]; then
  printf 'bv-compat: REFUSED: authoritative tracker changed during bv analysis; discard stdout\n' >&2
  exit 75
fi

exit "$bv_status"
