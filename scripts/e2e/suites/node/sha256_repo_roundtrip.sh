#!/usr/bin/env bash
# e2e: FG-058 / decision D3 -- SHA-256 repository creation through the real
# assembled `fg` binary (bead frankengit-fg058-sha256-repos-8td).
#
# WHAT IS ASSERTED HERE, and why it needs an e2e cell at all:
#   The unit tests for this capability call `fgit_cli::run(&args)` directly.
#   They never exercise the assembled binary, so they cannot show that the
#   object-format argument survives argument parsing, that a refusal reaches
#   the user on stderr, or that the process exit code distinguishes the two.
#   That is exactly what this cell pins:
#     - a SHA-256 repository initializes and exits zero;
#     - a SHA-1 repository does too (the permitted twin -- without it, a build
#       where `fg init` was broken outright would still satisfy the refusal
#       assertion below);
#     - the pre-existing four-argument form still works, unchanged;
#     - an unrecognised format REFUSES, exits nonzero, and NAMES the offending
#       token on stderr. A repository's object format is permanent, so the
#       thing that must never happen is a quiet fall back to SHA-1.
#
# WHAT IS NOT ASSERTED YET, deliberately and not by narrowing:
#   The clone/fetch differential against the pinned Git oracle
#   (`oracle.sh clone-loopback`) is acceptance line 4 of the bead and is
#   BLOCKED, not skipped here to make a green. A repository's object format is
#   not persisted anywhere -- `NodeConfig.object_format` is config-only, so
#   `fg serve` reopens any repository with the SHA-1 default and would
#   advertise `object-format=sha1` for a SHA-256 repository. Serving one
#   correctly is a precondition for the differential. Tracked as
#   frankengit-lozg; the reasoning is recorded in
#   docs/D3_SHA256_REPOSITORY_DECISION.md.
#
#   The differential body belongs in THIS file once lozg lands. It is left out
#   rather than stubbed because `fge_unsupported` is a terminal non-pass in
#   this harness, so a placeholder assertion would ship a permanently red cell.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init sha256-repo-roundtrip

TENANT=11111111111111111111111111111111
REPOID=22222222222222222222222222222222

fge_phase action

# Locate or assemble the node binary. Building is preferred; a prebuilt binary
# is accepted so the cell stays runnable while cargo is contended elsewhere.
FG_BIN=${FG_BIN:-}
if [ -z "$FG_BIN" ]; then
  ALT="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/fg"
  CAND="$REPO_ROOT/target/debug/fg"
  if command -v cargo >/dev/null 2>&1; then
    RCH_CARGO_WRAPPER_BYPASS=1 cargo build -q -p fgit-cli >&2 || true
  fi
  [ -x "$ALT" ] && FG_BIN=$ALT
  [ -z "$FG_BIN" ] && [ -x "$CAND" ] && FG_BIN=$CAND
fi
fge_assert_cmd FG-058-SHA256-001 'an fg node binary is available' test -n "$FG_BIN"
fge_assert_cmd FG-058-SHA256-002 'the node binary is executable' test -x "$FG_BIN"

WORK=$(fge_tempdir sha256-repo-roundtrip-work)

# A SHA-256 repository initializes through the real binary. Before the
# object-format argument existed, no invocation of fg could produce one.
SHA256_RC=0
"$FG_BIN" init "$WORK/sha256" "$TENANT" "$REPOID" sha256 >"$WORK/sha256.out" 2>&1 || SHA256_RC=$?
fge_assert_eq FG-058-SHA256-003 0 "$SHA256_RC" 'fg init accepts an explicit sha256 object format'
fge_assert_cmd FG-058-SHA256-004 'the sha256 storage root materialized' test -d "$WORK/sha256"

# The permitted twin. Same command shape, the other defined format.
SHA1_RC=0
"$FG_BIN" init "$WORK/sha1" "$TENANT" "$REPOID" sha1 >"$WORK/sha1.out" 2>&1 || SHA1_RC=$?
fge_assert_eq FG-058-SHA256-005 0 "$SHA1_RC" 'fg init accepts an explicit sha1 object format'

# Backward compatibility: the four-argument form predates this argument and
# must keep working. Without this the refusal assertion below would be
# satisfied by a build where fg init failed for every input.
DEFAULT_RC=0
"$FG_BIN" init "$WORK/default" "$TENANT" "$REPOID" >"$WORK/default.out" 2>&1 || DEFAULT_RC=$?
fge_assert_eq FG-058-SHA256-006 0 "$DEFAULT_RC" 'fg init without an object format still succeeds'

# The refusal, through the real process boundary: nonzero exit AND the
# offending token named on stderr. A silent fall back to SHA-1 would mint a
# repository in a format the caller never asked for, permanently.
BOGUS_RC=0
"$FG_BIN" init "$WORK/bogus" "$TENANT" "$REPOID" sha512 >"$WORK/bogus.out" 2>&1 || BOGUS_RC=$?
fge_assert_cmd FG-058-SHA256-007 'an unrecognised object format exits nonzero' test "$BOGUS_RC" -ne 0
fge_assert_cmd FG-058-SHA256-008 'the refusal names the rejected token' grep -q 'sha512' "$WORK/bogus.out"
fge_assert_cmd FG-058-SHA256-009 'the refused init created no repository' test ! -d "$WORK/bogus"

fge_phase assert
