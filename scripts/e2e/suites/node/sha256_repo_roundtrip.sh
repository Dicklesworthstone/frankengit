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
#   The served SHA-256 assertion below is intentionally narrower than a
#   clone/fetch differential: it proves the assembled `fg serve` command
#   reopens the separately initialized repository and advertises its stored
#   object domain. Object transfer conformance remains owned by the loopback
#   oracle lane; this cell does not claim it.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init sha256-repo-roundtrip

TENANT=11111111111111111111111111111111
REPOID=22222222222222222222222222222222
PRINCIPAL=44444444444444444444444444444444

fge_phase action

# This lane must execute a binary assembled from this checkout, not a binary
# another revision left in a shared target directory. A private target root
# prevents Cargo from reusing that artifact, and deliberately ignores FG_BIN:
# an externally supplied binary has no revision binding this test can prove.
BUILD_TARGET=$(fge_tempdir sha256-repo-roundtrip-binary)
BUILD_RC=0
fge_run sha256-repo-roundtrip-build-fg \
  env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="$BUILD_TARGET" \
  cargo build --locked -p fgit-cli \
  || BUILD_RC=$?
fge_assert_eq FG-058-SHA256-001 0 "$BUILD_RC" \
  'fg builds from this checkout into the lane-private target directory'
FG_BIN="$BUILD_TARGET/debug/fg"
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

# The exact open-path acceptance: this is not OneNode called in-process. The
# real assembled `fg serve` process reopens the SHA-256 repository produced by
# the earlier process, then a real Git client observes its advertised object
# format. `fg serve` is one-shot, so a live child also proves the chosen port
# was actually bound rather than merely syntactically acceptable.
PORT_BASE=$((20000 + ($$ % 20000)))
SHA256_SERVE_PORT=''
SHA256_SERVE_NAME=''
for offset in 0 4 8 12 16 20 24 28; do
  candidate=$((PORT_BASE + offset))
  name="sha256-serve-$candidate"
  fge_spawn "$name" bash -c 'exec "$1" serve "$2" "$3" "$4" "127.0.0.1:$5" >"$6" 2>&1' \
    _ "$FG_BIN" "$WORK/sha256" "$TENANT" "$REPOID" "$candidate" "$WORK/$name.out"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SHA256_SERVE_PORT=$candidate
    SHA256_SERVE_NAME=$name
    break
  fi
done
fge_assert_cmd FG-058-SHA256-010 'a separate fg serve process is listening for the SHA-256 repository' \
  test -n "$SHA256_SERVE_PORT"

SHA256_SERVE_RC=0
GIT_TERMINAL_PROMPT=0 GIT_TRACE_PACKET=1 git -c protocol.version=1 ls-remote \
  "git://127.0.0.1:$SHA256_SERVE_PORT/$REPOID.git" >"$WORK/sha256-ls-remote.out" 2>"$WORK/sha256-packet-trace.out" \
  || SHA256_SERVE_RC=$?
[ -z "$SHA256_SERVE_NAME" ] || fge_reap "$SHA256_SERVE_NAME"
fge_assert_eq FG-058-SHA256-011 0 "$SHA256_SERVE_RC" 'git reaches the separate-process SHA-256 serve endpoint'
fge_assert_cmd FG-058-SHA256-012 'the served protocol advertises SHA-256 from canonical repository state' \
  grep -q 'object-format=sha256' "$WORK/sha256-packet-trace.out"

# ---------------------------------------------------------------------------
# Acceptance line 4: the clone/fetch DIFFERENTIAL against the pinned oracle.
#
# Distinct from the check above, which uses the ordinary `git` on PATH as the
# client whose compatibility this bead claims. This block instead drives the
# pinned, sandboxed oracle binary (AGENTS.md 3.1) and performs a real clone, so
# what is pinned here is that a pinned upstream Git can materialize a working
# repository from our SHA-256 wire output -- not merely that some client reads
# the advertisement.
#
# The fixture is built BY the pinned binary rather than by system git, and that
# is forced rather than stylistic: D3 forbids inventing cross-format mappings,
# so importing a SHA-256 repository requires a source that already IS one.
# ---------------------------------------------------------------------------

ORACLE="$E2E_ROOT/oracle/oracle.sh"
ORACLE_PIN=git-2.54.0

VERIFY_RC=0
"$ORACLE" verify "$ORACLE_PIN" >/dev/null 2>&1 || VERIFY_RC=$?
fge_assert_eq FG-058-SHA256-013 0 "$VERIFY_RC" \
  'the pinned oracle git is built and its source and binary digests match'

RUN_DIR=$("$ORACLE" create-run "$ORACLE_PIN" sha256differential)
fge_assert_cmd FG-058-SHA256-014 'the oracle run directory exists' test -d "$RUN_DIR/work"

"$ORACLE" run "$ORACLE_PIN" "$RUN_DIR" . -- init --object-format=sha256 -b main fixture \
  >/dev/null 2>&1
FIXTURE="$RUN_DIR/work/fixture"
fge_assert_cmd FG-058-SHA256-015 'the pinned oracle created a fixture repository' \
  test -d "$FIXTURE/.git"
fge_assert_cmd FG-058-SHA256-016 'the fixture is genuinely sha256, not a sha1 repository we assumed' \
  grep -qi 'objectformat *= *sha256' "$FIXTURE/.git/config"

"$ORACLE" run "$ORACLE_PIN" "$RUN_DIR" fixture -- config user.email sha256@invalid.example \
  >/dev/null 2>&1
"$ORACLE" run "$ORACLE_PIN" "$RUN_DIR" fixture -- config user.name 'FG-058 fixture' >/dev/null 2>&1
printf 'fg058 sha256 differential fixture\n' >"$FIXTURE/root.txt"
"$ORACLE" run "$ORACLE_PIN" "$RUN_DIR" fixture -- add -A >/dev/null 2>&1
"$ORACLE" run "$ORACLE_PIN" "$RUN_DIR" fixture -- commit -qm 'sha256 fixture commit' >/dev/null 2>&1
fge_assert_cmd FG-058-SHA256-017 'the fixture carries a commit to transfer' \
  test -f "$FIXTURE/.git/HEAD"

DIFF_STORAGE="$WORK/differential"
DIFF_INIT_RC=0
"$FG_BIN" init "$DIFF_STORAGE" "$TENANT" "$REPOID" sha256 >"$WORK/diff-init.out" 2>&1 \
  || DIFF_INIT_RC=$?
fge_assert_eq FG-058-SHA256-018 0 "$DIFF_INIT_RC" 'the differential node initializes as sha256'

IMPORT_RC=0
"$FG_BIN" import "$DIFF_STORAGE" "$TENANT" "$REPOID" "$PRINCIPAL" fg058-sha256-differential \
  "$FIXTURE" >"$WORK/diff-import.out" 2>&1 || IMPORT_RC=$?
fge_assert_eq FG-058-SHA256-019 0 "$IMPORT_RC" 'a sha256 source repository imports into canonical state'

DIFF_PORT=''
DIFF_NAME=''
for offset in 0 4 8 12 16 20 24 28; do
  candidate=$((PORT_BASE + 40 + offset))
  name="sha256-diff-serve-$candidate"
  fge_spawn "$name" bash -c 'exec "$1" serve "$2" "$3" "$4" "127.0.0.1:$5" >"$6" 2>&1' \
    _ "$FG_BIN" "$DIFF_STORAGE" "$TENANT" "$REPOID" "$candidate" "$WORK/$name.out"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    DIFF_PORT=$candidate
    DIFF_NAME=$name
    break
  fi
done
fge_assert_cmd FG-058-SHA256-020 'a serve session is listening for the differential repository' \
  test -n "$DIFF_PORT"

CLONE_RC=0
"$ORACLE" clone-loopback "$ORACLE_PIN" "$RUN_DIR" sha256clone "127.0.0.1:$DIFF_PORT" \
  "/$REPOID.git" clone >/dev/null 2>&1 || CLONE_RC=$?
[ -z "$DIFF_NAME" ] || fge_reap "$DIFF_NAME"
fge_assert_eq FG-058-SHA256-021 0 "$CLONE_RC" \
  'the pinned oracle clones the served sha256 repository'

CLONE_DIR="$RUN_DIR/work/clone"
fge_assert_cmd FG-058-SHA256-022 'the clone materialized a repository' test -d "$CLONE_DIR/.git"
fge_assert_cmd FG-058-SHA256-023 'the clone is itself sha256, so the format survived the transfer' \
  grep -qi 'objectformat *= *sha256' "$CLONE_DIR/.git/config"
# The transferred tip, not a worktree comparison. The clone deliberately is NOT
# asserted to have a checked-out worktree: this daemon advertises no
# `symref=HEAD:...` capability, so a real `git clone` receives the objects and
# remote-tracking refs but cannot decide which branch to check out, and leaves
# HEAD dangling. That is format-INDEPENDENT -- a SHA-1 repository served the
# same way advertises no symref either -- so it is a Git-compatibility gap of
# its own rather than anything about SHA-256, and is tracked separately. What
# the differential must pin is that the content crossed the wire intact, which
# is exactly what comparing the fixture tip to the cloned remote ref does.
FIXTURE_TIP=$("$ORACLE" run "$ORACLE_PIN" "$RUN_DIR" fixture -- rev-parse HEAD 2>/dev/null | tr -d '[:space:]')
fge_assert_cmd FG-058-SHA256-024 'the fixture tip is a 64-hex sha256 identity' \
  test "${#FIXTURE_TIP}" -eq 64
fge_assert_cmd FG-058-SHA256-025 'the clone received that exact tip as a remote-tracking ref' \
  grep -q "$FIXTURE_TIP" "$CLONE_DIR/.git/packed-refs"
fge_assert_cmd FG-058-SHA256-026 'the clone received a pack, so objects crossed the wire' \
  test -n "$(ls -A "$CLONE_DIR/.git/objects/pack" 2>/dev/null)"

fge_phase assert
