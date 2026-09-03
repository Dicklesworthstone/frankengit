#!/usr/bin/env bash
# e2e: FIRST PUSH -- a real `git push` into a live fgit-node over the raw
# git-daemon transport (bead frankengit-hh37).
#
# WHAT IS ASSERTED:
#   - a node served WITHOUT --receive-principal keeps the compatibility
#     default: `git push` fails and publishes nothing (the refusal twin);
#   - init -> serve --receive-principal -> real `git push` of a non-empty
#     history into an EMPTY repository exits zero and reports ok;
#   - the pushed state is canonical only through the node: a fresh clone from
#     a later serve session transfers identical ref-tip identities, passes
#     strict fsck, and checks out byte-identical to the pushing worktree;
#   - an identical re-push is idempotent ("Everything up-to-date");
#   - an incremental push of one further commit lands and re-clones exactly.
#
# CLIENT PROVENANCE: plain `git` is the ordinary client whose compatibility
# the receive lane claims; this is not the pinned differential oracle lane.
#
# NON-CLAIMS: this suite does not cover hidden-ref policy content (jkbo),
# SHA-256 repositories, atomic multi-ref pushes, or push certificates. A
# successful run is compatibility evidence for exactly the cells exercised.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init first-push

TENANT=11111111111111111111111111111111
REPOID=33333333333333333333333333333333
PRINCIPAL=55555555555555555555555555555555

fge_phase action

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
fge_assert_cmd FG-HH37-PUSH-001 'an fg node binary is available' test -n "$FG_BIN"
fge_assert_cmd FG-HH37-PUSH-002 'the node binary is executable' test -x "$FG_BIN"

PORT_BASE=$(( 21000 + ($$ % 20000) ))

WORK=$(fge_tempdir first-push-work)
SRC="$WORK/src"

# Deterministic fixture: two commits with nested content the push must carry.
git init -q -b main "$SRC"
git -C "$SRC" config user.email first-push@invalid.example
git -C "$SRC" config user.name 'FG-HH37 fixture'
for i in 1 2; do
  mkdir -p "$SRC/dir$i"
  seq 1 $((i * 64)) > "$SRC/dir$i/file$i.txt"
  printf 'rev %s\n' "$i" > "$SRC/root.txt"
  git -C "$SRC" add -A
  git -C "$SRC" commit -qm "commit $i"
done

STORAGE="$WORK/storage"
INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq FG-HH37-PUSH-003 0 "$INIT_RC" 'node initializes'

SERVE_STATE=''
START_SERVE() { # NAME PORT EXTRA...
  local name=$1 port=$2
  shift 2
  fge_spawn "$name" bash -c 'port=$1; bin=$2; store=$3; tenant=$4; repo=$5; shift 5; exec "$bin" serve "$store" "$tenant" "$repo" "127.0.0.1:$port" "$@" 2>"/tmp/first-push-serve-$port.err"' _ "$port" "$FG_BIN" "$STORAGE" "$TENANT" "$REPOID" "$@"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SERVE_STATE=ok
  else
    SERVE_STATE=dead
  fi
}

FIND_PORT_AND_SERVE() { # NAME_PREFIX EXTRA...
  local prefix=$1
  shift
  FOUND_PORT='' FOUND_NAME=''
  local off cand
  for off in 0 4 8 12 16 20 24 28; do
    cand=$(( PORT_BASE + off ))
    START_SERVE "$prefix-$cand" "$cand" "$@"
    if [ "$SERVE_STATE" = ok ]; then FOUND_PORT=$cand; FOUND_NAME="$prefix-$cand"; break; fi
  done
  PORT_BASE=$(( PORT_BASE + 32 ))
}

# --- Refusal twin: no --receive-principal, push must fail and publish nothing.
FIND_PORT_AND_SERVE closed
fge_assert_cmd FG-HH37-PUSH-004 'a principal-less serve session is listening' test -n "$FOUND_PORT"
CLOSED_RC=0
GIT_TERMINAL_PROMPT=0 git -C "$SRC" -c protocol.version=1 push \
  "git://127.0.0.1:$FOUND_PORT/$REPOID.git" main >"$WORK/closed-push.out" 2>&1 || CLOSED_RC=$?
fge_reap "$FOUND_NAME"
fge_assert_cmd FG-HH37-PUSH-005 'a push without a configured receive principal fails' \
  test "$CLOSED_RC" -ne 0

# --- The first real push into the empty repository.
FIND_PORT_AND_SERVE open --receive-principal "$PRINCIPAL"
fge_assert_cmd FG-HH37-PUSH-006 'a receive-enabled serve session is listening' test -n "$FOUND_PORT"
PUSH_RC=0
GIT_TERMINAL_PROMPT=0 git -C "$SRC" -c protocol.version=1 push \
  "git://127.0.0.1:$FOUND_PORT/$REPOID.git" main >"$WORK/push.out" 2>&1 || PUSH_RC=$?
fge_reap "$FOUND_NAME"
fge_assert_eq FG-HH37-PUSH-007 0 "$PUSH_RC" 'a real git push exits zero'
NEW_BRANCH_RC=0
grep -q 'new branch' "$WORK/push.out" || NEW_BRANCH_RC=$?
fge_assert_eq FG-HH37-PUSH-008 0 "$NEW_BRANCH_RC" 'the client reports the new branch from report-status'

# --- The pushed state is canonical: a fresh clone from a later session.
FIND_PORT_AND_SERVE verify
fge_assert_cmd FG-HH37-PUSH-009 'a verification serve session is listening' test -n "$FOUND_PORT"
CLONE="$WORK/clone"
CLONE_RC=0
GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
  "git://127.0.0.1:$FOUND_PORT/$REPOID.git" "$CLONE" >"$WORK/clone.out" 2>&1 || CLONE_RC=$?
fge_reap "$FOUND_NAME"
fge_assert_eq FG-HH37-PUSH-010 0 "$CLONE_RC" 'a clone of the pushed repository exits zero'
FSCK_RC=0
git -C "$CLONE" fsck --strict >/dev/null 2>&1 || FSCK_RC=$?
fge_assert_eq FG-HH37-PUSH-011 0 "$FSCK_RC" 'every pushed object passes strict fsck after re-transfer'
git -C "$SRC" show-ref --hash | sort -u >"$WORK/src-oids.txt"
git -C "$CLONE" show-ref --hash | sort -u >"$WORK/clone-oids.txt"
OID_SRC=$(cat "$WORK/src-oids.txt")
OID_CLONE=$(cat "$WORK/clone-oids.txt")
fge_assert_eq FG-HH37-PUSH-012 "$OID_SRC" "$OID_CLONE" 'pushed ref tip identities round-trip exactly'
git -C "$CLONE" checkout -q -B main origin/main 2>/dev/null || true
DIFF_RC=0
diff -r --exclude=.git "$SRC" "$CLONE" >/dev/null 2>&1 || DIFF_RC=$?
fge_assert_eq FG-HH37-PUSH-013 0 "$DIFF_RC" 'the re-cloned worktree is byte-identical to the pusher'

# --- An identical re-push is idempotent.
FIND_PORT_AND_SERVE retry --receive-principal "$PRINCIPAL"
fge_assert_cmd FG-HH37-PUSH-014 'a retry serve session is listening' test -n "$FOUND_PORT"
RETRY_RC=0
GIT_TERMINAL_PROMPT=0 git -C "$SRC" -c protocol.version=1 push \
  "git://127.0.0.1:$FOUND_PORT/$REPOID.git" main >"$WORK/retry.out" 2>&1 || RETRY_RC=$?
fge_reap "$FOUND_NAME"
fge_assert_eq FG-HH37-PUSH-015 0 "$RETRY_RC" 'an identical re-push exits zero'
UPTODATE_RC=0
grep -q 'up.to.date' "$WORK/retry.out" || UPTODATE_RC=$?
fge_assert_eq FG-HH37-PUSH-016 0 "$UPTODATE_RC" 'the client sees the repository already up to date'

# --- An incremental push of one further commit.
printf 'rev 3\n' > "$SRC/root.txt"
git -C "$SRC" add -A
git -C "$SRC" commit -qm 'commit 3'
FIND_PORT_AND_SERVE incr --receive-principal "$PRINCIPAL"
fge_assert_cmd FG-HH37-PUSH-017 'an incremental serve session is listening' test -n "$FOUND_PORT"
INCR_RC=0
GIT_TERMINAL_PROMPT=0 git -C "$SRC" -c protocol.version=1 push \
  "git://127.0.0.1:$FOUND_PORT/$REPOID.git" main >"$WORK/incr.out" 2>&1 || INCR_RC=$?
fge_reap "$FOUND_NAME"
fge_assert_eq FG-HH37-PUSH-018 0 "$INCR_RC" 'an incremental push of one further commit exits zero'

FIND_PORT_AND_SERVE verify2
fge_assert_cmd FG-HH37-PUSH-019 'a second verification serve session is listening' test -n "$FOUND_PORT"
CLONE2="$WORK/clone2"
CLONE2_RC=0
GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
  "git://127.0.0.1:$FOUND_PORT/$REPOID.git" "$CLONE2" >"$WORK/clone2.out" 2>&1 || CLONE2_RC=$?
fge_reap "$FOUND_NAME"
fge_assert_eq FG-HH37-PUSH-020 0 "$CLONE2_RC" 'a clone after the incremental push exits zero'
git -C "$SRC" show-ref --hash | sort -u >"$WORK/src-oids2.txt"
git -C "$CLONE2" show-ref --hash | sort -u >"$WORK/clone2-oids.txt"
OID_SRC2=$(cat "$WORK/src-oids2.txt")
OID_CLONE2=$(cat "$WORK/clone2-oids.txt")
fge_assert_eq FG-HH37-PUSH-021 "$OID_SRC2" "$OID_CLONE2" 'the incremental tip identity round-trips exactly'
