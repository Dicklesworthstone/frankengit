#!/usr/bin/env bash
# e2e: FG-028b FIRST CLONE -- a real `git clone` from a live fgit-node, receipted
# here (bead frankengit-ipo5).
#
# OWNERSHIP NOTE (2026-08-23): the live body below was drafted by SwiftOx under
# the sanction request mailed to BoldMoose (msg 4770) and ProudJaguar (4771)
# after ipo5 sat blocked ~22h on blockers that had already closed. Closure
# credit and the bead remain BoldMoose's; this file wires the acceptance shape
# ipo5 itself defines. A later cargo-test refactor driving OneNode directly
# (instead of the assembled binary) belongs to the node crate's owner; this
# cell pins the USER-VISIBLE contract first.
#
# WHAT IS ASSERTED:
#   - init -> import -> serve -> real `git clone` of a NON-empty repository:
#     strict fsck clean, advertised refs transferred at identical identity,
#     checked-out worktree byte-identical to the source. The fixture includes
#     branch+lightweight-tag-at-one-tip (the duplicate-want shape) and an
#     annotated tag (tag-object transfer).
#   - An abruptly killed client never takes the node down: containment only.
#     Whether the kill lands mid-transfer or post-completion is scheduling;
#     what is pinned is that the spawned server is reaped by this script and a
#     fresh serve still produces a byte-identical clone.
#   - The empty-repository genesis lane keeps working (regression twin).
#
# CLIENT PROVENANCE: plain `git` is the ordinary client whose compatibility
# FG-028b claims; this is not the pinned differential oracle lane. Protocol is
# pinned to v1 because v2 greeting serving is a separate bead
# (frankengit-daemon-v2-lsrefs-serving-6mmn).
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init first-clone

TENANT=11111111111111111111111111111111
REPOID=22222222222222222222222222222222
PRINCIPAL=44444444444444444444444444444444

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
fge_assert_cmd FG-028B-CLONE-001 'an fg node binary is available' test -n "$FG_BIN"
fge_assert_cmd FG-028B-CLONE-002 'the node binary is executable' test -x "$FG_BIN"

PORT_BASE=$(( 20000 + ($$ % 20000) ))

WORK=$(fge_tempdir first-clone-work)
SRC="$WORK/src"

# Deterministic fixture: three commits, nested dirs, twin branch + lightweight
# tag sharing main's tip, annotated tag on main~1.
git init -q -b main "$SRC"
git -C "$SRC" config user.email first-clone@invalid.example
git -C "$SRC" config user.name 'FG-028B fixture'
for i in 1 2 3; do
  mkdir -p "$SRC/dir$i"
  seq 1 $((i * 64)) > "$SRC/dir$i/file$i.txt"
  # The final revision carries the ~2 MiB, line-oriented object shape that
  # previously exposed a size-correlated serve/clone failure.  This is not a
  # synthetic pack-writer unit corpus: the ordinary Git client below must
  # receive, index, fsck, and check out this exact object from a live node.
  if [ "$i" -eq 3 ]; then
    seq 1 300000 > "$SRC/dir$i/large-transport.txt"
  fi
  printf 'rev %s\n' "$i" > "$SRC/root.txt"
  git -C "$SRC" add -A
  git -C "$SRC" commit -qm "commit $i"
done
git -C "$SRC" branch twin main
git -C "$SRC" tag light main
git -C "$SRC" tag -a v1.0 -m 'annotated' main~1

STORAGE="$WORK/storage"
INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq FG-028B-CLONE-003 0 "$INIT_RC" 'node initializes'

IMP_RC=0
"$FG_BIN" import "$STORAGE" "$TENANT" "$REPOID" "$PRINCIPAL" fc-fixture-001 "$SRC" >/dev/null 2>&1 || IMP_RC=$?
fge_assert_eq FG-028B-CLONE-004 0 "$IMP_RC" 'import publishes the source history'

# One-shot serve sessions. A candidate port whose child dies within the grace
# window was a bind collision; a child alive after the window is listening.
# Neither the daemon grammar nor the CLI offers a pre-known port, so
# candidates walk a per-run window seeded from the PID. SERVE_STATE is a global
# on purpose: fge_spawn emits NDJSON, so nothing here may be $( ) captured.
SERVE_STATE=''
START_SERVE() { # NAME STORAGE PORT
  local name=$1 store=$2 port=$3
  fge_spawn "$name" bash -c 'exec "$1" serve "$2" "$3" "$4" "127.0.0.1:$5" 2>"/tmp/serve-$5.err"' _ "$FG_BIN" "$store" "$TENANT" "$REPOID" "$port"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SERVE_STATE=ok
  else
    SERVE_STATE=dead
  fi
}

CLONE_PORT='' CLONE_NAME=''
for off in 0 4 8 12 16 20 24 28; do
  cand=$(( PORT_BASE + off ))
  PORT_BASE_LOCAL=$cand
  START_SERVE "serve-$cand" "$STORAGE" "$cand"
  if [ "$SERVE_STATE" = ok ]; then CLONE_PORT=$cand; CLONE_NAME="serve-$cand"; break; fi
done
fge_assert_cmd FG-028B-CLONE-005 'a serve session is listening' test -n "$CLONE_PORT"

CLONE_RC=0
CLONE="$WORK/clone"
GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
  "git://127.0.0.1:$CLONE_PORT/$REPOID.git" "$CLONE" >"$WORK/clone.out" 2>&1 || CLONE_RC=$?
fge_reap "$CLONE_NAME"
fge_assert_eq FG-028B-CLONE-006 0 "$CLONE_RC" 'a real git clone exits zero'
fge_assert_file FG-028B-CLONE-007 "$CLONE/.git/HEAD" 'the clone materialized a repository'

FSCK_RC=0
git -C "$CLONE" fsck --strict >/dev/null 2>&1 || FSCK_RC=$?
fge_assert_eq FG-028B-CLONE-008 0 "$FSCK_RC" 'every transferred object passes strict fsck'

CHECKOUT_RC=0
git -C "$CLONE" checkout -q -b main origin/main 2>/dev/null || CHECKOUT_RC=$?
fge_assert_eq FG-028B-CLONE-009 0 "$CHECKOUT_RC" 'main checks out from the transferred refs'

DIFF_RC=0
diff -r --exclude=.git "$SRC" "$CLONE" >/dev/null 2>&1 || DIFF_RC=$?
# Every advertised tip identity must arrive exactly: compared as sorted OID
# sets over BOTH ref universes, which covers branches, the twin, and both tag
# kinds without depending on remote-tracking name mapping.
git -C "$SRC" show-ref --hash | sort -u >"$WORK/src-oids.txt"
git -C "$CLONE" show-ref --hash | sort -u >"$WORK/clone-oids.txt"
OID_SRC=$(cat "$WORK/src-oids.txt")
OID_CLONE=$(cat "$WORK/clone-oids.txt")
fge_assert_eq FG-028B-CLONE-011 "$OID_SRC" "$OID_CLONE" 'advertised ref tip identities transferred exactly'

fge_assert_eq FG-028B-CLONE-010 0 "$DIFF_RC" 'checked-out worktree is byte-identical to the source'

# Abrupt-client containment. Kill timing is scheduling on purpose; what is
# pinned is containment (the spawned server is reaped here, never orphaned)
# and continued service afterwards.
# ---------------------------------------------------------------------------
KILL_PORT=$(( PORT_BASE + 64 + ($$ % 32) ))
KILL_NAME="serve-k$KILL_PORT"
START_SERVE "$KILL_NAME" "$STORAGE" "$KILL_PORT"
if [ "$SERVE_STATE" = ok ]; then
  VICTIM="$WORK/victim"
  GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
    "git://127.0.0.1:$KILL_PORT/$REPOID.git" "$VICTIM" >"$WORK/victim.out" 2>&1 &
  VPID=$!
  sleep 0.4
  kill -9 "$VPID" 2>/dev/null || true
  wait "$VPID" 2>/dev/null || true
fi
fge_reap "$KILL_NAME"
fge_assert_cmd FG-028B-CLONE-012 \
  'after an abrupt client kill the spawned server was reaped, never orphaned' \
  test -z "$(printf '%s\n' ${FGE_SPAWN_NAMES[@]+"${FGE_SPAWN_NAMES[@]}"} | grep -x "$KILL_NAME" || true)"

RETRY_PORT=$(( PORT_BASE + 128 + ($$ % 32) ))
RETRY_NAME="serve-r$RETRY_PORT"
START_SERVE "$RETRY_NAME" "$STORAGE" "$RETRY_PORT"
RETRY_RC=9
if [ "$SERVE_STATE" = ok ]; then
  rm -rf "$WORK/retry"
  if GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
    "git://127.0.0.1:$RETRY_PORT/$REPOID.git" "$WORK/retry" >"$WORK/retry.out" 2>&1; then
    RETRY_RC=0
  else
    RETRY_RC=$?
  fi
fi
fge_reap "$RETRY_NAME"
fge_assert_eq FG-028B-CLONE-013 0 "$RETRY_RC" 'node still serves completely after an aborted session'
CO2_RC=0
git -C "$WORK/retry" checkout -q -b main origin/main 2>/dev/null || CO2_RC=$?
fge_assert_eq FG-028B-CLONE-017 0 "$CO2_RC" 'post-abort clone checks main out from transferred refs'
DIFF2_RC=0
diff -r --exclude=.git "$SRC" "$WORK/retry" >/dev/null 2>&1 || DIFF2_RC=$?
fge_assert_eq FG-028B-CLONE-014 0 "$DIFF2_RC" 'post-abort clone is byte-identical too'

# Genesis twin: empty repository advertisement unchanged.
EMPTY_STORE="$WORK/empty"
EINIT_RC=0
"$FG_BIN" init "$EMPTY_STORE" "$TENANT" "$REPOID" >/dev/null 2>&1 || EINIT_RC=$?
fge_assert_eq FG-028B-CLONE-015 0 "$EINIT_RC" 'second node initializes for genesis lane'
EMPTY_PORT=$(( PORT_BASE + 192 + ($$ % 32) ))
EMPTY_NAME="serve-e$EMPTY_PORT"
START_SERVE "$EMPTY_NAME" "$EMPTY_STORE" "$EMPTY_PORT"
EMPTY_RC=9
if [ "$SERVE_STATE" = ok ]; then
  rm -rf "$WORK/empty-clone"
  if GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
    "git://127.0.0.1:$EMPTY_PORT/$REPOID.git" "$WORK/empty-clone" >"$WORK/empty-clone.out" 2>&1; then
    EMPTY_RC=0
  else
    EMPTY_RC=$?
  fi
fi
fge_reap "$EMPTY_NAME"
fge_assert_eq FG-028B-CLONE-016 0 "$EMPTY_RC" 'empty-repository genesis lane still clones'

fge_phase assert
