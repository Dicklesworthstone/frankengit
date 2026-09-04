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
# SHA-256 repositories, atomic multi-ref pushes, or push certificates. The
# opt-in XL case (FG_E2E_LARGE_PUSH=1, release node) additionally pins the
# documented receive session envelope (frankengit-asb8): a >= 300 MB inflated
# first push under explicit size ceilings, a work-scaled deadline that admits
# it under a 5 s base, and the over-budget report-status refusal. A
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

# --- A delta-chained large first push is admitted and published end to end
# (frankengit-rpqx / frankengit-xefn). The corpus below has ~85 MB of UNIQUE
# inflated object content across 16 blobs -- under the 128 MB expanded ceiling,
# but the pre-rpqx quarantine resolver re-charged each shared delta base once
# per referencing delta, accounting it as ~150 MB and refusing it with
# PackError::TotalExpandedLimit (which xefn now surfaces to the client instead
# of hanging up). Counting each unique object once, the push is admitted and
# publishes main, and a clone-back reproduces the pushed head exactly.
#
# OPT-IN (FG_E2E_LARGE_PUSH=1) and expects a RELEASE node: on release the
# corpus inflates/resolves/seals in ~10-15 s, but a debug node is ~10-30x
# slower and a push this large exceeds the 300 s git-daemon session deadline
# mid-seal. The resolver accounting itself is pinned fast and build-
# independently by fgit-pack's caller_owned_budget_* unit tests and the xefn
# refusal-diagnostic by fgit-node's git_daemon_receive_transport test; this
# case adds the whole-stack confirmation (git client -> daemon -> quarantine
# -> resolve -> seal -> publish -> clone-back).
if [ "${FG_E2E_LARGE_PUSH:-0}" = "1" ]; then
  REPOID_LARGE=44444444444444444444444444444444
  STORAGE_LARGE="$WORK/storage-large"
  LSRC="$WORK/large-src"

  git init -q -b main "$LSRC"
  git -C "$LSRC" config user.email first-push-large@invalid.example
  git -C "$LSRC" config user.name 'FG-HH37 large fixture'
  for c in 1 2 3 4; do
    for f in a b c d; do
      seq "$c" $((c + 300000)) | sed "s/^/file-$f line /" > "$LSRC/$f.txt"
    done
    git -C "$LSRC" add -A
    git -C "$LSRC" commit -qm "large commit $c"
  done

  LINIT_RC=0
  "$FG_BIN" init "$STORAGE_LARGE" "$TENANT" "$REPOID_LARGE" >/dev/null 2>&1 || LINIT_RC=$?
  fge_assert_eq FG-HH37-PUSH-022 0 "$LINIT_RC" 'a fresh node for the large-push case initializes'

  SERVE_LARGE_STATE=''
  START_SERVE_LARGE() { # NAME PORT EXTRA...
    local name=$1 port=$2
    shift 2
    fge_spawn "$name" bash -c 'port=$1; bin=$2; store=$3; tenant=$4; repo=$5; shift 5; exec "$bin" serve "$store" "$tenant" "$repo" "127.0.0.1:$port" "$@" 2>"/tmp/first-push-large-serve-$port.err"' _ "$port" "$FG_BIN" "$STORAGE_LARGE" "$TENANT" "$REPOID_LARGE" "$@"
    sleep 1
    if kill -0 "$FGE_LAST_PID" 2>/dev/null; then SERVE_LARGE_STATE=ok; else SERVE_LARGE_STATE=dead; fi
  }
  FIND_PORT_AND_SERVE_LARGE() { # PREFIX EXTRA...
    local prefix=$1; shift
    FOUND_PORT='' FOUND_NAME=''
    local off cand
    for off in 0 4 8 12 16 20 24 28; do
      cand=$(( PORT_BASE + off ))
      START_SERVE_LARGE "$prefix-$cand" "$cand" "$@"
      if [ "$SERVE_LARGE_STATE" = ok ]; then FOUND_PORT=$cand; FOUND_NAME="$prefix-$cand"; break; fi
    done
    PORT_BASE=$(( PORT_BASE + 32 ))
  }

  FIND_PORT_AND_SERVE_LARGE large --receive-principal "$PRINCIPAL"
  fge_assert_cmd FG-HH37-PUSH-023 'a large-push serve session is listening' test -n "$FOUND_PORT"
  LPUSH_RC=0
  GIT_TERMINAL_PROMPT=0 git -C "$LSRC" -c protocol.version=1 push \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_LARGE.git" main >"$WORK/large-push.out" 2>&1 || LPUSH_RC=$?
  fge_reap "$FOUND_NAME"
  LPUSH_OUT=$(cat "$WORK/large-push.out")
  fge_assert_not_contains FG-HH37-PUSH-024 "$LPUSH_OUT" 'ResourceBudgetExceeded' \
    'the expanded over-count no longer refuses a legitimate large push (frankengit-rpqx)'
  fge_assert_not_contains FG-HH37-PUSH-025 "$LPUSH_OUT" 'hung up' \
    'any outcome is a typed report-status, never a silent socket hangup (frankengit-xefn)'
  fge_assert_eq FG-HH37-PUSH-026 0 "$LPUSH_RC" 'a release node admits the delta-chained large first push'
  fge_assert_contains FG-HH37-PUSH-027 "$LPUSH_OUT" 'main -> main' \
    'the pushed branch is accepted and reported to the client'

  # The published head must reproduce the pushed head exactly (clone-back).
  FIND_PORT_AND_SERVE_LARGE large-verify
  fge_assert_cmd FG-HH37-PUSH-028 'a large-verify serve session is listening' test -n "$FOUND_PORT"
  LCLONE="$WORK/large-clone"
  GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 clone \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_LARGE.git" "$LCLONE" >"$WORK/large-clone.out" 2>&1 || true
  fge_reap "$FOUND_NAME"
  LSRC_HEAD=$(git -C "$LSRC" rev-parse HEAD 2>/dev/null || echo source-missing)
  LCLONE_HEAD=$(git -C "$LCLONE" rev-parse HEAD 2>/dev/null || echo clone-missing)
  fge_assert_eq FG-HH37-PUSH-029 "$LSRC_HEAD" "$LCLONE_HEAD" 'the published head round-trips identically'

  # --- XL case (frankengit-asb8): a >= 300 MB inflated first push under a
  # deliberate, documented receive envelope. The corpus is ONE commit with 24
  # blobs of ~13.8 MB unique text (~330 MB unique inflated content; each blob
  # under the 32 MiB per-object ceiling; `pack.window=0` keeps the pack raw so
  # no delta-work limit applies). Three serves pin the envelope semantics:
  #   1. explicit size envelope + default time scaling -> admitted;
  #   2. a 5 s base timeout + explicit per-MiB scaling -> admitted, because the
  #      deadline scales with admitted work (a flat 5 s envelope cannot
  #      transfer + inflate + seal ~330 MB even on a release node);
  #   3. a 3 s flat envelope -> the over-budget push is refused through
  #      report-status with the envelope-exhausted notice, never a hangup, and
  #      an identical retry under a sufficient envelope resolves the unknown
  #      outcome idempotently (section 5.2).
  XL_SRC="$WORK/xl-src"
  git init -q -b main "$XL_SRC"
  git -C "$XL_SRC" config user.email first-push-xl@invalid.example
  git -C "$XL_SRC" config user.name 'FG-ASB8 XL fixture'
  for f in $(seq 1 24); do
    seq 1 600000 | sed "s/^/xl-file-$f line /" > "$XL_SRC/xl$f.txt"
  done
  git -C "$XL_SRC" add -A
  git -C "$XL_SRC" commit -qm 'XL commit: ~330 MB inflated unique content'

  START_SERVE_XL() { # NAME PORT STORAGE REPOID EXTRA...
    local name=$1 port=$2 storage=$3 repoid=$4
    shift 4
    fge_spawn "$name" bash -c 'port=$1; bin=$2; store=$3; tenant=$4; repo=$5; shift 5; exec "$bin" serve "$store" "$tenant" "$repo" "127.0.0.1:$port" "$@" 2>"/tmp/first-push-xl-serve-$port.err"' _ "$port" "$FG_BIN" "$storage" "$TENANT" "$repoid" "$@"
    sleep 1
    if kill -0 "$FGE_LAST_PID" 2>/dev/null; then SERVE_XL_STATE=ok; else SERVE_XL_STATE=dead; fi
  }
  FIND_PORT_AND_SERVE_XL() { # PREFIX STORAGE REPOID EXTRA...
    local prefix=$1 storage=$2 repoid=$3
    shift 3
    FOUND_PORT='' FOUND_NAME=''
    local off cand
    for off in 0 4 8 12 16 20 24 28; do
      cand=$(( PORT_BASE + off ))
      START_SERVE_XL "$prefix-$cand" "$cand" "$storage" "$repoid" "$@"
      if [ "$SERVE_XL_STATE" = ok ]; then FOUND_PORT=$cand; FOUND_NAME="$prefix-$cand"; break; fi
    done
    PORT_BASE=$(( PORT_BASE + 32 ))
  }

  # 1. The documented bound: explicit size envelope, default time scaling.
  REPOID_XL1=66666666666666666666666666666666
  STORAGE_XL1="$WORK/storage-xl1"
  XL1_INIT_RC=0
  "$FG_BIN" init "$STORAGE_XL1" "$TENANT" "$REPOID_XL1" >/dev/null 2>&1 || XL1_INIT_RC=$?
  fge_assert_eq FG-HH37-PUSH-030 0 "$XL1_INIT_RC" 'the XL repository initializes'
  FIND_PORT_AND_SERVE_XL xl1 "$STORAGE_XL1" "$REPOID_XL1" --receive-principal "$PRINCIPAL" --receive-max-input-mib 256 --receive-max-expanded-mib 512
  fge_assert_cmd FG-HH37-PUSH-031 'an XL serve session with the explicit size envelope is listening' test -n "$FOUND_PORT"
  XL1_RC=0
  GIT_TERMINAL_PROMPT=0 git -C "$XL_SRC" -c protocol.version=1 -c pack.window=0 push \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_XL1.git" main >"$WORK/xl1-push.out" 2>&1 || XL1_RC=$?
  fge_reap "$FOUND_NAME"
  XL1_OUT=$(cat "$WORK/xl1-push.out")
  fge_assert_eq FG-HH37-PUSH-032 0 "$XL1_RC" 'a >= 300 MB inflated first push succeeds under the documented envelope'
  fge_assert_contains FG-HH37-PUSH-033 "$XL1_OUT" 'main -> main' 'the XL push is accepted and reported to the client'
  fge_assert_not_contains FG-HH37-PUSH-034 "$XL1_OUT" 'hung up' 'the XL outcome is report-status, never a hangup'

  # The published XL head is canonical: the verify session's ls-remote
  # advertisement reports the pushed tip exactly, and the authenticated
  # doctor path re-verifies one named XL blob's envelope. A full byte-level
  # clone-back of a >= 300 MB repository is a separate capability: the
  # selected-pack writer carries its own 128 MiB expanded ceiling
  # (frankengit-e6jj).
  FIND_PORT_AND_SERVE_XL xl1-verify "$STORAGE_XL1" "$REPOID_XL1"
  fge_assert_cmd FG-HH37-PUSH-035 'an XL verification serve session is listening' test -n "$FOUND_PORT"
  GIT_TERMINAL_PROMPT=0 git -c protocol.version=1 ls-remote \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_XL1.git" main >"$WORK/xl-lsremote.out" 2>&1 || true
  fge_reap "$FOUND_NAME"
  XLSRC_HEAD=$(git -C "$XL_SRC" rev-parse HEAD 2>/dev/null || echo source-missing)
  XLSERVED_HEAD=$(awk '{print $1}' "$WORK/xl-lsremote.out" 2>/dev/null || true)
  fge_assert_eq FG-HH37-PUSH-036 "$XLSRC_HEAD" "$XLSERVED_HEAD" 'the published XL head round-trips identically through ls-remote'
  XL_BLOB_OID=$(git -C "$XL_SRC" ls-tree HEAD xl1.txt | awk '{print $3}')
  XL_DOCTOR_RC=0
  "$FG_BIN" doctor "$STORAGE_XL1" "$TENANT" "$REPOID_XL1" "$XL_BLOB_OID" >"$WORK/xl-doctor.out" 2>&1 || XL_DOCTOR_RC=$?
  fge_assert_eq FG-HH37-PUSH-046 0 "$XL_DOCTOR_RC" 'the doctor path re-verifies one named XL blob against the authenticated head'

  # 2. Work-proportional deadline: a 5 s base with 4 s/MiB scaling admits the
  # push; a flat 5 s envelope fails it anywhere (client-side pack streaming
  # alone takes longer), and the flat 300 s legacy envelope caps it on a
  # slower host. Scaling funds the session in proportion to admitted bytes.
  REPOID_XL2=77777777777777777777777777777777
  STORAGE_XL2="$WORK/storage-xl2"
  "$FG_BIN" init "$STORAGE_XL2" "$TENANT" "$REPOID_XL2" >/dev/null 2>&1
  FIND_PORT_AND_SERVE_XL xl2 "$STORAGE_XL2" "$REPOID_XL2" --receive-principal "$PRINCIPAL" --receive-max-input-mib 256 --receive-max-expanded-mib 512 --session-timeout-secs 5 --session-secs-per-mib 4
  fge_assert_cmd FG-HH37-PUSH-037 'a scaled-envelope XL serve session is listening' test -n "$FOUND_PORT"
  XL2_RC=0
  GIT_TERMINAL_PROMPT=0 git -C "$XL_SRC" -c protocol.version=1 -c pack.window=0 push \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_XL2.git" main >"$WORK/xl2-push.out" 2>&1 || XL2_RC=$?
  fge_reap "$FOUND_NAME"
  XL2_OUT=$(cat "$WORK/xl2-push.out")
  fge_assert_eq FG-HH37-PUSH-038 0 "$XL2_RC" 'the work-scaled envelope admits a push a flat 5 s deadline cannot'
  fge_assert_contains FG-HH37-PUSH-039 "$XL2_OUT" 'main -> main' 'the scaled-envelope push publishes main'

  # 3. Planted negative: a flat 15 s envelope cannot admit ~330 MB of work
  # (pack streaming finishes inside it, then the inflate/seal cannot). The
  # refusal must reach the client through report-status with the
  # envelope-exhausted notice (outcome unknown; retry resolves), never a
  # hangup (frankengit-xefn preserved).
  REPOID_XL3=88888888888888888888888888888888
  STORAGE_XL3="$WORK/storage-xl3"
  "$FG_BIN" init "$STORAGE_XL3" "$TENANT" "$REPOID_XL3" >/dev/null 2>&1
  FIND_PORT_AND_SERVE_XL xl3 "$STORAGE_XL3" "$REPOID_XL3" --receive-principal "$PRINCIPAL" --receive-max-input-mib 256 --receive-max-expanded-mib 512 --session-timeout-secs 15 --session-max-extension-secs 0
  fge_assert_cmd FG-HH37-PUSH-040 'a flat-envelope XL serve session is listening' test -n "$FOUND_PORT"
  XL3_RC=0
  GIT_TERMINAL_PROMPT=0 git -C "$XL_SRC" -c protocol.version=1 -c pack.window=0 push \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_XL3.git" main >"$WORK/xl3-push.out" 2>&1 || XL3_RC=$?
  fge_reap "$FOUND_NAME"
  XL3_OUT=$(cat "$WORK/xl3-push.out")
  fge_assert_cmd FG-HH37-PUSH-041 'the genuinely over-budget push fails' test "$XL3_RC" -ne 0
  fge_assert_contains FG-HH37-PUSH-042 "$XL3_OUT" 'envelope exhausted' 'the over-budget refusal is diagnosable through report-status'
  fge_assert_not_contains FG-HH37-PUSH-043 "$XL3_OUT" 'hung up' 'the over-budget refusal is never a silent hangup'

  # The unknown outcome resolves idempotently: the identical retried push
  # under a sufficient envelope exits zero (whether the cancelled admission
  # committed or not, section 5.2).
  FIND_PORT_AND_SERVE_XL xl3-retry "$STORAGE_XL3" "$REPOID_XL3" --receive-principal "$PRINCIPAL" --receive-max-input-mib 256 --receive-max-expanded-mib 512 --session-timeout-secs 60
  fge_assert_cmd FG-HH37-PUSH-044 'the retry serve session is listening' test -n "$FOUND_PORT"
  XL3_RETRY_RC=0
  GIT_TERMINAL_PROMPT=0 git -C "$XL_SRC" -c protocol.version=1 -c pack.window=0 push \
    "git://127.0.0.1:$FOUND_PORT/$REPOID_XL3.git" main >"$WORK/xl3-retry.out" 2>&1 || XL3_RETRY_RC=$?
  fge_reap "$FOUND_NAME"
  fge_assert_eq FG-HH37-PUSH-045 0 "$XL3_RETRY_RC" 'the identical retried push resolves the unknown outcome'
else
  fge_note FG-HH37-PUSH-022 'large-push and XL end-to-end cases skipped: set FG_E2E_LARGE_PUSH=1 with a release fg to run them. The frankengit-rpqx expanded-accounting fix is pinned by fgit-pack caller_owned_budget_* unit tests; the frankengit-asb8 envelope arithmetic and terminal-grace mechanism are pinned by fgit-node session_envelope_tests and the flag parsing by fgit-cli serve_envelope tests; a release-node run of the XL corpus is the whole-stack evidence.'
fi
