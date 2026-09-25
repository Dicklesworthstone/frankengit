#!/usr/bin/env bash
# e2e: stock OpenSSH + git compatibility over `fg serve-ssh` (x2mv.4.4 item 4/5)
# Bead: frankengit-root-doctrine-x2mv.4.4
#
# Proves, against the real `fg serve-ssh` binary and stock clients:
# 1. an initial push of a delta-bearing history into an empty node, then an
#    incremental push, both over SSH;
# 2. protocol v0 and v2 clones and a v2 fetch return the pushed refs and
#    objects byte-identically (strict fsck);
# 3. a push the node must refuse (deleting the default branch) is refused
#    through report-status and publishes nothing;
# 4. a silent client holding the only worker is released by the session read
#    timeout, after which a real clone succeeds;
# 5. a clone killed mid-transfer leaves the server serving the next clone.
# The pinned OpenSSH and git client versions are recorded in the NDJSON.
#
# FG_E2E_SSH_DELTA_BASE_BYTES sizes the incompressible base file (default
# 4 MB); each of FG_E2E_SSH_DELTA_VERSIONS further commits (default 4)
# rewrites a small slice of it, so the history is delta-friendly. For the
# acceptance envelope run with a RELEASE FG_BIN and >= 209715200 bytes.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init ssh-git-compat
fge_context bead frankengit-root-doctrine-x2mv.4.4
fge_context crate fgit-ssh
fge_context evidence_class e2e_binary_stock_client
fge_context openssh_version "$(ssh -V 2>&1 | head -1)"
fge_context git_version "$(git --version)"
fge_context non_claim 'Stock OpenSSH and git against one local fg serve-ssh with one worker; not a throughput, multi-client, hostile-network or HTTP-vs-SSH differential claim.'

TENANT="11111111111111111111111111111111"
REPOID="22222222222222222222222222222222"
PRINCIPAL="44444444444444444444444444444444"
BASE_BYTES="${FG_E2E_SSH_DELTA_BASE_BYTES:-4000000}"
VERSIONS="${FG_E2E_SSH_DELTA_VERSIONS:-4}"
fge_context base_bytes "$BASE_BYTES"
fge_context versions "$VERSIONS"

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd SSH-COMPAT-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
fge_assert_cmd SSH-COMPAT-002 'the supplied fg binary is executable' test -x "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

WORK="$(fge_tempdir ssh-compat)"
STORAGE="$WORK/storage"
SRC="$WORK/src"
git init -q -b main "$SRC"
git -C "$SRC" config user.email ssh-compat@invalid.example
git -C "$SRC" config user.name 'SSH compat fixture'
head -c "$BASE_BYTES" /dev/urandom > "$SRC/data.bin"
git -C "$SRC" add -A
git -C "$SRC" commit -qm 'base'
for version in $(seq 1 "$VERSIONS"); do
  # Rewrite 4 KiB in place: each version deltas cheaply against the last.
  head -c 4096 /dev/urandom | dd of="$SRC/data.bin" bs=4096 seek="$version" conv=notrunc status=none
  printf 'version %s\n' "$version" > "$SRC/VERSION"
  git -C "$SRC" add -A
  git -C "$SRC" commit -qm "version $version"
done

INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq SSH-COMPAT-003 0 "$INIT_RC" 'an empty node initializes'

printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$WORK/host_key.hex"
ssh-keygen -t ed25519 -N "" -f "$WORK/client_rw" -C rw -q
hex_key() { cut -d' ' -f2 "$1" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n'; }
printf '%s %s read,write\n' "$(hex_key "$WORK/client_rw.pub")" "$PRINCIPAL" > "$WORK/deploy_keys.txt"

fge_phase action
SSH_PORT=''
SSH_NAME=''
for attempt in 0 1 2 3 4 5 6 7; do
  port=$(( 24000 + (($$ + attempt * 131) % 20000) ))
  fge_spawn "serve-ssh-$port" bash -c 'exec "$1" serve-ssh "$2" "$3" "$4" "127.0.0.1:$5" --host-key-file "$6" --deploy-keys-file "$7" --allow-receive --max-sessions 64 --max-in-flight 1 >"$8/serve.out" 2>"$8/serve.err"' \
    _ "$FG_BIN" "$STORAGE" "$TENANT" "$REPOID" "$port" "$WORK/host_key.hex" "$WORK/deploy_keys.txt" "$WORK"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SSH_PORT=$port
    SSH_NAME="serve-ssh-$port"
    break
  fi
done
fge_assert_cmd SSH-COMPAT-004 'fg serve-ssh listens on loopback with one worker' test -n "$SSH_PORT"

SSH_CMD="ssh -p $SSH_PORT -i $WORK/client_rw -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR"
REMOTE="ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git"
git -C "$SRC" remote add fg "$REMOTE"

# 1. Initial push of the whole delta-bearing history into the empty node.
INITIAL_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 900 git -C "$SRC" push -q fg main 2>"$WORK/initial.err" || INITIAL_RC=$?
fge_assert_eq SSH-COMPAT-005 0 "$INITIAL_RC" 'initial push of the full history into an empty node succeeds'

# 2. Clones over protocol v0 and v2 are exact.
for version in 0 2; do
  CLONE_RC=0
  GIT_SSH_COMMAND="$SSH_CMD" timeout 900 git -c protocol.version="$version" clone -q "$REMOTE" "$WORK/clone-v$version" 2>"$WORK/clone-v$version.err" || CLONE_RC=$?
  fge_assert_eq "SSH-COMPAT-01$version" 0 "$CLONE_RC" "protocol v$version clone succeeds"
  fge_assert_eq "SSH-COMPAT-02$version" "$(git -C "$SRC" rev-parse main)" \
    "$(git -C "$WORK/clone-v$version" rev-parse HEAD 2>/dev/null || echo missing)" "protocol v$version clone observes the pushed tip"
  FSCK_RC=0
  git -C "$WORK/clone-v$version" fsck --strict >/dev/null 2>&1 || FSCK_RC=$?
  fge_assert_eq "SSH-COMPAT-03$version" 0 "$FSCK_RC" "protocol v$version clone passes strict fsck"
  fge_assert_cmd "SSH-COMPAT-04$version" "protocol v$version clone content is byte-identical" cmp -s "$WORK/clone-v$version/data.bin" "$SRC/data.bin"
done

# 3. Incremental push, then a v2 fetch into the earlier clone sees it exactly.
printf 'incremental\n' > "$SRC/INCREMENTAL"
git -C "$SRC" add -A
git -C "$SRC" commit -qm 'incremental'
INCR_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 600 git -C "$SRC" push -q fg main 2>"$WORK/incremental.err" || INCR_RC=$?
fge_assert_eq SSH-COMPAT-050 0 "$INCR_RC" 'incremental push succeeds'
FETCH_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 600 git -C "$WORK/clone-v2" -c protocol.version=2 fetch -q origin 2>"$WORK/fetch-v2.err" || FETCH_RC=$?
fge_assert_eq SSH-COMPAT-051 0 "$FETCH_RC" 'protocol v2 fetch after the incremental push succeeds'
fge_assert_eq SSH-COMPAT-052 "$(git -C "$SRC" rev-parse main)" \
  "$(git -C "$WORK/clone-v2" rev-parse origin/main 2>/dev/null || echo missing)" 'the v2 fetch observes the incremental tip'

# 4. A push the node refuses is reported through report-status and changes nothing.
BEFORE_TIP="$(git -C "$SRC" rev-parse main)"
REFUSED_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 300 git -C "$SRC" push fg :main >"$WORK/refused.out" 2>"$WORK/refused.err" || REFUSED_RC=$?
fge_assert_cmd SSH-COMPAT-060 'deleting the default branch over SSH is refused' test "$REFUSED_RC" -ne 0
fge_assert_cmd SSH-COMPAT-061 'the refusal arrives through report-status' grep -Eq 'remote rejected|\[rejected\]|! ' "$WORK/refused.err"
AFTER_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 300 git ls-remote "$REMOTE" refs/heads/main >"$WORK/after.refs" 2>"$WORK/after.err" || AFTER_RC=$?
fge_assert_eq SSH-COMPAT-062 0 "$AFTER_RC" 'ls-remote after the refusal succeeds'
fge_assert_eq SSH-COMPAT-063 "$BEFORE_TIP" "$(cut -f1 "$WORK/after.refs")" 'the refused delete left main unchanged'

# 5. A silent client holds the only worker until the session read timeout
#    (60 s) releases it; a real clone queued behind it then succeeds.
exec 7<>"/dev/tcp/127.0.0.1/$SSH_PORT"
sleep 1
SILENT_START=$(date +%s)
SILENT_RC=0
GIT_SSH_COMMAND="$SSH_CMD -o ConnectTimeout=120" timeout 300 git clone -q "$REMOTE" "$WORK/after-silent" 2>"$WORK/after-silent.err" || SILENT_RC=$?
SILENT_WAIT=$(( $(date +%s) - SILENT_START ))
exec 7<&- 7>&- || true
fge_context silent_client_wait_s "$SILENT_WAIT"
fge_assert_eq SSH-COMPAT-070 0 "$SILENT_RC" 'a clone queued behind a silent client succeeds once the worker is released'
fge_assert_cmd SSH-COMPAT-071 'the queued clone waited for the session read timeout (>= 45 s), not an early drop' test "$SILENT_WAIT" -ge 45

# 6. A clone killed mid-transfer does not wedge the server.
CANCEL_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout -s KILL 1 git clone -q "$REMOTE" "$WORK/cancelled" 2>/dev/null || CANCEL_RC=$?
fge_context cancelled_clone_rc "$CANCEL_RC"
sleep 2
fge_assert_cmd SSH-COMPAT-080 'the server is still running after a cancelled clone' kill -0 "$FGE_LAST_PID"
RESUME_RC=0
GIT_SSH_COMMAND="$SSH_CMD -o ConnectTimeout=120" timeout 600 git clone -q "$REMOTE" "$WORK/after-cancel" 2>"$WORK/after-cancel.err" || RESUME_RC=$?
fge_assert_eq SSH-COMPAT-081 0 "$RESUME_RC" 'a clone after the cancelled one succeeds'
fge_assert_cmd SSH-COMPAT-082 'the post-cancellation clone content is byte-identical' cmp -s "$WORK/after-cancel/data.bin" "$SRC/data.bin"

fge_phase teardown
fge_reap "$SSH_NAME"
