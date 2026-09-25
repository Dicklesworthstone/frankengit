#!/usr/bin/env bash
# e2e: SSH transfers larger than one channel window, through a stock OpenSSH client
# Bead: frankengit-root-doctrine-x2mv.4.4
#
# Proves, against the real `fg serve-ssh` binary:
# 1. a clone whose pack exceeds the client's 2 MiB channel window completes
#    byte-identically (server honours window/max-packet and waits for
#    WINDOW_ADJUST; teardown does not truncate the client's drained output);
# 2. a push larger than the server's advertised receive window completes
#    (the server reopens its window as it consumes input) and a fresh clone
#    returns the pushed bytes exactly;
# 3. the same push with a read-only key is refused and publishes nothing.
#
# Size defaults keep the lane fast; set FG_E2E_SSH_CLONE_BYTES /
# FG_E2E_SSH_PUSH_BYTES for larger envelopes (use a release FG_BIN: a debug
# fg import of large incompressible data can exceed its wall-clock deadline).
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init ssh-large-transfer
fge_context bead frankengit-root-doctrine-x2mv.4.4
fge_context crate fgit-ssh
fge_context openssh_version "$(ssh -V 2>&1 | head -1)"
fge_context git_version "$(git --version)"
fge_context evidence_class e2e_binary_stock_client
fge_context non_claim 'Stock OpenSSH and git clients against one local fg serve-ssh; not a throughput, multi-client or hostile-network claim.'

TENANT="11111111111111111111111111111111"
REPOID="22222222222222222222222222222222"
PRINCIPAL="44444444444444444444444444444444"
CLONE_BYTES="${FG_E2E_SSH_CLONE_BYTES:-6000000}"
PUSH_BYTES="${FG_E2E_SSH_PUSH_BYTES:-3000000}"

fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd SSH-LARGE-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
fge_assert_cmd SSH-LARGE-002 'the supplied fg binary is executable' test -x "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'

WORK="$(fge_tempdir ssh-large)"
STORAGE="$WORK/storage"
SRC="$WORK/src"
git init -q -b main "$SRC"
git -C "$SRC" config user.email ssh-large@invalid.example
git -C "$SRC" config user.name 'SSH large fixture'
# Incompressible content: the pack cannot shrink below one channel window.
head -c "$CLONE_BYTES" /dev/urandom > "$SRC/large.bin"
git -C "$SRC" add -A
git -C "$SRC" commit -qm 'large base'

INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq SSH-LARGE-003 0 "$INIT_RC" 'node storage initializes'
IMPORT_RC=0
"$FG_BIN" import "$STORAGE" "$TENANT" "$REPOID" "$PRINCIPAL" ssh-large-import "$SRC" >/dev/null 2>"$WORK/import.err" || IMPORT_RC=$?
fge_assert_eq SSH-LARGE-004 0 "$IMPORT_RC" 'large history imports'

printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$WORK/host_key.hex"
ssh-keygen -t ed25519 -N "" -f "$WORK/client_rw" -C rw -q
ssh-keygen -t ed25519 -N "" -f "$WORK/client_ro" -C ro -q
hex_key() { cut -d' ' -f2 "$1" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n'; }
{
  printf '%s %s read,write\n' "$(hex_key "$WORK/client_rw.pub")" "$PRINCIPAL"
  printf '%s %s read\n' "$(hex_key "$WORK/client_ro.pub")" "$PRINCIPAL"
} > "$WORK/deploy_keys.txt"

fge_phase action
SSH_PORT=''
SSH_NAME=''
for attempt in 0 1 2 3 4 5 6 7; do
  port=$(( 24000 + (($$ + attempt * 97) % 20000) ))
  fge_spawn "serve-ssh-$port" bash -c 'exec "$1" serve-ssh "$2" "$3" "$4" "127.0.0.1:$5" --host-key-file "$6" --deploy-keys-file "$7" --allow-receive --max-sessions 4 >"$8/serve.out" 2>"$8/serve.err"' \
    _ "$FG_BIN" "$STORAGE" "$TENANT" "$REPOID" "$port" "$WORK/host_key.hex" "$WORK/deploy_keys.txt" "$WORK"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SSH_PORT=$port
    SSH_NAME="serve-ssh-$port"
    break
  fi
done
fge_assert_cmd SSH-LARGE-005 'fg serve-ssh listens on loopback' test -n "$SSH_PORT"

ssh_command() {
  printf 'ssh -p %s -i %s -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR' "$SSH_PORT" "$1"
}
REMOTE="ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git"

CLONE_RC=0
GIT_SSH_COMMAND="$(ssh_command "$WORK/client_rw")" timeout 600 git clone -q "$REMOTE" "$WORK/clone" 2>"$WORK/clone.err" || CLONE_RC=$?
fge_assert_eq SSH-LARGE-006 0 "$CLONE_RC" 'clone larger than one channel window completes'
fge_assert_cmd SSH-LARGE-007 'cloned large blob is byte-identical to the source' cmp -s "$WORK/clone/large.bin" "$SRC/large.bin"
FSCK_RC=0
git -C "$WORK/clone" fsck --strict >/dev/null 2>&1 || FSCK_RC=$?
fge_assert_eq SSH-LARGE-008 0 "$FSCK_RC" 'cloned objects pass strict fsck'

git -C "$WORK/clone" config user.email ssh-large@invalid.example
git -C "$WORK/clone" config user.name 'SSH large fixture'
head -c "$PUSH_BYTES" /dev/urandom > "$WORK/clone/pushed.bin"
git -C "$WORK/clone" add -A
git -C "$WORK/clone" commit -qm 'large push'
PUSHED_TIP="$(git -C "$WORK/clone" rev-parse HEAD)"

# Refusal twin first: the read-only key must not publish the same push.
RO_RC=0
GIT_SSH_COMMAND="$(ssh_command "$WORK/client_ro")" timeout 300 git -C "$WORK/clone" push -q origin main 2>"$WORK/ro_push.err" || RO_RC=$?
fge_assert_cmd SSH-LARGE-009 'read-only key push is refused' test "$RO_RC" -ne 0

PUSH_RC=0
GIT_SSH_COMMAND="$(ssh_command "$WORK/client_rw")" timeout 600 git -C "$WORK/clone" push -q origin main 2>"$WORK/push.err" || PUSH_RC=$?
fge_assert_eq SSH-LARGE-010 0 "$PUSH_RC" 'push larger than the receive window completes'

RECLONE_RC=0
GIT_SSH_COMMAND="$(ssh_command "$WORK/client_rw")" timeout 600 git clone -q "$REMOTE" "$WORK/reclone" 2>"$WORK/reclone.err" || RECLONE_RC=$?
fge_assert_eq SSH-LARGE-011 0 "$RECLONE_RC" 'fresh clone after the push completes'

fge_phase assert
fge_assert_eq SSH-LARGE-012 "$PUSHED_TIP" "$(git -C "$WORK/reclone" rev-parse HEAD 2>/dev/null || echo missing)" 'fresh clone observes the pushed tip'
fge_assert_cmd SSH-LARGE-013 'pushed blob round-trips byte-identically' cmp -s "$WORK/reclone/pushed.bin" "$WORK/clone/pushed.bin"

fge_phase teardown
fge_reap "$SSH_NAME"
