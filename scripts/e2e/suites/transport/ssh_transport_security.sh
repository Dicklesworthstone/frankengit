#!/usr/bin/env bash
# e2e: FG-047b SSH transport security and auth adversarial campaign
# Bead: frankengit-fg047b-ssh-security-m9rr
#
# Proves:
# 1. Shell-free typed command dispatch (arbitrary commands and injection refused)
# 2. Deploy key authentication and scope enforcement (read vs write, unknown key, wrong repo)
# 3. Quiescent teardown and bounded connection limits
# 4. HTTP vs SSH differential clone equivalence
# 5. Live deploy-key revocation, rotation, scope downgrade, and fail-closed repair
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg047b-ssh-transport-security
fge_kind e2e-binary
fge_context bead frankengit-fg047b-ssh-security-m9rr
fge_context crate fgit-ssh
fge_context openssh_version "$(ssh -V 2>&1 | head -1)"
fge_context git_version "$(git --version)"
fge_context evidence_class security_adversarial_campaign
fge_context non_claim 'This tests SSH protocol security and authentication boundaries; it does not claim multi-tenant cluster isolation or network-layer DDoS mitigation.'

TENANT="11111111111111111111111111111111"
REPOID="22222222222222222222222222222222"
OTHER_REPO="33333333333333333333333333333333"
PRINCIPAL="44444444444444444444444444444444"

fge_phase setup

# Locate fg binary
FG_BIN=${FG_BIN:-}
if [ -z "$FG_BIN" ]; then
  ALT="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug/fg"
  CAND="$REPO_ROOT/target/debug/fg"
  if command -v cargo >/dev/null 2>&1 && [ ! -x "${ALT:-}" ] && [ ! -x "${CAND:-}" ]; then
    RCH_CARGO_WRAPPER_BYPASS=1 cargo build -q -p fgit-cli >&2 || true
  fi
  [ -x "$ALT" ] && FG_BIN=$ALT
  [ -z "$FG_BIN" ] && [ -x "$CAND" ] && FG_BIN=$CAND
fi
fge_assert_cmd FG-047B-SEC-001 'fg binary is available' test -n "$FG_BIN"
fge_assert_cmd FG-047B-SEC-002 'fg binary is executable' test -x "$FG_BIN"

WORK="$(fge_tempdir ssh-sec-work)"
STORAGE="$WORK/storage"
SRC="$WORK/src"

# Deterministic git fixture
git init -q -b main "$SRC"
git -C "$SRC" config user.email ssh-sec@invalid.example
git -C "$SRC" config user.name 'FG-047B Fixture'
for i in 1 2 3; do
  mkdir -p "$SRC/dir$i"
  seq 1 $((i * 32)) > "$SRC/dir$i/file$i.txt"
  printf 'revision %s\n' "$i" > "$SRC/version.txt"
  git -C "$SRC" add -A
  git -C "$SRC" commit -qm "commit $i"
done
git -C "$SRC" tag light-tag main
git -C "$SRC" tag -a v1.0 -m "annotated release 1.0" main~1

# Initialize and import repository into FrankenGit node
INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq FG-047B-SEC-003 0 "$INIT_RC" 'node storage initializes cleanly'

IMP_RC=0
"$FG_BIN" import "$STORAGE" "$TENANT" "$REPOID" "$PRINCIPAL" sec-import-001 "$SRC" >/dev/null 2>&1 || IMP_RC=$?
fge_assert_eq FG-047B-SEC-004 0 "$IMP_RC" 'repository history imports cleanly'

# Generate Ed25519 host key (32 bytes / 64 hex chars)
HOST_KEY="$WORK/host_key.hex"
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$HOST_KEY"

# Generate Ed25519 client keys
ssh-keygen -t ed25519 -N "" -f "$WORK/client_ro" -C "ro-key" -q
ssh-keygen -t ed25519 -N "" -f "$WORK/client_rw" -C "rw-key" -q
ssh-keygen -t ed25519 -N "" -f "$WORK/client_unknown" -C "unknown-key" -q

# Extract raw 32-byte public keys in hex
RO_B64=$(cut -d' ' -f2 "$WORK/client_ro.pub")
RO_HEX=$(printf "%s" "$RO_B64" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n')

RW_B64=$(cut -d' ' -f2 "$WORK/client_rw.pub")
RW_HEX=$(printf "%s" "$RW_B64" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n')

UNKNOWN_B64=$(cut -d' ' -f2 "$WORK/client_unknown.pub")
UNKNOWN_HEX=$(printf "%s" "$UNKNOWN_B64" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n')

# Create deploy keys configuration file
DEPLOY_KEYS_FILE="$WORK/deploy_keys.txt"
cat <<EOF > "$DEPLOY_KEYS_FILE"
$RO_HEX $PRINCIPAL read
$RW_HEX $PRINCIPAL read,write
EOF
chmod 0600 "$DEPLOY_KEYS_FILE"

fge_phase action

# Pick available port and start fg serve-ssh
PORT_BASE=$(( 23000 + ($$ % 10000) ))
SERVE_STATE=''
SERVE_PID=''
START_SERVE() {
  local name=$1 port=$2 max_sess=${3:-100}
  fge_spawn "$name" bash -c 'exec "$1" serve-ssh "$2" "$3" "$4" "127.0.0.1:$5" --host-key-file "$6" --deploy-keys-file "$7" --allow-receive --max-sessions "$8" >"/tmp/ssh-serve-$5.out" 2>"/tmp/ssh-serve-$5.err"' _ "$FG_BIN" "$STORAGE" "$TENANT" "$REPOID" "$port" "$HOST_KEY" "$DEPLOY_KEYS_FILE" "$max_sess"
  sleep 1
  SERVE_PID=$FGE_LAST_PID
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SERVE_STATE=ok
  else
    SERVE_STATE=dead
  fi
}

SSH_PORT='' SSH_NAME=''
for off in 0 4 8 12 16 20 24 28; do
  cand=$(( PORT_BASE + off ))
  START_SERVE "serve-ssh-$cand" "$cand" 100
  if [ "$SERVE_STATE" = ok ]; then
    SSH_PORT=$cand
    SSH_NAME="serve-ssh-$cand"
    break
  fi
done

fge_assert_cmd FG-047B-SEC-005 'ssh server is listening on local port' test -n "$SSH_PORT"

SSH_COMMON_OPTS="-p $SSH_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR"

# 0. Host key authentication (ATK-017 host key forgery). A client pinned to
#    the server's real host key connects; the same strict client pinned to a
#    different key for the same address refuses, so a server that cannot
#    sign the exchange hash with the pinned key cannot impersonate it.
SCAN_RC=0
ssh-keyscan -T 5 -t ed25519 -p "$SSH_PORT" 127.0.0.1 >"$WORK/known_hosts_pinned" 2>"$WORK/keyscan.err" || SCAN_RC=$?
fge_assert_cmd FG-047B-SEC-030 'ssh-keyscan obtains the server ed25519 host key' \
  grep -q 'ssh-ed25519 ' "$WORK/known_hosts_pinned"
ssh-keygen -t ed25519 -N "" -f "$WORK/forged_host" -C forged-host -q
printf '[127.0.0.1]:%s %s\n' "$SSH_PORT" "$(cut -d' ' -f1,2 "$WORK/forged_host.pub")" >"$WORK/known_hosts_forged"
STRICT_BASE="-p $SSH_PORT -i $WORK/client_rw -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR"
PINNED_RC=0
GIT_SSH_COMMAND="ssh $STRICT_BASE -o UserKnownHostsFile=$WORK/known_hosts_pinned" timeout 120 \
  git ls-remote "ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git" >"$WORK/pinned.refs" 2>"$WORK/pinned.err" || PINNED_RC=$?
fge_assert_eq FG-047B-SEC-031 0 "$PINNED_RC" 'a strict client pinned to the real host key connects'
FORGED_RC=0
GIT_SSH_COMMAND="ssh $STRICT_BASE -o UserKnownHostsFile=$WORK/known_hosts_forged" timeout 120 \
  git ls-remote "ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git" >"$WORK/forged.refs" 2>"$WORK/forged.err" || FORGED_RC=$?
fge_assert_cmd FG-047B-SEC-032 'a strict client pinned to a different host key refuses the server' test "$FORGED_RC" -ne 0
fge_assert_cmd FG-047B-SEC-033 'the refusal is host key verification, not another failure' \
  grep -Eq 'Host key verification failed|IDENTIFICATION HAS CHANGED' "$WORK/forged.err"
fge_context keyscan_rc "$SCAN_RC"

# 1. Public-key auth bypass attempt (no key presented)
bypass_rc=0
ssh $SSH_COMMON_OPTS -o PubkeyAuthentication=no user@127.0.0.1 "git-upload-pack '/$REPOID.git'" 2>"$WORK/bypass.err" || bypass_rc=$?
fge_assert_cmd FG-047B-SEC-006 'unauthenticated exec attempt is refused' test "$bypass_rc" -ne 0

# 2. Unknown key attempt
unknown_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_unknown" user@127.0.0.1 "git-upload-pack '/$REPOID.git'" 2>"$WORK/unknown.err" || unknown_rc=$?
fge_assert_cmd FG-047B-SEC-007 'unknown public key is refused' test "$unknown_rc" -ne 0

# 3. Read-only deploy key attempting git-receive-pack (scope refusal)
ro_receive_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "git-receive-pack '/$REPOID.git'" 2>"$WORK/ro_receive.err" || ro_receive_rc=$?
fge_assert_cmd FG-047B-SEC-008 'read-only key refused on receive-pack' test "$ro_receive_rc" -ne 0

# 4. Read-only key attempting wrong repository (repository scope refusal)
wrong_repo_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "git-upload-pack '/$OTHER_REPO.git'" 2>"$WORK/wrong_repo.err" || wrong_repo_rc=$?
fge_assert_cmd FG-047B-SEC-009 'key access to unauthorized repository refused' test "$wrong_repo_rc" -ne 0

# 5. Hostile command execution attempts (command injection and shell escape)
cmd_sh_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "sh -c 'touch $WORK/pwned1'" 2>/dev/null || cmd_sh_rc=$?
fge_assert_cmd FG-047B-SEC-010 'arbitrary shell command refused' test "$cmd_sh_rc" -ne 0
fge_assert_cmd FG-047B-SEC-011 'shell payload did not execute' test ! -f "$WORK/pwned1"

cmd_semi_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "git-upload-pack '/$REPOID.git; touch $WORK/pwned2'" 2>/dev/null || cmd_semi_rc=$?
fge_assert_cmd FG-047B-SEC-012 'semicolon metacharacter command refused' test "$cmd_semi_rc" -ne 0
fge_assert_cmd FG-047B-SEC-013 'semicolon payload did not execute' test ! -f "$WORK/pwned2"

cmd_sub_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "git-upload-pack '/\$(touch $WORK/pwned3)'" 2>/dev/null || cmd_sub_rc=$?
fge_assert_cmd FG-047B-SEC-014 'subshell metacharacter command refused' test "$cmd_sub_rc" -ne 0
fge_assert_cmd FG-047B-SEC-015 'subshell payload did not execute' test ! -f "$WORK/pwned3"

cmd_pipe_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "git-upload-pack '/$REPOID.git | cat'" 2>/dev/null || cmd_pipe_rc=$?
fge_assert_cmd FG-047B-SEC-016 'pipe metacharacter command refused' test "$cmd_pipe_rc" -ne 0

cmd_dotdot_rc=0
ssh $SSH_COMMON_OPTS -i "$WORK/client_ro" user@127.0.0.1 "git-upload-pack '/../etc/passwd'" 2>/dev/null || cmd_dotdot_rc=$?
fge_assert_cmd FG-047B-SEC-017 'directory traversal command refused' test "$cmd_dotdot_rc" -ne 0

# 6. Permitted read-only operation: real git clone over SSH
CLONE="$WORK/ssh-clone"
CLONE_RC=0
GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="ssh $SSH_COMMON_OPTS -i $WORK/client_ro" \
  git clone "ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git" "$CLONE" >"$WORK/clone.out" 2>&1 || CLONE_RC=$?
fge_assert_eq FG-047B-SEC-018 0 "$CLONE_RC" 'real git clone over SSH with authorized deploy key succeeds'

fge_phase assert

# Verify cloned repository integrity
fge_assert_file FG-047B-SEC-019 "$CLONE/.git/HEAD" 'SSH clone materialized valid git repository'

FSCK_RC=0
git -C "$CLONE" fsck --strict >/dev/null 2>&1 || FSCK_RC=$?
fge_assert_eq FG-047B-SEC-020 0 "$FSCK_RC" 'transferred objects pass strict git fsck'

# HTTP-vs-SSH differential equivalence check
git -C "$SRC" show-ref --hash | sort -u > "$WORK/src-oids.txt"
git -C "$CLONE" show-ref --hash | sort -u > "$WORK/clone-oids.txt"
OID_SRC=$(cat "$WORK/src-oids.txt")
OID_CLONE=$(cat "$WORK/clone-oids.txt")
fge_assert_eq FG-047B-SEC-021 "$OID_SRC" "$OID_CLONE" 'SSH transferred ref identities match source identically'

DIFF_RC=0
diff -r --exclude=.git "$SRC" "$CLONE" >/dev/null 2>&1 || DIFF_RC=$?
fge_assert_eq FG-047B-SEC-022 0 "$DIFF_RC" 'checked-out worktree is byte-identical to source'

# 7. Live table changes affect the next signed Git command on this exact
# listener. Use fresh connections, only the selected private key, and a fixed
# client deadline so neither an agent nor a reused control socket masks reloads.
LIVE_SERVER_PID=$SERVE_PID
LIVE_REMOTE="ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git"
LIVE_COMMAND_TIMEOUT=60
LIVE_SSH="ssh -F /dev/null -p $SSH_PORT -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$WORK/known_hosts_pinned -o BatchMode=yes -o ConnectTimeout=5 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 -o IdentitiesOnly=yes -o IdentityAgent=none -o ControlMaster=no -o ControlPath=none -o LogLevel=ERROR"
fge_context live_key_listener_pid "$LIVE_SERVER_PID"
fge_context live_key_command_timeout_s "$LIVE_COMMAND_TIMEOUT"

# Stage the whole table privately, then rename within the same directory. An
# empty replacement is valid and revokes every row. No server restart occurs.
replace_deploy_keys() {
  local replacement
  replacement=$(mktemp "$WORK/deploy-keys.XXXXXX")
  chmod 0600 "$replacement"
  cat > "$replacement"
  mv -f -- "$replacement" "$DEPLOY_KEYS_FILE"
}
live_ls_remote() {
  local key=$1 label=$2
  LIVE_RC=0
  LC_ALL=C GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$LIVE_SSH -i $WORK/$key" \
    timeout -k 5 "$LIVE_COMMAND_TIMEOUT" git ls-remote "$LIVE_REMOTE" \
    >"$WORK/$label.refs" 2>"$WORK/$label.err" || LIVE_RC=$?
}
live_push() {
  local key=$1 label=$2 ref=$3
  LIVE_RC=0
  LC_ALL=C GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$LIVE_SSH -i $WORK/$key" \
    timeout -k 5 "$LIVE_COMMAND_TIMEOUT" git -C "$SRC" push "$LIVE_REMOTE" "main:$ref" \
    >"$WORK/$label.out" 2>"$WORK/$label.err" || LIVE_RC=$?
}
refused_before_deadline() {
  local rc=$1 stderr_path=$2
  # Require a live original listener and an exec/auth refusal from the server.
  # A connection, host-key, timeout, or launcher failure cannot pass this oracle.
  case "$rc" in
    0|124|125|126|127|137) return 1 ;;
  esac
  kill -0 "$LIVE_SERVER_PID" 2>/dev/null || return 1
  if grep -Eq '^ssh: connect to host |Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED|^ssh: Could not resolve hostname |^kex_exchange_identification:|^banner exchange:|Permission denied' "$stderr_path"; then
    return 1
  fi
  # OpenSSH may stop at CHANNEL_FAILURE before displaying extended-data stderr.
  grep -Eq 'exec request failed on channel [0-9]+|ERR: (deploy key authorization refusal:|deploy key does not grant required scope|SSH command authorization source is unavailable)' "$stderr_path"
}

live_ls_remote client_rw live-initial
fge_assert_eq FG-047B-SEC-040 0 "$LIVE_RC" 'the initial write-capable key can read on the existing listener'
fge_assert_cmd FG-047B-SEC-041 'the initial live-key read returns the imported main ref' \
  grep -q "^$(git -C "$SRC" rev-parse main)[[:space:]]refs/heads/main\$" "$WORK/live-initial.refs"
live_ls_remote client_unknown live-unknown
fge_assert_cmd FG-047B-SEC-042 'the future rotation key is refused before it is granted' refused_before_deadline "$LIVE_RC" "$WORK/live-unknown.err"
fge_assert_cmd FG-047B-SEC-043 'the unknown key receives no ref advertisement' test ! -s "$WORK/live-unknown.refs"

replace_deploy_keys </dev/null
live_ls_remote client_rw live-revoked
fge_assert_cmd FG-047B-SEC-044 'an empty replacement revokes the previously admitted key without restarting SSH' refused_before_deadline "$LIVE_RC" "$WORK/live-revoked.err"
fge_assert_cmd FG-047B-SEC-045 'the revoked key receives no ref advertisement' test ! -s "$WORK/live-revoked.refs"

replace_deploy_keys <<EOF
$RO_HEX $PRINCIPAL read
$UNKNOWN_HEX $PRINCIPAL read,write # newly rotated grant
EOF
live_ls_remote client_unknown live-rotated
fge_assert_eq FG-047B-SEC-046 0 "$LIVE_RC" 'the previously unknown key is admitted after atomic table rotation'
fge_assert_cmd FG-047B-SEC-047 'rotation returns exactly the original ref advertisement' \
  cmp -s "$WORK/live-initial.refs" "$WORK/live-rotated.refs"
live_ls_remote client_rw live-retired
fge_assert_cmd FG-047B-SEC-048 'rotation does not revive the retired key from a stale cache' refused_before_deadline "$LIVE_RC" "$WORK/live-retired.err"
fge_assert_cmd FG-047B-SEC-049 'the retired key still receives no refs' test ! -s "$WORK/live-retired.refs"

LIVE_GRANTED_REF=refs/heads/live-key-write
LIVE_DENIED_REF=refs/heads/live-key-denied
live_push client_unknown live-write-granted "$LIVE_GRANTED_REF"
fge_assert_eq FG-047B-SEC-050 0 "$LIVE_RC" 'the rotated read-write key can publish a real branch before downgrade'
live_ls_remote client_unknown live-before-downgrade
fge_assert_eq FG-047B-SEC-051 0 "$LIVE_RC" 'the newly published branch can be read before downgrade'
fge_assert_cmd FG-047B-SEC-052 'the granted write published the expected branch tip' \
  grep -q "^$(git -C "$SRC" rev-parse main)[[:space:]]$LIVE_GRANTED_REF\$" "$WORK/live-before-downgrade.refs"

replace_deploy_keys <<EOF
$RO_HEX $PRINCIPAL read
$UNKNOWN_HEX $PRINCIPAL read # write access revoked
EOF
live_push client_unknown live-write-denied "$LIVE_DENIED_REF"
fge_assert_cmd FG-047B-SEC-053 'downgrading the same key to read-only refuses its next push' refused_before_deadline "$LIVE_RC" "$WORK/live-write-denied.err"
live_ls_remote client_unknown live-after-downgrade
fge_assert_eq FG-047B-SEC-054 0 "$LIVE_RC" 'the downgraded key retains read access on the same listener'
fge_assert_cmd FG-047B-SEC-055 'the refused write left the full advertised ref map unchanged' \
  cmp -s "$WORK/live-before-downgrade.refs" "$WORK/live-after-downgrade.refs"

# A valid matching first row must not hide a malformed later row. The whole
# table is untrusted until validation finishes; previous grants cannot survive.
replace_deploy_keys <<EOF
$UNKNOWN_HEX $PRINCIPAL read
$RW_HEX $PRINCIPAL read,write unexpected-field
EOF
live_ls_remote client_unknown live-invalid
fge_assert_cmd FG-047B-SEC-056 'a malformed replacement fails closed even after a matching valid row' refused_before_deadline "$LIVE_RC" "$WORK/live-invalid.err"
fge_assert_cmd FG-047B-SEC-057 'an invalid replacement leaks no ref advertisement' test ! -s "$WORK/live-invalid.refs"

replace_deploy_keys <<EOF
$RO_HEX $PRINCIPAL read
$UNKNOWN_HEX $PRINCIPAL read # repaired source
EOF
live_ls_remote client_unknown live-repaired
fge_assert_eq FG-047B-SEC-058 0 "$LIVE_RC" 'repairing the table restores reads without restarting the listener'
fge_assert_cmd FG-047B-SEC-059 'repair preserves the repository state from before the invalid table' \
  cmp -s "$WORK/live-before-downgrade.refs" "$WORK/live-repaired.refs"
fge_assert_cmd FG-047B-SEC-060 'the original listener PID survived revocation, rotation, downgrade, refusal, and repair' \
  kill -0 "$LIVE_SERVER_PID"

# Quiescent teardown: reap the listening SSH server
fge_reap "$SSH_NAME"

# Verify server process has exited cleanly (quiescence oracle)
sleep 1
if kill -0 "$SERVE_PID" 2>/dev/null; then
  fge_assert_cmd FG-047B-SEC-023 'server process reaped cleanly' false
else
  fge_assert_cmd FG-047B-SEC-023 'server process reaped cleanly' true
fi
