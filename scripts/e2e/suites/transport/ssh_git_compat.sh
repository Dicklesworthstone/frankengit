#!/usr/bin/env bash
# e2e: stock OpenSSH + git compatibility over `fg serve-ssh` (x2mv.4.4 item 4/5)
# Bead: frankengit-root-doctrine-x2mv.4.4
#
# Proves, against the real `fg serve-ssh` binary and stock clients:
# 1. an initial push of a delta-bearing history into an empty node, then an
#    incremental push, both over SSH;
# 2. protocol v0 and v2 clones and a v2 fetch return the pushed refs and
#    objects byte-identically (strict fsck);
# 3. a push to a review-protected ref is refused by admission through
#    report-status and publishes nothing;
# 4. a silent client holding the only worker is released by the session read
#    timeout, after which a real clone succeeds;
# 5. a clone killed mid-transfer leaves the server serving the next clone;
# 6. the same node served over `fg serve-http` returns the identical refs and
#    the identical object set (HTTP-vs-SSH differential).
# The pinned OpenSSH and git client versions are recorded in the NDJSON.
#
# FG_E2E_SSH_DELTA_BASE_BYTES sizes the incompressible base content (default
# 4 MB), split into files of at most 8 MB so no blob reaches the default
# 32 MiB object ceiling; each of FG_E2E_SSH_DELTA_VERSIONS further commits
# (default 4) rewrites 4 KiB of one file, so the history is delta-friendly.
# When the history outgrows the default receive envelope, serve-ssh and
# serve-http get an explicit envelope sized from it, through the same flags
# `fg serve` takes. For the acceptance envelope use a RELEASE FG_BIN and
# >= 209715200 bytes.
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
fge_context non_claim 'Stock OpenSSH and git against one local fg serve-ssh with one worker, then fg serve-http on the same node; not a throughput, multi-client or hostile-network claim.'

TENANT="11111111111111111111111111111111"
REPOID="22222222222222222222222222222222"
PRINCIPAL="44444444444444444444444444444444"
BASE_BYTES="${FG_E2E_SSH_DELTA_BASE_BYTES:-4000000}"
VERSIONS="${FG_E2E_SSH_DELTA_VERSIONS:-4}"
fge_context base_bytes "$BASE_BYTES"
fge_context versions "$VERSIONS"
# The receive envelope: twice the history plus headroom, in MiB. Explicit
# flags only when the defaults (64 MiB input, 128 MiB expanded) cannot hold
# it, so the default-sized run still exercises the default limits.
ENVELOPE_MIB=$(( BASE_BYTES * 2 / 1048576 + 64 ))
ENVELOPE=()
if [ $(( BASE_BYTES * 2 )) -gt $(( 64 * 1048576 )) ]; then
  ENVELOPE=(--receive-max-input-mib "$ENVELOPE_MIB" --receive-max-expanded-mib "$ENVELOPE_MIB"
    --pack-max-expanded-mib "$ENVELOPE_MIB" --session-timeout-secs 1800)
fi
fge_context receive_envelope "${ENVELOPE[*]:-default}"

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
FILE_BYTES=$(( BASE_BYTES < 8000000 ? BASE_BYTES : 8000000 ))
FILES=$(( (BASE_BYTES + FILE_BYTES - 1) / FILE_BYTES ))
fge_context base_files "$FILES"
for file in $(seq 1 "$FILES"); do
  head -c "$FILE_BYTES" /dev/urandom > "$SRC/data-$file.bin"
done
git -C "$SRC" add -A
git -C "$SRC" commit -qm 'base'
for version in $(seq 1 "$VERSIONS"); do
  # Rewrite 4 KiB of one file in place: it deltas cheaply against the last.
  target=$(( (version - 1) % FILES + 1 ))
  head -c 4096 /dev/urandom | dd of="$SRC/data-$target.bin" bs=4096 seek="$version" conv=notrunc status=none
  printf 'version %s\n' "$version" > "$SRC/VERSION"
  git -C "$SRC" add -A
  git -C "$SRC" commit -qm "version $version"
done

INIT_RC=0
"$FG_BIN" init "$STORAGE" "$TENANT" "$REPOID" >/dev/null 2>&1 || INIT_RC=$?
fge_assert_eq SSH-COMPAT-003 0 "$INIT_RC" 'an empty node initializes'
REVIEWER="55555555555555555555555555555555"
PROTECT_RC=0
"$FG_BIN" protection set "$STORAGE" "$TENANT" "$REPOID" --trusted-local --object-format sha1 \
  --principal "$PRINCIPAL" --idempotency-key ssh-compat-protect --expected-version 0 --expected-epoch 1 \
  --admin "$PRINCIPAL" --require-reviewer "refs/heads/protected:$REVIEWER" >"$WORK/protect.json" 2>"$WORK/protect.err" || PROTECT_RC=$?
fge_assert_eq SSH-COMPAT-006 0 "$PROTECT_RC" 'refs/heads/protected requires a review before any direct write'

printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$WORK/host_key.hex"
ssh-keygen -t ed25519 -N "" -f "$WORK/client_rw" -C rw -q
hex_key() { cut -d' ' -f2 "$1" | base64 -d | tail -c 32 | od -An -tx1 | tr -d ' \n'; }
printf '%s %s read,write\n' "$(hex_key "$WORK/client_rw.pub")" "$PRINCIPAL" > "$WORK/deploy_keys.txt"

fge_phase action
SSH_PORT=''
SSH_NAME=''
for attempt in 0 1 2 3 4 5 6 7; do
  port=$(( 24000 + (($$ + attempt * 131) % 20000) ))
  fge_spawn "serve-ssh-$port" bash -c 'bin=$1 store=$2 tenant=$3 repo=$4 port=$5 key=$6 keys=$7 out=$8; shift 8
    exec "$bin" serve-ssh "$store" "$tenant" "$repo" "127.0.0.1:$port" --host-key-file "$key" --deploy-keys-file "$keys" --allow-receive --max-sessions 64 --max-in-flight 1 "$@" >"$out/serve.out" 2>"$out/serve.err"' \
    _ "$FG_BIN" "$STORAGE" "$TENANT" "$REPOID" "$port" "$WORK/host_key.hex" "$WORK/deploy_keys.txt" "$WORK" "${ENVELOPE[@]}"
  sleep 1
  if kill -0 "$FGE_LAST_PID" 2>/dev/null; then
    SSH_PORT=$port
    SSH_NAME="serve-ssh-$port"
    break
  fi
done
fge_assert_cmd SSH-COMPAT-004 'fg serve-ssh listens on loopback with one worker' test -n "$SSH_PORT"

# OpenSSH keeps the FIRST value of a repeated -o option, so the connect (and
# banner) timeout leads each variant: ordinary calls fail fast, while a client
# queued behind the single busy worker may wait for its release.
SSH_REST="-p $SSH_PORT -i $WORK/client_rw -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o LogLevel=ERROR"
SSH_CMD="ssh -o ConnectTimeout=5 $SSH_REST"
SSH_PATIENT="ssh -o ConnectTimeout=150 $SSH_REST"
REMOTE="ssh://git@127.0.0.1:$SSH_PORT/$REPOID.git"
git -C "$SRC" remote add fg "$REMOTE"

# 1. Initial push of the whole delta-bearing history into the empty node.
INITIAL_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 900 git -C "$SRC" push -q fg main 2>"$WORK/initial.err" || INITIAL_RC=$?
fge_assert_eq SSH-COMPAT-005 0 "$INITIAL_RC" 'initial push of the full history into an empty node succeeds'

# 2. Clones over protocol v0 and v2 are exact. A packet trace first proves
#    which protocol the server actually speaks: git silently falls back to
#    v0 when a server ignores GIT_PROTOCOL, so a v2 clone succeeding alone
#    proves nothing about v2.
for version in 0 2; do
  NEGOTIATE_RC=0
  GIT_TRACE_PACKET="$WORK/trace-v$version" GIT_SSH_COMMAND="$SSH_CMD" timeout 300 \
    git -c protocol.version="$version" ls-remote "$REMOTE" >/dev/null 2>"$WORK/ls-remote-v$version.err" || NEGOTIATE_RC=$?
  fge_assert_eq "SSH-COMPAT-11$version" 0 "$NEGOTIATE_RC" "protocol v$version ls-remote succeeds"
  if [ "$version" = 2 ]; then
    fge_assert_cmd SSH-COMPAT-122 'the server answers a v2 client with a protocol v2 capability advertisement' \
      grep -Eq '< version 2$' "$WORK/trace-v2"
  else
    fge_assert_cmd SSH-COMPAT-120 'the server answers a v0 client with a v0 ref advertisement, not v2' \
      bash -c '! grep -Eq "< version 2$" "$1"' _ "$WORK/trace-v0"
  fi
  CLONE_RC=0
  GIT_SSH_COMMAND="$SSH_CMD" timeout 900 git -c protocol.version="$version" clone -q "$REMOTE" "$WORK/clone-v$version" 2>"$WORK/clone-v$version.err" || CLONE_RC=$?
  fge_assert_eq "SSH-COMPAT-01$version" 0 "$CLONE_RC" "protocol v$version clone succeeds"
  fge_assert_eq "SSH-COMPAT-02$version" "$(git -C "$SRC" rev-parse main)" \
    "$(git -C "$WORK/clone-v$version" rev-parse HEAD 2>/dev/null || echo missing)" "protocol v$version clone observes the pushed tip"
  FSCK_RC=0
  git -C "$WORK/clone-v$version" fsck --strict >/dev/null 2>&1 || FSCK_RC=$?
  fge_assert_eq "SSH-COMPAT-03$version" 0 "$FSCK_RC" "protocol v$version clone passes strict fsck"
  fge_assert_cmd "SSH-COMPAT-04$version" "protocol v$version clone content is byte-identical" diff -rq -x .git "$WORK/clone-v$version" "$SRC"
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

# 4. A direct push to the review-protected ref is refused by admission and
#    reported through report-status; the ref is not created.
REFUSED_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 300 git -C "$SRC" push fg main:refs/heads/protected >"$WORK/refused.out" 2>"$WORK/refused.err" || REFUSED_RC=$?
fge_assert_cmd SSH-COMPAT-060 'a direct push to a review-protected ref is refused' test "$REFUSED_RC" -ne 0
fge_assert_cmd SSH-COMPAT-061 'the refusal arrives through report-status' grep -Eq 'remote rejected|\[rejected\]' "$WORK/refused.err"
AFTER_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 300 git ls-remote "$REMOTE" >"$WORK/after.refs" 2>"$WORK/after.err" || AFTER_RC=$?
fge_assert_eq SSH-COMPAT-062 0 "$AFTER_RC" 'ls-remote after the refusal succeeds'
fge_assert_cmd SSH-COMPAT-063 'the refused ref was not created' bash -c '! grep -q "refs/heads/protected" "$1"' _ "$WORK/after.refs"
fge_assert_eq SSH-COMPAT-064 "$(git -C "$SRC" rev-parse main)" \
  "$(awk '$2 == "refs/heads/main" {print $1}' "$WORK/after.refs")" 'main is unchanged by the refused push'

# 5. A silent client holds the only worker until the session read timeout
#    (60 s) releases it; a real clone queued behind it then succeeds.
exec 7<>"/dev/tcp/127.0.0.1/$SSH_PORT"
sleep 1
SILENT_START=$(date +%s)
SILENT_RC=0
GIT_SSH_COMMAND="$SSH_PATIENT" timeout 300 git clone -q "$REMOTE" "$WORK/after-silent" 2>"$WORK/after-silent.err" || SILENT_RC=$?
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
GIT_SSH_COMMAND="$SSH_PATIENT" timeout 600 git clone -q "$REMOTE" "$WORK/after-cancel" 2>"$WORK/after-cancel.err" || RESUME_RC=$?
fge_assert_eq SSH-COMPAT-081 0 "$RESUME_RC" 'a clone after the cancelled one succeeds'
fge_assert_cmd SSH-COMPAT-082 'the post-cancellation clone content is byte-identical' diff -rq -x .git "$WORK/after-cancel" "$SRC"

# 7. HTTP-vs-SSH differential: the refs and the complete object set a mirror
#    clone receives over SSH equal those `fg serve-http` returns from the same
#    node. The SSH listener is reaped first, so one process owns the node.
objects() { git -C "$1" cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype) %(objectsize)' | sort; }
SSH_REFS_RC=0
GIT_SSH_COMMAND="$SSH_CMD" timeout 300 git ls-remote "$REMOTE" >"$WORK/ssh.refs" 2>"$WORK/ssh-refs.err" || SSH_REFS_RC=$?
SSH_MIRROR_RC=0
GIT_SSH_COMMAND="$SSH_PATIENT" timeout 900 git clone -q --mirror "$REMOTE" "$WORK/ssh-mirror" 2>"$WORK/ssh-mirror.err" || SSH_MIRROR_RC=$?
fge_assert_eq SSH-COMPAT-090 0 "$((SSH_REFS_RC + SSH_MIRROR_RC))" 'ls-remote and a mirror clone over SSH succeed'
fge_reap "$SSH_NAME"

head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/http.token"
chmod 600 "$WORK/http.token"
fge_spawn serve-http bash -c 'bin=$1 store=$2 tenant=$3 repo=$4 token=$5 principal=$6 out=$7; shift 7
  exec "$bin" serve-http "$store" "$tenant" "$repo" 127.0.0.1:0 --trusted-local --token-file "$token" --principal "$principal" --max-sessions 64 --max-in-flight 1 --idle-timeout-secs 120 "$@" >"$out/http.out" 2>"$out/http.err"' \
  _ "$FG_BIN" "$STORAGE" "$TENANT" "$REPOID" "$WORK/http.token" "$PRINCIPAL" "$WORK" "${ENVELOPE[@]}"
HTTP_NAME=serve-http
HTTP_URL=''
for _ in $(seq 1 300); do
  HTTP_URL=$(sed -n 's/.*"type":"smart_http_listening".*"url":"\([^"]*\)".*/\1/p' "$WORK/http.out" 2>/dev/null | head -1)
  [ -n "$HTTP_URL" ] && break
  kill -0 "$FGE_LAST_PID" 2>/dev/null || break
  sleep 0.1
done
fge_assert_cmd SSH-COMPAT-091 'fg serve-http serves the same node on loopback' test -n "$HTTP_URL"
HTTP_AUTH="Authorization: Bearer $(cat "$WORK/http.token")"
HTTP_REFS_RC=0
timeout 300 git -c http.extraHeader="$HTTP_AUTH" ls-remote "$HTTP_URL" >"$WORK/http.refs" 2>"$WORK/http-refs.err" || HTTP_REFS_RC=$?
HTTP_MIRROR_RC=0
timeout 900 git -c http.extraHeader="$HTTP_AUTH" clone -q --mirror "$HTTP_URL" "$WORK/http-mirror" 2>"$WORK/http-mirror.err" || HTTP_MIRROR_RC=$?
fge_assert_eq SSH-COMPAT-092 0 "$((HTTP_REFS_RC + HTTP_MIRROR_RC))" 'ls-remote and a mirror clone over HTTP succeed'
fge_assert_cmd SSH-COMPAT-093 'the SSH ref advertisement names main at the pushed tip' \
  grep -q "^$(git -C "$SRC" rev-parse main)[[:space:]]refs/heads/main\$" "$WORK/ssh.refs"
fge_assert_cmd SSH-COMPAT-094 'HTTP and SSH advertise identical refs' diff -q "$WORK/ssh.refs" "$WORK/http.refs"
objects "$WORK/ssh-mirror" >"$WORK/ssh.objects"
objects "$WORK/http-mirror" >"$WORK/http.objects"
fge_context differential_objects "$(wc -l <"$WORK/ssh.objects" | tr -d ' ')"
fge_assert_cmd SSH-COMPAT-095 'the SSH mirror holds the whole pushed history' \
  test "$(wc -l <"$WORK/ssh.objects")" -ge "$(git -C "$SRC" rev-list --objects --all | wc -l)"
fge_assert_cmd SSH-COMPAT-096 'HTTP and SSH mirror clones hold the identical object set' diff -q "$WORK/ssh.objects" "$WORK/http.objects"

fge_phase teardown
fge_reap "$HTTP_NAME"
