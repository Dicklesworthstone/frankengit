#!/usr/bin/env bash
# Exercise the implemented empty-repository one-node lifecycle without ambient
# configuration: init -> doctor -> one bounded git-daemon upload-pack session
# -> authority-selected export.  The transcript is an operator artifact, not a
# claim that this profile completed a Durable publication epoch or supports a
# general clone/fetch/push workflow.  It deliberately lives outside
# `scripts/e2e/suites/`: README invokes it as an operator runbook, while the
# e2e runner discovers every executable suite there and would treat this
# caller-supplied lifecycle exercise as a CI campaign.
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: scripts/one_node_bringup.sh \
  <empty-storage-root> <tenant-id-hex> <repository-id-hex> \
  <unused-loopback-address> <absent-export-pack>

FG_BIN=/path/to/fg may select a prebuilt CLI binary. Without FG_BIN, the
script invokes `cargo run -q -p fgit-cli --` for each fg command.
USAGE
  exit 64
}

if [ "$#" -ne 5 ]; then
  usage
fi

storage_root=$1
tenant_id=$2
repository_id=$3
listen_address=$4
export_pack=$5

case "$listen_address" in
  127.0.0.1:*) ;;
  *)
    printf 'refusing non-loopback listener address: %s\n' "$listen_address" >&2
    exit 64
    ;;
esac
listen_port=${listen_address##*:}
if [[ ! "$listen_port" =~ ^[0-9]+$ ]] \
  || ((10#$listen_port == 0 || 10#$listen_port > 65535)); then
  printf 'listener port must be in 1..65535: %s\n' "$listen_address" >&2
  exit 64
fi

if [ -e "$storage_root" ] && [ ! -d "$storage_root" ]; then
  printf 'storage root is not a directory: %s\n' "$storage_root" >&2
  exit 64
fi
if [ -d "$storage_root" ] && [ -n "$(find "$storage_root" -mindepth 1 -print -quit)" ]; then
  printf 'storage root must be empty: %s\n' "$storage_root" >&2
  exit 64
fi
if [ -e "$export_pack" ]; then
  printf 'export destination must be absent: %s\n' "$export_pack" >&2
  exit 64
fi
mkdir -p "$storage_root"
mkdir -p "$(dirname "$export_pack")"

transcript="$storage_root/bring-up.transcript"
serve_output="$storage_root/serve.output"
advertisement="$storage_root/serve.advertisement"
: >"$transcript"

fg() {
  if [ -n "${FG_BIN:-}" ]; then
    "$FG_BIN" "$@"
  else
    RCH_CARGO_WRAPPER_BYPASS=1 cargo run -q -p fgit-cli -- "$@"
  fi
}

record_fg() {
  printf '+ fg' >>"$transcript"
  printf ' %q' "$@" >>"$transcript"
  printf '\n' >>"$transcript"
  fg "$@" 2>&1 | tee -a "$transcript"
}

serve_pid=''
reap_serve() {
  if [ -n "$serve_pid" ] && kill -0 "$serve_pid" 2>/dev/null; then
    kill "$serve_pid" 2>/dev/null || true
    wait "$serve_pid" 2>/dev/null || true
  fi
  return 0
}
trap reap_serve EXIT

wait_for_listener() {
  local endpoint
  local attempt

  if [ ! -r /proc/net/tcp ]; then
    printf 'cannot observe the loopback listener: /proc/net/tcp is unavailable\n' >&2
    return 1
  fi
  printf -v endpoint '0100007F:%04X' "$((10#$listen_port))"
  for attempt in $(seq 1 100); do
    if grep -E \
      "^[[:space:]]*[0-9]+:[[:space:]]+${endpoint}[[:space:]]+00000000:0000[[:space:]]+0A([[:space:]]|$)" \
      /proc/net/tcp >/dev/null; then
      return 0
    fi
    if ! kill -0 "$serve_pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.05
  done
  return 1
}

record_fg init "$storage_root" "$tenant_id" "$repository_id"
grep -Fqx 'initialized authority head' "$transcript"

record_fg doctor "$storage_root" "$tenant_id" "$repository_id"
grep -F 'authenticated authority head at generation ' "$transcript" >/dev/null

printf '+ fg serve %q %q %q %q --max-sessions 1 --max-in-flight 1\n' \
  "$storage_root" "$tenant_id" "$repository_id" "$listen_address" >>"$transcript"
fg serve "$storage_root" "$tenant_id" "$repository_id" "$listen_address" \
  --max-sessions 1 --max-in-flight 1 \
  >"$serve_output" 2>&1 &
serve_pid=$!

# Checking the kernel listener table does not consume a connection. The one
# `/dev/tcp` open below is therefore the only session consumed by `fg serve`.
if ! wait_for_listener; then
  printf 'fg serve did not accept the bounded loopback session\n' >&2
  cat "$serve_output" >&2
  exit 1
fi
exec 3<>"/dev/tcp/${listen_address%:*}/${listen_port}"

service="git-upload-pack /${repository_id}.git"
host='host=loopback'
packet_length=$((4 + ${#service} + 1 + ${#host} + 1))
printf '%04x%s\0%s\0' "$packet_length" "$service" "$host" >&3
cat <&3 >"$advertisement"
exec 3<&-
wait "$serve_pid"
serve_pid=''
tee -a "$transcript" <"$serve_output"
grep -F 'served bounded git-daemon run on ' "$serve_output" >/dev/null
grep -F 'accepted=1, completed=1, refused=0' "$serve_output" >/dev/null
test -s "$advertisement"
printf 'received %s bytes of empty-repository advertisement\n' "$(wc -c <"$advertisement")" \
  | tee -a "$transcript"

record_fg export "$storage_root" "$tenant_id" "$repository_id" "$export_pack"
grep -F 'exported ' "$transcript" | grep -F ' authority-selected pack bytes to ' >/dev/null
test "$(head -c 4 "$export_pack")" = 'PACK'

printf 'bring-up completed; transcript: %s\n' "$transcript"
