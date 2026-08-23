#!/usr/bin/env bash
# Exercise the implemented empty-repository one-node lifecycle without ambient
# configuration: init -> doctor -> one bounded git-daemon upload-pack session
# -> authority-selected export.  The transcript is an operator artifact, not a
# claim that this profile completed a Durable publication epoch or supports a
# general clone/fetch/push workflow.
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
}
trap reap_serve EXIT

record_fg init "$storage_root" "$tenant_id" "$repository_id"
grep -Fqx 'initialized authority head' "$transcript"

record_fg doctor "$storage_root" "$tenant_id" "$repository_id"
grep -F 'authenticated authority head at generation ' "$transcript" >/dev/null

printf '+ fg serve %q %q %q %q\n' \
  "$storage_root" "$tenant_id" "$repository_id" "$listen_address" >>"$transcript"
fg serve "$storage_root" "$tenant_id" "$repository_id" "$listen_address" \
  >"$serve_output" 2>&1 &
serve_pid=$!

# A failed connect is before the listener accepts a session. The one successful
# connection below is the only session consumed by `fg serve`.
connected=0
for _attempt in $(seq 1 100); do
  if exec 3<>"/dev/tcp/${listen_address%:*}/${listen_address##*:}"; then
    connected=1
    break
  fi
  sleep 0.05
done
if [ "$connected" -ne 1 ]; then
  printf 'fg serve did not accept the bounded loopback session\n' >&2
  cat "$serve_output" >&2
  exit 1
fi

service="git-upload-pack /${repository_id}.git"
host='host=loopback'
packet_length=$((4 + ${#service} + 1 + ${#host} + 1))
printf '%04x%s\0%s\0' "$packet_length" "$service" "$host" >&3
cat <&3 >"$advertisement"
exec 3<&-
wait "$serve_pid"
serve_pid=''
tee -a "$transcript" <"$serve_output"
grep -F 'served an authenticated empty repository session on ' "$serve_output" >/dev/null
test -s "$advertisement"
printf 'received %s bytes of empty-repository advertisement\n' "$(wc -c <"$advertisement")" \
  | tee -a "$transcript"

record_fg export "$storage_root" "$tenant_id" "$repository_id" "$export_pack"
grep -F 'exported ' "$transcript" | grep -F ' authority-selected pack bytes to ' >/dev/null
test "$(head -c 4 "$export_pack")" = 'PACK'

printf 'bring-up completed; transcript: %s\n' "$transcript"
