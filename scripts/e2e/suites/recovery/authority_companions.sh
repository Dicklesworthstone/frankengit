#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init authority-companions
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.42
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    fge_fail AUTH-COMPANIONS-BINARY 'native prebuilt FG_BIN required'
    exit 1
fi
fge_context fg_sha256 "$(fge_digest_file "$FG_BIN")"
work="$(fge_tempdir authority-companions)"

expect_exit() {
    local id=$1 expected=$2 actual=0
    shift 2
    fge_capture "$id" "$@" || actual=$?
    fge_assert_exit "$id" "$expected" "$actual"
    [[ "$expected" -eq "$actual" ]]
}

for format in sha1 sha256; do
    root="$work/$format"
    mkdir "$root"
    id="AUTH-COMPANIONS-$format"
    export_args=(--trusted-local --all-heads)
    tenant=11111111111111111111111111111111
    repository=22222222222222222222222222222222
    actor=33333333333333333333333333333333
    expect_exit "$id-init" 0 "$FG_BIN" init "$root/source" "$tenant" "$repository" "$format"
    expect_exit "$id-open-issue" 0 "$FG_BIN" issue open "$root/source" "$tenant" "$repository" 1 \
        --trusted-local --object-format "$format" --principal "$actor" --idempotency-key initial-issue \
        --expected-version 0 --title 'Companion restore' --body 'Preserve this issue through retry.'
    expect_exit "$id-export" 0 "$FG_BIN" authority-backup export "$root/source/authority.fsqlite" "$root/archive" "${export_args[@]}"
    restore=("$FG_BIN" authority-backup restore "$root/archive" "$root/dest" "${export_args[@]}" --expected-sha256 "$(fge_digest_file "$root/archive")" --destination-instance 99)
    expect_exit "$id-restore" 0 "${restore[@]}"
    expect_exit "$id-before" 0 "$FG_BIN" authority-backup export "$root/dest/authority.fsqlite" "$root/before" "${export_args[@]}"

    # Exercise final-location verification and cleanup through a real resume.
    quarantine="$root/dest/.authority-restore-quarantine"
    mkdir "$quarantine"
    unknown="$quarantine/authority.fsqlite-future-format"
    known="$quarantine/authority.fsqlite-shm"
    alias="$quarantine/authority.fsqlite"
    ln "$root/dest/authority.fsqlite" "$alias"
    printf 'retain unknown bytes' > "$unknown"
    printf 'retain known bytes until cleanup' > "$known"
    unknown_hash=$(fge_digest_file "$unknown")
    known_hash=$(fge_digest_file "$known")
    expect_exit "$id-refusal" 2 "${restore[@]}" --resume
    fge_assert_contains "$id-names-file" "$FGE_LAST_STDERR" 'authority.fsqlite-future-format'
    fge_assert_eq "$id-unknown-preserved" "$unknown_hash" "$(fge_digest_file "$unknown" || echo missing)"
    fge_assert_eq "$id-known-preserved" "$known_hash" "$(fge_digest_file "$known" || echo missing)"
    alias_exit=0
    fge_capture "$id-alias-preserved" test "$root/dest/authority.fsqlite" -ef "$alias" || alias_exit=$?
    fge_assert_exit "$id-alias-preserved" 0 "$alias_exit"
    rm -- "$unknown"
    expect_exit "$id-resume" 0 "${restore[@]}" --resume
    expect_exit "$id-cleanup" 0 test ! -e "$quarantine"
    expect_exit "$id-after" 0 "$FG_BIN" authority-backup export "$root/dest/authority.fsqlite" "$root/after" "${export_args[@]}"
    expect_exit "$id-identical-restored-image" 0 cmp "$root/before" "$root/after"
    expect_exit "$id-reopened-issue" 0 "$FG_BIN" issue show "$root/dest" "$tenant" "$repository" 1 \
        --trusted-local --object-format "$format"
    expect_exit "$id-issue-state" 0 python3 -I -c '
import json, sys
record = json.loads(sys.argv[1])
issue = record["issue"]
assert record["node_closed"] is True and record["object_format"] == sys.argv[2]
assert (issue["number"], issue["version"], issue["state"], issue["opened_by"]) == (1, 1, "open", sys.argv[3])
assert (issue["title"], issue["body"]) == ("Companion restore", "Preserve this issue through retry.")
' "$FGE_LAST_STDOUT" "$format" "$actor"

    # A surviving hard-link alias and a complete, controlled set of closed
    # staging files exercise cleanup after publication. Only the reopened
    # destination database decides what the later export contains.
    mkdir "$quarantine"
    ln "$root/dest/authority.fsqlite" "$quarantine/authority.fsqlite"
    for suffix in -journal -shm -wal -wal-fec -wal-fec.lock .fsqlite-shm \
        -fsqlite-ns-gate -fsqlite-ns-use .fsqlite-migration-state \
        -lock-shared -lock-reserved -lock-pending -wal-cert -wal-cert-head; do
        : > "$quarantine/authority.fsqlite$suffix"
    done
    all_exit=0
    fge_capture "$id-all-companions" "${restore[@]}" --resume || all_exit=$?
    fge_assert_exit "$id-all-companions" 0 "$all_exit"
    if [[ "$all_exit" -eq 0 ]]; then
        expect_exit "$id-all-cleaned" 0 test ! -e "$quarantine"
        expect_exit "$id-all-export" 0 "$FG_BIN" authority-backup export "$root/dest/authority.fsqlite" "$root/all" "${export_args[@]}"
        expect_exit "$id-all-identical" 0 cmp "$root/before" "$root/all"
    fi
done
