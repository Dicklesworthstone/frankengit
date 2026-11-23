#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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
    expect_exit "$id-init" 0 "$FG_BIN" init "$root/source" 11111111111111111111111111111111 22222222222222222222222222222222 "$format"
    expect_exit "$id-export" 0 "$FG_BIN" authority-backup export "$root/source/authority.fsqlite" "$root/archive" "${export_args[@]}"
    restore=("$FG_BIN" authority-backup restore "$root/archive" "$root/dest" "${export_args[@]}" --expected-sha256 "$(fge_digest_file "$root/archive")" --destination-instance 99)
    expect_exit "$id-restore" 0 "${restore[@]}"
    expect_exit "$id-before" 0 "$FG_BIN" authority-backup export "$root/dest/authority.fsqlite" "$root/before" "${export_args[@]}"

    # Exercise final-location verification and cleanup through a real resume.
    quarantine="$root/dest/.authority-restore-quarantine"
    mkdir "$quarantine"
    unknown="$quarantine/authority.fsqlite-future-format"
    known="$quarantine/authority.fsqlite-shm"
    printf 'retain unknown bytes' > "$unknown"
    printf 'retain known bytes until cleanup' > "$known"
    unknown_hash=$(fge_digest_file "$unknown")
    known_hash=$(fge_digest_file "$known")
    expect_exit "$id-refusal" 2 "${restore[@]}" --resume
    fge_assert_contains "$id-names-file" "$FGE_LAST_STDERR" 'authority.fsqlite-future-format'
    fge_assert_eq "$id-unknown-preserved" "$unknown_hash" "$(fge_digest_file "$unknown" || echo missing)"
    fge_assert_eq "$id-known-preserved" "$known_hash" "$(fge_digest_file "$known" || echo missing)"
    rm -- "$unknown"
    expect_exit "$id-resume" 0 "${restore[@]}" --resume
    expect_exit "$id-cleanup" 0 test ! -e "$quarantine"
    expect_exit "$id-after" 0 "$FG_BIN" authority-backup export "$root/dest/authority.fsqlite" "$root/after" "${export_args[@]}"
    expect_exit "$id-identical-restored-image" 0 cmp "$root/before" "$root/after"
done
