#!/usr/bin/env bash
# e2e: defensive crypto key-lifecycle abuse drills with authenticated GC evidence.
#
# This suite intentionally composes two independent boundaries. `fgit-crypto`
# provides typed, receipted key lifecycle refusal; fg033b's `fgit-repair` GC
# epoch supplies the authenticated logical-deletion state. Neither pretends to
# subsume the other, and the suite records both real test oracles together.

set -euo pipefail

KA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KA_REPO=$(cd "$KA_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$KA_REPO/scripts/e2e/lib.sh"

capture_test() {
  local step=$1
  local output_name=$2
  shift 2

  fge_capture "$step" env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked "$@" || true
  printf -v "$output_name" '%s' "$FGE_LAST_STDOUT"
  return "$FGE_LAST_EXIT"
}

main() {
  local abuse_exit=0 gc_exit=0
  local abuse_out='' gc_out=''

  fge_phase setup
  fge_context crate fgit-crypto
  fge_context lab_schedule 'explicit reader-before/after-rotation, writer, revoker interleavings'
  fge_context deletion_integration 'typed crypto erasure receipt alongside fg033b authenticated GC epoch'
  fge_context non_claim 'This proves key-registry refusal and authenticated object-GC evidence. It does not claim physical deletion of root-secret copies retained outside the key registry.'
  fge_assert_file FG-057B-E2E-001 "$KA_REPO/crates/fgit-crypto/tests/key_abuse.rs" \
    'the defensive key-abuse conformance drill is checked in'
  fge_assert_file FG-057B-E2E-002 "$KA_REPO/crates/fgit-repair/tests/gc_epoch.rs" \
    'fg033b authenticated GC-epoch evidence is checked in'

  fge_phase action
  capture_test crypto-key-abuse abuse_out \
    -p fgit-crypto --test key_abuse || abuse_exit=$?
  capture_test fg033b-authenticated-gc-epoch gc_out \
    -p fgit-repair --test gc_epoch \
    logical_tombstone_is_distinct_from_physical_deletion -- --exact || gc_exit=$?

  fge_phase assert
  fge_assert_exit FG-057B-E2E-010 0 "$abuse_exit" \
    'serialized cross-purpose material, scheduled rotation, and terminal erasure all refuse safely'
  fge_assert_contains FG-057B-E2E-011 "$abuse_out" \
    'serialized_cross_purpose_material_is_refused_with_a_same_purpose_twin ... ok' \
    'a serialized capsule key cannot acquire tenant-encryption purpose'
  fge_assert_contains FG-057B-E2E-012 "$abuse_out" \
    'rotation_window_interleavings_are_receipted_and_never_fall_back ... ok' \
    'each replayable lab ordering preserves old reads, new writes, and revocation'
  fge_assert_contains FG-057B-E2E-013 "$abuse_out" \
    'erasure_is_terminal_receipted_and_refuses_every_authorized_read_path ... ok' \
    'an erased key state is permanent and typed rather than unknown'
  fge_assert_exit FG-057B-E2E-020 0 "$gc_exit" \
    'fg033b retains a root-proof-carrying logical deletion state before physical deletion'
  fge_assert_contains FG-057B-E2E-021 "$gc_out" \
    'logical_tombstone_is_distinct_from_physical_deletion ... ok' \
    'authenticated GC evidence remains separate from the crypto key-registry state'
}

fge_init fg057b-crypto-key-abuse
fge_context bead frankengit-fg057b-crypto-keyabuse-mh89
fge_context harness_seed "$(fge_seed)"
main
