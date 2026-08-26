#!/usr/bin/env bash
# e2e: FG-042c recovery + re-auth race and expiry corpus.
#
# Exercises the recovery state machine's delay/notification/downgrade wall
# and the elevation-token lifecycle (single use, principal/action binding,
# expiry) as a distinct lane from the broad corpus, because recovery races
# are the account-takeover path with the highest historical blast radius.
set -euo pipefail

AR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AR_REPO=$(cd "$AR_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$AR_REPO/scripts/e2e/lib.sh"

fge_init fg042c-auth-recovery-races
fge_context bead frankengit-fg042c-account-security-evidence-9xq9
fge_context crate fgit-identity

fge_phase setup

fge_assert_file FG-042C-RACES-FILE \
  "$AR_REPO/crates/fgit-identity/src/recovery.rs" \
  "the delay-and-notify recovery state machine is present"

fge_phase action

fge_run "recovery-races" \
  env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AR_REPO/target}" \
  cargo test --locked -p fgit-identity --test auth_adversarial_recovery || true
recovery_rc=$FGE_LAST_EXIT

fge_run "reauth-races" \
  env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AR_REPO/target}" \
  cargo test --locked -p fgit-identity --lib reauth:: -- --list >/dev/null || true
reauth_list_rc=$FGE_LAST_EXIT

fge_run "reauth-lifecycle" \
  env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$AR_REPO/target}" \
  cargo test --locked -p fgit-identity --test auth_adversarial_rate_limit elevation || true
elevation_rc=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-042C-RACES-001 0 "$recovery_rc" \
  'delay floor, notification requirement, early-completion refusal, one-shot completion, and the SingleFactor downgrade wall all hold'
fge_assert_exit FG-042C-RACES-002 0 "$reauth_list_rc" \
  'the re-auth module enumerates its surface for the lane record'
fge_assert_exit FG-042C-RACES-003 0 "$elevation_rc" \
  'elevation tokens are single-use, principal/action bound, and expiry bounded'

fge_phase teardown
