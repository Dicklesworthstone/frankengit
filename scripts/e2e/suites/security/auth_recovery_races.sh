#!/usr/bin/env bash
# e2e: FG-042c auth recovery races, adversarial boundaries, and anti-downgrade campaign.
#
# Exercises race conditions, anti-downgrade invariants, privilege elevation bounds,
# and clone/replay detections in fgit-identity.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='auth_recovery_races'
readonly RUN_OBLIGATION='fg042c-auth-recovery-races-runner'

main() {
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg042c-account-security-evidence-9xq9
  fge_context suite auth-recovery-races
  fge_context evidence_class local_exact
  fge_context non_claim 'in-process race and boundary model; does not claim distributed multi-node quorum recovery coordination'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture auth-recovery-races-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-identity --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" auth-recovery-races-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" auth-recovery-races-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-042C-RACE-001' 0 "$test_exit" \
    'the auth recovery races test target completes successfully'
  fge_assert_contains 'FG-042C-RACE-002' "$output" \
    'recovery_delay_is_enforced_and_cancelled_by_active_session' \
    'active sessions successfully cancel pending recovery requests before delay expiration'
  fge_assert_contains 'FG-042C-RACE-003' "$output" \
    'recovery_session_truthfully_binds_single_factor_and_cannot_masquerade' \
    'recovery session cannot masquerade as MultiFactor or satisfy strong-auth requirements'
  fge_assert_contains 'FG-042C-RACE-004' "$output" \
    'privilege_elevation_token_lifecycle_and_single_use' \
    'elevation tokens fail closed upon replay, expiration, principal mismatch, or action mismatch'
  fge_assert_contains 'FG-042C-RACE-005' "$output" \
    'passkey_cloning_and_replay_detection' \
    'passkey counter rollback or clone assertion replay is refused with CounterRegression'
  fge_assert_contains 'FG-042C-RACE-006' "$output" \
    'oauth_pkce_s256_verification_and_code_single_use' \
    'OAuth authorization codes refuse re-redemption replay attempts'
  fge_assert_contains 'FG-042C-RACE-007' "$output" \
    'oauth_redirect_uri_strict_confinement' \
    'OAuth redirect URIs reject fragment identifiers and wildcards'
  fge_assert_contains 'FG-042C-RACE-008' "$output" \
    'rate_limiting_locks_out_brute_force_and_preserves_oracle_opacity' \
    'rate limiting preserves Invariant 17 oracle opacity between valid and nonexistent accounts'
}

fge_init fg042c-auth-recovery-races
main
