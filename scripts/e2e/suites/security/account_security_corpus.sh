#!/usr/bin/env bash
# e2e: FG-042c account security adversarial and recovery campaign.
#
# Exercises passkeys, OAuth PKCE, rate limiting, delay-and-notify recovery,
# and privilege elevation reauth controls via fgit-identity test targets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='account_security'
readonly RUN_OBLIGATION='fg042c-account-security-corpus-runner'

main() {
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg042c-account-security-evidence-9xq9
  fge_context suite account-security-corpus
  fge_context evidence_class local_exact
  fge_context non_claim 'in-process pure-Rust cryptographic and protocol validation; does not claim live third-party WebAuthn browser hardware token interaction'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture account-security-corpus-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-identity --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"

  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" account-security-corpus-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" account-security-corpus-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-042C-E2E-001' 0 "$test_exit" \
    'the account security corpus test target completes successfully'
  fge_assert_contains 'FG-042C-E2E-002' "$output" \
    'passkey_registration_and_assertion_roundtrip' \
    'passkey WebAuthn registration and assertion roundtrip succeeds with MultiFactor strength'
  fge_assert_contains 'FG-042C-E2E-003' "$output" \
    'passkey_assertion_refuses_counter_regression' \
    'passkey authenticator clone/replay attempts trip monotonic counter regression defense'
  fge_assert_contains 'FG-042C-E2E-004' "$output" \
    'oauth_pkce_s256_verification_and_code_redemption' \
    'OAuth PKCE S256 verifies challenge and enforces single-use code redemption'
  fge_assert_contains 'FG-042C-E2E-005' "$output" \
    'oauth_redirect_uri_rejects_fragments_and_wildcards' \
    'OAuth redirect URI validation strictly rejects fragments and wildcards'
  fge_assert_contains 'FG-042C-E2E-006' "$output" \
    'rate_limiter_locks_out_after_consecutive_failures' \
    'rate limiter enforces progressive lockout on repeated authentication failures'
  fge_assert_contains 'FG-042C-E2E-007' "$output" \
    'recovery_delay_and_notification_enforced' \
    'recovery state machine enforces mandatory 24h delay and active session cancellation'
  fge_assert_contains 'FG-042C-E2E-008' "$output" \
    'recovery_yields_single_factor_only' \
    'recovery sessions bind strictly to single-factor authentication strength'
  fge_assert_contains 'FG-042C-E2E-009' "$output" \
    'privilege_elevation_token_enforces_narrow_window_and_action' \
    'privilege elevation tokens enforce 300s window and action binding'
}

fge_init fg042c-account-security-corpus
main
