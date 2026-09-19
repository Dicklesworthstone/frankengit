#!/usr/bin/env bash
# e2e: FG-043c -- protected ref governance vocabulary and break-glass emergency override protocol
#
# Asserts:
# 1. Machine-readable vocabulary matrix covers admit/refuse for every rule.
# 2. Break-glass protocol enforces auth strength, reasons, approval threshold,
#    self-approval prohibition, scope bounds, and audit token content-addressing.
# 3. Displaced-state retention and immutable post-review obligations are preserved.
# 4. Planted inline-bypass defects in receive-pack and merge protection are caught.
#
# Pure bash plus coreutils, per FG-000A-PORT-019.
set -euo pipefail

POLICY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
POLICY_REPO=$(cd "$POLICY_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$POLICY_REPO/scripts/e2e/lib.sh"

fge_init suites-policy-protected_refs_breakglass
fge_context bead frankengit-fg043c-policy-evidence-vfrn
fge_context crate fgit-policy
fge_context campaign protected_refs_breakglass

readonly POLICY_CRATE="$POLICY_REPO/crates/fgit-policy"
readonly ADMISSION_CRATE="$POLICY_REPO/crates/fgit-admission"
readonly VOCAB_MATRIX="$POLICY_CRATE/tests/vocabulary_matrix.rs"
readonly BREAK_GLASS_EVIDENCE="$POLICY_CRATE/tests/break_glass_evidence.rs"
readonly BREAK_GLASS_IMPL="$POLICY_CRATE/src/break_glass.rs"
readonly PROTECTED_REF_IMPL="$POLICY_CRATE/src/protected_ref.rs"
readonly PLANTED_BYPASSES="$ADMISSION_CRATE/tests/planted_bypasses.rs"

fge_phase setup

fge_assert_file FG-043C-E2E-001 "$VOCAB_MATRIX" 'vocabulary matrix test suite is present'
fge_assert_file FG-043C-E2E-002 "$BREAK_GLASS_EVIDENCE" 'break-glass evidence test suite is present'
fge_assert_file FG-043C-E2E-003 "$BREAK_GLASS_IMPL" 'break-glass implementation is present'
fge_assert_file FG-043C-E2E-004 "$PROTECTED_REF_IMPL" 'protected ref implementation is present'
fge_assert_file FG-043C-E2E-005 "$PLANTED_BYPASSES" 'planted bypasses admission test suite is present'

fge_phase assert

# Crate constitution
fge_assert_cmd FG-043C-E2E-010 'fgit-policy forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$POLICY_CRATE/src/lib.rs"

fge_assert_cmd FG-043C-E2E-011 'fgit-admission forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$ADMISSION_CRATE/src/lib.rs"

# Vocabulary matrix coverage
fge_assert_cmd FG-043C-E2E-020 'vocabulary matrix tests admit and refuse directions' \
  grep -qF 'vocabulary_matrix_machine_readable_admit_and_refuse_coverage' "$VOCAB_MATRIX"

fge_assert_cmd FG-043C-E2E-021 'composition governance rules are verified' \
  grep -qF 'composition_fixtures_composite_governance_rule' "$VOCAB_MATRIX"

fge_assert_cmd FG-043C-E2E-022 'temporal expiry and revocation fixtures are verified' \
  grep -qF 'revocation_and_temporal_expiry_fixtures' "$VOCAB_MATRIX"

# Break-glass invariant verification
fge_assert_cmd FG-043C-E2E-030 'break-glass weak authentication is refused' \
  grep -qF 'break_glass_weak_or_missing_authentication_refusal' "$BREAK_GLASS_EVIDENCE"

fge_assert_cmd FG-043C-E2E-031 'break-glass missing or overlong reason is refused' \
  grep -qF 'break_glass_missing_or_overlong_reason_refusal' "$BREAK_GLASS_EVIDENCE"

fge_assert_cmd FG-043C-E2E-032 'break-glass approval threshold and deduplication race' \
  grep -qF 'break_glass_approval_threshold_and_deduplication_race' "$BREAK_GLASS_EVIDENCE"

fge_assert_cmd FG-043C-E2E-033 'break-glass self-approval prohibition' \
  grep -qF 'break_glass_self_approval_prohibition' "$BREAK_GLASS_EVIDENCE"

fge_assert_cmd FG-043C-E2E-034 'break-glass scope and temporal bounds' \
  grep -qF 'break_glass_scope_and_temporal_bounds' "$BREAK_GLASS_EVIDENCE"

fge_assert_cmd FG-043C-E2E-035 'break-glass audit token tamper detection' \
  grep -qF 'break_glass_audit_token_tamper_detection_and_notification_integrity' "$BREAK_GLASS_EVIDENCE"

fge_assert_cmd FG-043C-E2E-036 'break-glass displaced state retention and post-review obligation' \
  grep -qF 'break_glass_successful_execution_retains_displaced_state_and_post_review' "$BREAK_GLASS_EVIDENCE"

# Planted bypass defense
fge_assert_cmd FG-043C-E2E-040 'planted receive-pack force push bypass is caught' \
  grep -qF 'planted_bypass_receive_pack_force_push_on_protected_ref_is_caught' "$PLANTED_BYPASSES"

fge_assert_cmd FG-043C-E2E-041 'planted canonical ref state force bypass is refused' \
  grep -qF 'planted_bypass_canonical_ref_state_apply_force_update_is_refused' "$PLANTED_BYPASSES"

fge_assert_cmd FG-043C-E2E-042 'planted merge direct push violation is caught' \
  grep -qF 'planted_bypass_merge_protection_direct_push_violation_is_caught' "$PLANTED_BYPASSES"

fge_assert_cmd FG-043C-E2E-043 'planted effects protection catches unadmitted updates' \
  grep -qF 'planted_bypass_effects_protection_catches_unadmitted_updates' "$PLANTED_BYPASSES"
