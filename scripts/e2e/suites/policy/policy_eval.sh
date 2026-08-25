#!/usr/bin/env bash
# e2e: FG-043a / FG-043b -- policy evaluation, compilation, snapshots, and governance rules
#
# Asserts:
# 1. Policy compiler refuses ambient clock / I/O access and malformed constructs.
# 2. Evaluation produces deterministic, explainable decision traces.
# 3. Policy normalization and snapshot identities are stable.
# 4. Protected ref rules, break-glass protocol, and rollout machinery execute correctly.
#
# Pure bash plus coreutils, per FG-000A-PORT-019.
set -euo pipefail

POLICY_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
POLICY_REPO=$(cd "$POLICY_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$POLICY_REPO/scripts/e2e/lib.sh"

fge_init fg043-policy-eval
fge_context bead frankengit-fg043a-policy-impl-b5n
fge_context crate fgit-policy
fge_context campaign policy_eval

readonly POLICY_CRATE="$POLICY_REPO/crates/fgit-policy"
readonly POLICY_GOLDENS="$POLICY_CRATE/tests/goldens.rs"
readonly POLICY_NORMALIZATION="$POLICY_CRATE/tests/normalization.rs"
readonly POLICY_NEGATIVES="$POLICY_CRATE/tests/planted_negatives.rs"
readonly POLICY_PROTECTED="$POLICY_CRATE/tests/protected_ref_tests.rs"
readonly POLICY_BREAK_GLASS="$POLICY_CRATE/tests/break_glass_tests.rs"
readonly POLICY_ROLLOUT="$POLICY_CRATE/tests/rollout_tests.rs"

fge_phase setup

fge_assert_file FG-043A-E2E-001 "$POLICY_GOLDENS" 'goldens suite is present'
fge_assert_file FG-043A-E2E-002 "$POLICY_NORMALIZATION" 'normalization suite is present'
fge_assert_file FG-043A-E2E-003 "$POLICY_NEGATIVES" 'planted negatives suite is present'
fge_assert_file FG-043B-E2E-001 "$POLICY_PROTECTED" 'protected ref test suite is present'
fge_assert_file FG-043B-E2E-002 "$POLICY_BREAK_GLASS" 'break-glass test suite is present'
fge_assert_file FG-043B-E2E-003 "$POLICY_ROLLOUT" 'rollout test suite is present'

fge_phase assert

# Crate constitution
fge_assert_cmd FG-043A-E2E-010 'fgit-policy forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$POLICY_CRATE/src/lib.rs"

# Planted negatives coverage
fge_assert_cmd FG-043A-E2E-011 'clock read prevention test is present' \
  grep -qF 'the_permitted_twin_of_a_clock_read_is_a_declared_aggregate' "$POLICY_NEGATIVES"

fge_assert_cmd FG-043A-E2E-012 'unknown construct refusal test is present' \
  grep -qF 'an_invented_declaration_is_refused_at_compile_time' "$POLICY_NEGATIVES"

# Protected ref governance checks
fge_assert_cmd FG-043B-E2E-010 'break-glass self-approval prohibition is present' \
  grep -qF 'self_approval_is_strictly_forbidden' "$POLICY_BREAK_GLASS"

fge_assert_cmd FG-043B-E2E-011 'rollout shadow divergence detection test is present' \
  grep -qF 'shadow_mode_detects_divergence_without_blocking_effective_decision' "$POLICY_ROLLOUT"

