#!/usr/bin/env bash
# e2e: the destructive capsule drills, run end to end.
#
# FG-010b. The bead names `scripts/e2e/capsule_drills.sh`; discovery is by
# directory under `scripts/e2e/suites`, so the suite lives at
# `suites/chronicle/capsule_drills.sh` and is registered as
# `suites-chronicle-capsule_drills` without an edit to run_all.sh. Same
# capability, current layout.
#
# What is worth running end to end rather than trusting:
#
#   1. the classification matrix — the SAME damage must classify differently
#      depending on whether repair material exists, and the two
#      authenticity/ordering defects must fail closed under every profile;
#   2. the masquerade drill — a valid older capsule behind an unverifiable
#      newer acknowledged one must fail closed with BOTH preserved;
#   3. that "recoverable-with-repair" never becomes an automatic path.
#
# The third is the one that would be quiet if it broke. A classifier that let
# automation repair its way past an unverifiable acknowledged root would be
# exactly the silent retreat NORMATIVE_PROTOCOL_CONTRACTS section 23 forbids,
# just wearing a different name, and the repository would come up looking
# healthy having discarded every decision since.
set -euo pipefail

CD_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CD_REPO=$(cd "$CD_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CD_REPO/scripts/e2e/lib.sh"

fge_init fg010b-capsule-drills
fge_context bead frankengit-fg010b-capsule-drills-doa
fge_context crate fgit-chronicle
fge_context harness_seed "$(fge_seed)"

# The fixture matrix is exhaustive over (defect class x backup profile), not
# sampled, so there is no property seed to record.
fge_context sampling none

fge_phase setup

fge_assert_file FG-010b-E2E-001 "$CD_REPO/crates/fgit-chronicle/src/verify.rs" \
  'the capsule classifier is present'
fge_assert_file FG-010b-E2E-002 "$CD_REPO/crates/fgit-chronicle/tests/capsule_drills.rs" \
  'the destructive drill fixtures are checked in'

fge_phase action

fge_run chronicle-capsule-drills \
  cargo test --locked -p fgit-chronicle --test capsule_drills
cd_drills_exit=$FGE_LAST_EXIT

# The drills sit on top of fg010a's recovery rules; if those regress the
# masquerade assertion above is resting on a broken foundation.
fge_run chronicle-recovery-rules \
  cargo test --locked -p fgit-chronicle --test recovery_rules
cd_recovery_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-010b-E2E-010 0 "$cd_drills_exit" \
  'every destructive fixture reaches its expected typed classification'
fge_assert_exit FG-010b-E2E-011 0 "$cd_recovery_exit" \
  'the fg010a recovery rules the drills rest on still hold'

# Repair symbols reconstruct bytes. They cannot make a capsule be a checkpoint
# of a head it never had, so the two authenticity/ordering defects must not be
# reachable from the reconstructible set. Asserted against the source because
# it is a property of the classifier's shape, not of one test run.
fge_assert_cmd FG-010b-E2E-012 \
  'identity and predecessor defects are excluded from the reconstructible set' \
  grep -qE 'Self::IdentityMismatch \{ \.\. \} \| Self::PredecessorStale \{ \.\. \} => false' \
  "$CD_REPO/crates/fgit-chronicle/src/verify.rs"

# The planner must not gain a variant naming an older capsule. This is fg010a's
# invariant and the drills depend on it; a regression here would make the
# masquerade drill pass while the system became unsafe.
fge_assert_cmd FG-010b-E2E-013 'recovery still cannot express a silent retreat' \
  grep -qE 'pub enum RecoveryPlan \{' "$CD_REPO/crates/fgit-chronicle/src/recovery.rs"
cd_plan_variants=$(grep -cE '^    (Resume|HaltForAudit) \{' \
  "$CD_REPO/crates/fgit-chronicle/src/recovery.rs" || true)
fge_assert_cmd FG-010b-E2E-014 'RecoveryPlan still has exactly its two safe variants' \
  test "$cd_plan_variants" = "2"
fge_note 'RecoveryPlan variant count' "$cd_plan_variants"

# Section 23 is the reason all of this exists; if the sentence moves, the
# drills are enforcing a rule the document no longer states.
fge_assert_cmd FG-010b-E2E-015 'section 23 still forbids the silent retreat' \
  grep -qF 'Older-state recovery is an explicit audited restore that advances a new authority generation' \
  "$CD_REPO/docs/NORMATIVE_PROTOCOL_CONTRACTS.md"
