#!/usr/bin/env bash
# e2e: the publication crash matrix and anti-rollback campaign for
# fgit-chronicle, run as one revision-bound lane.
#
# The campaign is written by a pane that did not implement the crate. That
# separation is the point of the bead, so this script asserts it mechanically
# rather than trusting the roster: it fails if the campaign file ever starts
# touching fgit-chronicle/src, which is the way verifier independence quietly
# stops being true.
#
# Pure bash plus coreutils, per FG-000A-PORT-019. No awk, jq, python or perl.
set -euo pipefail

CR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CR_REPO=$(cd "$CR_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CR_REPO/scripts/e2e/lib.sh"

fge_init fg009b-crash-antirollback
fge_context bead frankengit-fg009b-crash-antirollback-6zy
fge_context crate fgit-chronicle
fge_context campaign crash_matrix_publication

readonly CR_CAMPAIGN="$CR_REPO/crates/fgit-chronicle/tests/crash_matrix_publication.rs"

fge_phase setup

fge_assert_file FG-009B-E2E-001 "$CR_CAMPAIGN" 'the crash campaign is present'
fge_artifact "$CR_CAMPAIGN" crash-campaign

# The faults this campaign relies on. If the campaign ever stops arming a
# fault it becomes a plain happy-path suite that still passes, so the presence
# of each mechanism is asserted rather than assumed.
cr_missing=''
for cr_needle in \
  'FaultKind::LoseRequest' \
  'FaultKind::LoseResponse' \
  'AuthorityOpKind::CompareExchangeHead' \
  'AuthorityOpKind::PutIfAbsent' \
  'only_for'; do
  if ! grep -qF "$cr_needle" "$CR_CAMPAIGN"; then
    cr_missing="$cr_missing $cr_needle"
  fi
done

# Verifier independence, asserted rather than trusted: the campaign must read
# fgit-chronicle's public surface and never reach into its source tree.
cr_reaches_into_src=''
if grep -qE '(include!|path *= *"[^"]*chronicle/src)' "$CR_CAMPAIGN"; then
  cr_reaches_into_src='yes'
fi

# Count the crash points the campaign actually arms, so a campaign that
# quietly lost its fault plans reports a smaller number rather than passing.
cr_armed=$(grep -c 'armed(' "$CR_CAMPAIGN" || true)
cr_tests=$(grep -c '^fn ' "$CR_CAMPAIGN" || true)

fge_step campaign-shape "campaign: $cr_tests functions, $cr_armed armed fault sites"

fge_phase action

fge_run chronicle-crash-matrix \
  cargo test --locked -p fgit-chronicle --test crash_matrix_publication
cr_matrix_exit=$FGE_LAST_EXIT

# The pre-existing chronicle suites must keep passing alongside the new one: a
# campaign that breaks the crate's own evidence is not verification.
fge_run chronicle-publication-invariants \
  cargo test --locked -p fgit-chronicle --test publication_invariants
cr_invariants_exit=$FGE_LAST_EXIT

fge_run chronicle-publication-race \
  cargo test --locked -p fgit-chronicle --test publication_race
cr_race_exit=$FGE_LAST_EXIT

fge_run chronicle-recovery-rules \
  cargo test --locked -p fgit-chronicle --test recovery_rules
cr_recovery_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-009B-E2E-010 0 "$cr_matrix_exit" \
  'the crash matrix and anti-rollback campaign passes'
fge_assert_exit FG-009B-E2E-011 0 "$cr_invariants_exit" \
  'the crate publication invariants still pass alongside it'
fge_assert_exit FG-009B-E2E-012 0 "$cr_race_exit" \
  'the crate race evidence still passes alongside it'
fge_assert_exit FG-009B-E2E-013 0 "$cr_recovery_exit" \
  'the crate recovery rules still pass alongside it'

fge_assert_eq FG-009B-E2E-014 '' "$cr_missing" \
  'every fault mechanism the campaign depends on is still present in it'
fge_assert_eq FG-009B-E2E-015 '' "$cr_reaches_into_src" \
  'the campaign reads the public surface and never reaches into chronicle/src'

# A campaign with no armed faults would pass every assertion above while
# exercising none of the crash matrix, so the count is a floor rather than a
# decoration.
if [ "$cr_armed" -lt 4 ]; then
  fge_fail FG-009B-E2E-016 \
    "only $cr_armed armed fault sites; the crash matrix requires at least four"
fi
if [ "$cr_tests" -lt 8 ]; then
  fge_fail FG-009B-E2E-017 \
    "only $cr_tests functions in the campaign; the dispatch names more scenarios than that"
fi
