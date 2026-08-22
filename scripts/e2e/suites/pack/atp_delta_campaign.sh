#!/usr/bin/env bash
# FG-022b: the ATP-Git transfer fault and fallback campaign, as one lane.
#
# The bead asks for `scripts/e2e/atp_delta_campaign.sh` "registered in
# run_all.sh". It lives HERE instead, and the deviation is deliberate: this
# runner discovers executables under `scripts/e2e/suites/<area>/` and its own
# header says "ANYTHING OUTSIDE suites/ IS NOT DISCOVERED AND RUNS NOWHERE."
# A script at the literal path would have satisfied the wording and run in no
# lane, which is worse than not writing it. `pack/` is the area because ATP-Git
# is the delta transfer that sits beneath ordinary pack compatibility.
#
# WHAT THIS LANE IS EVIDENCE FOR, and what it is not.
#
# The campaign is five Rust targets, each covering one of the bead's named
# adversaries. Every one of them pairs its refusals with a PERMITTED case on
# the same code path, because a refusal-only suite passes just as happily
# against a pipeline that refuses everything, and a staging-limit suite passes
# against one that stages nothing. Those controls are the reason the cells
# below are worth asserting at all.
#
# One acceptance line of the bead is NOT covered here and is not silently
# dropped: it is recorded as a typed unsupported cell, so this lane's terminal
# status is non-pass until the orchestrator disposes of it. See FG-022B-E2E-020.
set -euo pipefail

ATP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ATP_REPO=$(cd "$ATP_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$ATP_REPO/scripts/e2e/lib.sh"

fge_init fg022b-atp-delta-campaign
fge_context bead frankengit-fg022b-atp-delta-evidence-a4z
fge_context crate fgit-atp-git

# Builds run locally (AGENTS.md §16.2). Without this the rch wrapper offloads
# the build to a remote worker, which passes there while any artifact it writes
# stays on the remote host.
export RCH_CARGO_WRAPPER_BYPASS=1

readonly ATP_TESTS="$ATP_REPO/crates/fgit-atp-git/tests"

fge_phase setup

fge_assert_file FG-022B-E2E-001 "$ATP_TESTS/fallback_reasons.rs" \
  'the capability-absent fallback campaign is present'
fge_assert_file FG-022B-E2E-002 "$ATP_TESTS/payload_integrity.rs" \
  'the corrupted/truncated/reordered payload campaign is present'
fge_assert_file FG-022B-E2E-003 "$ATP_TESTS/summary_poisoning.rs" \
  'the summary-poisoning campaign is present'
fge_assert_file FG-022B-E2E-004 "$ATP_TESTS/abandonment_visibility.rs" \
  'the mid-transfer abandonment campaign is present'
fge_assert_file FG-022B-E2E-005 "$ATP_TESTS/trust_scope_isolation.rs" \
  'the trust-scope isolation campaign is present'

# The controls, asserted mechanically rather than trusted to survive editing.
#
# Each campaign file's refusals are only meaningful beside a permitted case on
# the same path. If one of these disappears, its file keeps passing while
# testing strictly less -- the failure mode that does not announce itself. This
# is the same guard the FG-005b lane runs over its own campaign's mechanisms.
atp_missing_controls=''
atp_require_control() {
  if ! grep -qF "$2" "$ATP_TESTS/$1"; then
    atp_missing_controls="$atp_missing_controls [$1:$2]"
  fi
}
atp_require_control fallback_reasons.rs 'fn a_fully_capable_pair_does_not_fall_back'
atp_require_control payload_integrity.rs 'fn a_complete_and_correct_payload_set_stages_every_object'
atp_require_control summary_poisoning.rs 'fn an_honest_summary_completes_without_repair'
atp_require_control abandonment_visibility.rs 'fn a_receiver_that_never_abandons_takes_the_whole_closure'
atp_require_control trust_scope_isolation.rs 'fn an_honest_local_object_is_reused_rather_than_retransferred'

# Verifier independence: the campaign drives the published surface only.
atp_reaches_into_src=''
if grep -rqE '(include!|path *= *"[^"]*atp-git/src)' "$ATP_TESTS"; then
  atp_reaches_into_src='yes'
fi

# Pure bash plus coreutils, per FG-000A-PORT-019 -- no jq, python, perl or awk,
# and no bc either: nothing else in suites/ depends on it, so this counts in the
# shell rather than introducing a tool the lane did not already require.
atp_tests=0
for atp_file in "$ATP_TESTS"/*.rs; do
  atp_in_file=$(grep -c '^#\[test\]' "$atp_file" || true)
  atp_tests=$((atp_tests + atp_in_file))
done

fge_step campaign-shape "campaign: $atp_tests integration tests across 5 targets"

fge_phase action

fge_run atp-fallback-reasons \
  cargo test --locked -p fgit-atp-git --test fallback_reasons || true
atp_fallback_exit=$FGE_LAST_EXIT

fge_run atp-payload-integrity \
  cargo test --locked -p fgit-atp-git --test payload_integrity || true
atp_payload_exit=$FGE_LAST_EXIT

fge_run atp-summary-poisoning \
  cargo test --locked -p fgit-atp-git --test summary_poisoning || true
atp_summary_exit=$FGE_LAST_EXIT

fge_run atp-abandonment-visibility \
  cargo test --locked -p fgit-atp-git --test abandonment_visibility || true
atp_abandon_exit=$FGE_LAST_EXIT

fge_run atp-trust-scope-isolation \
  cargo test --locked -p fgit-atp-git --test trust_scope_isolation || true
atp_trust_exit=$FGE_LAST_EXIT

# The crate's own unit tests must keep passing beside the campaign: a campaign
# that breaks the crate it verifies is not verification.
fge_run atp-crate-unit-tests \
  cargo test --locked -p fgit-atp-git --lib || true
atp_unit_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-022B-E2E-010 0 "$atp_fallback_exit" \
  'every FullFallbackReason is produced by the exact condition mapped to it, the ordered chain reports the FIRST failing check, and a fully capable pair does NOT fall back'
fge_assert_exit FG-022B-E2E-011 0 "$atp_payload_exit" \
  'corrupted, truncated and duplicated payloads are refused by name and leave quarantine EMPTY; reordering changes nothing; an omission asks for repair rather than staging a partial closure'
fge_assert_exit FG-022B-E2E-012 0 "$atp_summary_exit" \
  'a summary with every bit set removes every object from the plan, is never reported AlreadyInSync, marks requires_exact_closure_repair, and costs one round trip rather than a wrong end state'
fge_assert_exit FG-022B-E2E-013 0 "$atp_abandon_exit" \
  'abandoning before staging leaves quarantine empty; abandoning mid-staging leaves exactly what was accepted and yields no completion receipt'
fge_assert_exit FG-022B-E2E-014 0 "$atp_trust_exit" \
  'a genuine object reached under the WRONG KEY is refused with ExistingObjectMismatch and stages nothing, while an honest local object is reused rather than re-transferred'
fge_assert_exit FG-022B-E2E-015 0 "$atp_unit_exit" \
  'the crate own unit tests still pass alongside the campaign'

fge_assert_eq FG-022B-E2E-016 '' "$atp_missing_controls" \
  'every campaign file still carries its permitted case; a refusal suite without one cannot tell "refused correctly" from "inert"'
fge_assert_eq FG-022B-E2E-017 '' "$atp_reaches_into_src" \
  'the campaign drives the published surface and never reaches into fgit-atp-git/src'

# ---------------------------------------------------------- the support matrix
#
# FG-022b's acceptance has one line this lane cannot satisfy, and it is recorded
# as a TYPED UNSUPPORTED assertion rather than a prose note, so the terminal
# status is non-pass. A campaign with a hole in it must not look like one
# without.

fge_unsupported FG-022B-E2E-020 \
  'cache trust-scope isolation, literally: THERE IS NO CACHE. Measured -- zero occurrences of "cache" in fgit-atp-git/src, and trust.?scope / trust.?domain / cross.?trust match nothing in any crate src across the workspace. FG-022a, the implementation bead, is closed and never had a cache in its SCOPE (capability records, inventory summaries, plan selector, reconstruction pipeline). So the epic FG-022 names "trust-scoped cache keys" that neither child was asked to build, while this evidence child is asked to probe them. NOT papered over with a fixture: an invented cache would convert a real planning gap into a false green. The PROPERTY behind the words -- an object held locally is never served on the strength of its key alone -- IS covered by FG-022B-E2E-014. What is uncovered is key derivation, because there are no keys. Routed to GoldLotus with three dispositions; delete this cell when one is chosen'
