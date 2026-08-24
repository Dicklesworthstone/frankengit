#!/usr/bin/env bash
# e2e: durable DSR release-attempt asset-contract and resume campaign.
#
# This suite invokes fgit-release's real filesystem inventory and append-only
# attempt-journal integration tests.  `fgit-release-attempt` intentionally
# accepts only its wiring probe today: execution requires a caller-owned
# fgit-runner obligation, so this campaign drives the public runner through
# the crate test boundary rather than inventing an ambient release CLI.
#
# The test fixture supplies only terminal target results.  The asset walk,
# byte-digest verification, journal, resume decision, and manifest withholding
# are the production fgit-release implementation.  This does not claim that a
# release was published or that an operating-system target executor exists.
set -euo pipefail

DSR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DSR_REPO=$(cd "$DSR_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$DSR_REPO/scripts/e2e/lib.sh"

fge_init fg035b-dsr-release-contract
fge_context bead frankengit-fg035b-dsr-evidence-c6l
fge_context crate fgit-release
fge_context campaign asset_contract_resume_and_manifest_withholding
fge_context non_claim 'no external target executor, publication, or TOCTOU-resistant filesystem containment claim'

export RCH_CARGO_WRAPPER_BYPASS=1

readonly DSR_TEST="$DSR_REPO/crates/fgit-release/tests/release_attempt_runner.rs"
readonly DSR_SUITE='suites-release-dsr_release_contract'

fge_phase setup

fge_assert_file FG-035B-E2E-001 "$DSR_TEST" \
  'the release attempt runner integration campaign is present'
fge_artifact "$DSR_TEST" release-attempt-runner-source

# The product tests assert the concrete typed variants.  Keep this list in the
# wrapper so deleting a refusal assertion cannot leave an apparently complete
# E2E campaign that merely launches a smaller test module.
dsr_missing_controls=''
for dsr_control in \
  'fn inventory_refusals_each_have_a_permitted_twin' \
  'AttemptRunnerRefusal::AssetTraversal' \
  'AttemptRunnerRefusal::AssetNonRegular' \
  'AttemptRunnerRefusal::AssetUnlisted' \
  'fn duplicate_asset_name_is_refused_and_distinct_names_are_permitted' \
  'AttemptRunnerRefusal::DuplicateTargetAsset' \
  'fn symlinked_asset_is_refused_and_regular_twin_is_permitted' \
  'AttemptRunnerRefusal::AssetSymlink' \
  'fn resume_reuses_only_a_byte_verified_inventory_identity' \
  'AttemptRunnerRefusal::AssetDigestMismatch' \
  'b"substituted bytes"' \
  'ResumeDecision::Reuse' \
  'ResumeDecision::Rerun' \
  'fn cancellation_leaves_resumable_evidence_and_no_manifest_root' \
  'MatrixOutcome::Cancelled' \
  'fn failed_target_provably_withholds_the_manifest_root' \
  'AttemptRunnerRefusal::ManifestWithheld'
do
  if ! grep -qF "$dsr_control" "$DSR_TEST"; then
    dsr_missing_controls="$dsr_missing_controls [$dsr_control]"
  fi
done

fge_phase action

fge_capture dsr-release-discovery "$DSR_REPO/scripts/e2e/run_all.sh" --list || true
dsr_discovery_exit=$FGE_LAST_EXIT
dsr_discovery=$(<"$FGE_LAST_STDOUT_FILE")

# One module covers real files, its append-only journal, exact-byte resume,
# cancellation, and root-last manifest behavior.  The captured test artifact
# makes every named fixture and the cargo result reviewable from the NDJSON
# receipt without reimplementing the release runner in shell.
fge_capture dsr-release-attempt-runner \
  cargo test --locked -p fgit-release --test release_attempt_runner || true
dsr_campaign_exit=$FGE_LAST_EXIT
dsr_campaign_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_phase assert

fge_assert_exit FG-035B-E2E-010 0 "$dsr_discovery_exit" \
  'run_all discovery completes before the release attempt campaign is evaluated'
fge_assert_contains FG-035B-E2E-011 "$dsr_discovery" "$DSR_SUITE" \
  'the contract campaign is discovered from suites/release without a root-level exception'
fge_assert_exit FG-035B-E2E-012 0 "$dsr_campaign_exit" \
  'the real release attempt runner module passes its filesystem and journal fixtures'
fge_assert_eq FG-035B-E2E-013 '' "$dsr_missing_controls" \
  'every required typed refusal, permitted twin, resume, cancellation, and manifest control remains asserted'

for dsr_fixture in \
  inventory_refusals_each_have_a_permitted_twin \
  duplicate_asset_name_is_refused_and_distinct_names_are_permitted \
  symlinked_asset_is_refused_and_regular_twin_is_permitted \
  resume_reuses_only_a_byte_verified_inventory_identity \
  cancellation_leaves_resumable_evidence_and_no_manifest_root \
  failed_target_provably_withholds_the_manifest_root
do
  fge_assert_contains "FG-035B-E2E-020-${dsr_fixture}" "$dsr_campaign_output" "$dsr_fixture" \
    'the captured fgit-release runner result names the required fixture'
done
