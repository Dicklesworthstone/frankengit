#!/usr/bin/env bash
# e2e: FG-055 claim-registry admission, generated status, and automatic
# artifact-drift demotion. The fixture is intentionally independent of the
# checkout's claims.tsv so the lane observes both refusal and restoration.
set -euo pipefail

CP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CP_REPO=$(cd "$CP_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CP_REPO/scripts/e2e/lib.sh"

fge_init fg055-claims-pipeline
fge_context bead frankengit-fg055-claims-evidence-eu7
fge_context checker fgit-registry-check
fge_context claim_invariant INV-017

fge_phase setup
CP_WORK=$(fge_tempdir claims-pipeline)
CP_FIXTURE="$CP_WORK/fixture"
mkdir -p "$CP_FIXTURE/registries"
cp "$CP_REPO/registries/claim_classes.tsv" "$CP_FIXTURE/registries/claim_classes.tsv"
printf '%s\n' \
  '# franken-registry-v1' \
  'id	owner	statement	verification	release_blocking	status' \
  'INV-017	claims	claim-status-integrity	fixture	yes	implemented' \
  >"$CP_FIXTURE/registries/invariants.tsv"
printf '%s' 'first evidence body' >"$CP_FIXTURE/receipt.txt"
CP_DIGEST=$(fge_digest_file "$CP_FIXTURE/receipt.txt")

write_claim() {
  local evidence_class=$1
  printf '%s\n' \
    '# franken-registry-v1' \
    'id	claim_class	scope	owner_invariant	required_artifacts	evidence_class	status	source_revision	toolchain	target_profile	assumptions	non_claims	revalidation	fallback_wording' \
    "CLM-001	CLAIM-004	fixture-claim	INV-017	receipt.txt@sha256:$CP_DIGEST	$evidence_class	verified	fixture-source	fixture-toolchain	fixture-target	fixture-assumptions	not-a-proof	on-artifact-change	artifact-drift-demotes" \
    >"$CP_FIXTURE/registries/claims.tsv"
}

run_claims_gate() {
  local label=$1
  fge_capture "claims-$label" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$CP_REPO/tools/registry-check/Cargo.toml" -- \
    claims --root "$CP_FIXTURE" || true
  CP_GATE_EXIT=$FGE_LAST_EXIT
  CP_GATE_OUTPUT="$FGE_LAST_STDOUT"$'\n'"$FGE_LAST_STDERR"
}

fge_assert_file FG-055-E2E-001 "$CP_REPO/tools/registry-check/src/claims.rs" \
  'claims registry evaluator is present'

fge_phase action
write_claim CLAIM-006
run_claims_gate weak-evidence
CP_WEAK_EXIT=$CP_GATE_EXIT
CP_WEAK_OUTPUT=$CP_GATE_OUTPUT

write_claim CLAIM-004
fge_capture claims-status \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
  --manifest-path "$CP_REPO/tools/registry-check/Cargo.toml" -- \
  claims-status --root "$CP_FIXTURE"
CP_STATUS_OUTPUT=$FGE_LAST_STDOUT
printf '%s' "$CP_STATUS_OUTPUT" >"$CP_FIXTURE/README.md"
run_claims_gate exact-artifact
CP_EXACT_EXIT=$CP_GATE_EXIT

printf '%s\n' \
  '<!-- franken-claims-status:begin -->' \
  'stale human status' \
  '<!-- franken-claims-status:end -->' \
  >"$CP_FIXTURE/README.md"
run_claims_gate stale-readme
CP_STALE_EXIT=$CP_GATE_EXIT
CP_STALE_OUTPUT=$CP_GATE_OUTPUT

printf '%s' "$CP_STATUS_OUTPUT" >"$CP_FIXTURE/README.md"
printf '%s' 'later evidence body' >"$CP_FIXTURE/receipt.txt"
run_claims_gate artifact-drift
CP_DRIFT_EXIT=$CP_GATE_EXIT
CP_DRIFT_OUTPUT=$CP_GATE_OUTPUT

fge_phase assert
fge_assert_ne FG-055-E2E-002 0 "$CP_WEAK_EXIT" \
  'weaker evidence class is refused by the claims gate'
fge_assert_cmd FG-055-E2E-003 \
  'weak-evidence refusal names the forbidden strength upgrade' \
  grep -qF 'weaker than claim class' <<<"$CP_WEAK_OUTPUT"
fge_assert_eq FG-055-E2E-004 0 "$CP_EXACT_EXIT" \
  'exact artifact and admissible evidence produce a checked claim status'
fge_assert_cmd FG-055-E2E-005 \
  'generated status presents the admitted fixture claim' \
  grep -qF '| CLM-001 | CLAIM-004 | verified | fixture-claim |' <<<"$CP_STATUS_OUTPUT"
fge_assert_ne FG-055-E2E-006 0 "$CP_STALE_EXIT" \
  'handwritten README status is rejected as stale'
fge_assert_cmd FG-055-E2E-007 \
  'stale README diagnostic names the repository-owned generator' \
  grep -qF 'README claim-status block is stale' <<<"$CP_STALE_OUTPUT"
fge_assert_ne FG-055-E2E-008 0 "$CP_DRIFT_EXIT" \
  'a changed committed artifact automatically demotes the claim'
fge_assert_cmd FG-055-E2E-009 \
  'artifact demotion names the changed digest' \
  grep -qF 'digest changed' <<<"$CP_DRIFT_OUTPUT"

fge_phase teardown
fge_note 'narrow checker claim only: this lane does not claim evidence-envelope implementation'
