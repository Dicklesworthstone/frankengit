#!/usr/bin/env bash
# FG-039b: hostile foreign-evidence exchange corpus, driven through fgit-exchange.
#
# run_all.sh discovers suites recursively below scripts/e2e/suites, so this
# exact ruled path registers without a root-level wrapper or a runner edit.
# Every probe invokes the crate's public import/export path; this script never
# reproduces signature, policy, or conflict logic in shell.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly EXCHANGE_CRATE='fgit-exchange'

main() {
  local forged_exit=0 replay_exit=0 domain_exit=0 inflation_exit=0
  local equivocation_exit=0 rotation_exit=0
  local forged_out='' replay_out='' domain_out='' inflation_out=''
  local equivocation_out='' rotation_out=''

  fge_phase setup
  fge_context crate "$EXCHANGE_CRATE"
  fge_context corpus 'forged provenance; evidence replay against changed artifact bytes; trust-domain confusion; signed label inflation; same-origin successor equivocation; key rotation, retirement, revocation, and replacement history'
  fge_context method 'each probe runs one exact fgit-exchange unit test through cargo; shell only captures the real test receipt and asserts its named result'
  fge_context authority_boundary 'foreign evidence remains locally admitted only; this suite neither moves refs nor writes an authority head'
  fge_context non_claim 'bounded adversarial corpus over the implemented exchange API, not a network-federation or durable-storage proof'

  fge_phase action
  fge_capture forged-provenance env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p "$EXCHANGE_CRATE" --lib \
    tests::forged_provenance_with_an_unregistered_key_is_refused -- --exact \
    || forged_exit=$?
  forged_out="$FGE_LAST_STDOUT"

  fge_capture artifact-replay env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p "$EXCHANGE_CRATE" --lib \
    tests::replay_against_newer_artifacts_is_refused_on_commitment_mismatch -- --exact \
    || replay_exit=$?
  replay_out="$FGE_LAST_STDOUT"

  fge_capture trust-domain-confusion env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p "$EXCHANGE_CRATE" --lib \
    tests::trust_domain_confusion_is_refused_even_for_the_same_signing_key -- --exact \
    || domain_exit=$?
  domain_out="$FGE_LAST_STDOUT"

  fge_capture claim-inflation env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p "$EXCHANGE_CRATE" --lib \
    tests::re_signed_claim_upgrade_label_is_refused_against_the_immutable_record -- --exact \
    || inflation_exit=$?
  inflation_out="$FGE_LAST_STDOUT"

  fge_capture equivocation env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p "$EXCHANGE_CRATE" --lib \
    tests::equivocation_retains_both_signed_successors_and_refuses_later_use -- --exact \
    || equivocation_exit=$?
  equivocation_out="$FGE_LAST_STDOUT"

  fge_capture key-rotation env \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p "$EXCHANGE_CRATE" --lib \
    tests::key_rotation_retains_historical_verification_and_refuses_retired_or_revoked_issuance -- --exact \
    || rotation_exit=$?
  rotation_out="$FGE_LAST_STDOUT"

  fge_phase assert
  fge_assert_exit 'FG-039B-E2E-001' 0 "$forged_exit" \
    'forged provenance is refused through the exchange importer'
  fge_assert_contains 'FG-039B-E2E-002' "$forged_out" \
    'tests::forged_provenance_with_an_unregistered_key_is_refused ... ok' \
    'the forged-provenance test actually ran'
  fge_assert_exit 'FG-039B-E2E-003' 0 "$replay_exit" \
    'an old evidence pack cannot replay against newer artifact bytes'
  fge_assert_contains 'FG-039B-E2E-004' "$replay_out" \
    'tests::replay_against_newer_artifacts_is_refused_on_commitment_mismatch ... ok' \
    'the artifact-replay refusal test actually ran'
  fge_assert_exit 'FG-039B-E2E-005' 0 "$domain_exit" \
    'a valid signer under a different trust domain is refused'
  fge_assert_contains 'FG-039B-E2E-006' "$domain_out" \
    'tests::trust_domain_confusion_is_refused_even_for_the_same_signing_key ... ok' \
    'the trust-domain confusion refusal test actually ran'
  fge_assert_exit 'FG-039B-E2E-007' 0 "$inflation_exit" \
    'a signed claim-rank inflation label is refused against the immutable record'
  fge_assert_contains 'FG-039B-E2E-008' "$inflation_out" \
    'tests::re_signed_claim_upgrade_label_is_refused_against_the_immutable_record ... ok' \
    'the claim-inflation refusal test actually ran'
  fge_assert_exit 'FG-039B-E2E-009' 0 "$equivocation_exit" \
    'same-origin equivocation retains both signed successors and refuses later use'
  fge_assert_contains 'FG-039B-E2E-010' "$equivocation_out" \
    'tests::equivocation_retains_both_signed_successors_and_refuses_later_use ... ok' \
    'the equivocation conflict-record test actually ran'
  fge_assert_exit 'FG-039B-E2E-011' 0 "$rotation_exit" \
    'rotation verifies historical evidence while retired and revoked epochs cannot issue'
  fge_assert_contains 'FG-039B-E2E-012' "$rotation_out" \
    'tests::key_rotation_retains_historical_verification_and_refuses_retired_or_revoked_issuance ... ok' \
    'the key-history edge test actually ran'
}

fge_init fg039b-exchange-adversarial
fge_context bead frankengit-fg039b-exchange-adversarial-jlp
fge_context evidence_class adversarial
main
