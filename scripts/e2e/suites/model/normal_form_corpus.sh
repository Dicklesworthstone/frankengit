#!/usr/bin/env bash
# e2e: FG-008b -- the net-effect normal-form property corpus and its equivalence
# with an independently written scalar oracle.
#
# The oracle is written by a pane that did not implement the folder, from the
# normative text rather than from the code. That separation is the entire value
# of the bead: an oracle derived from the implementation agrees with it by
# construction, reproduces its bugs, and proves only that the code equals
# itself. So this script asserts the separation MECHANICALLY rather than
# trusting the roster -- it fails if the corpus ever starts importing the
# reference folder it is supposed to be checking.
#
# It also asserts the two things that would silently hollow the campaign out:
# that the comparison is actually wired to the published evaluator seam, and
# that dispositions are compared INCLUDING their absorption reason. Collapsing
# the reason would let both sides agree while the distinction the specification
# asks for went untested -- a mistake this bead made once and retracted.
#
# PLACEMENT NOTE. The bead's acceptance names `scripts/e2e/normal_form_corpus.sh`
# and says to register it in run_all.sh. Both have since been overtaken by the
# harness: run_all.sh discovers scripts by `find` under `scripts/e2e/suites`
# (run_all.sh:97,227), so a script at the literal path would never be
# discovered and never run -- registered in appearance, absent in fact. It is
# therefore placed here, where discovery reaches it. Following the acceptance
# letter would have produced the worst outcome available: a suite that looks
# registered and silently does nothing.
#
# Pure bash plus coreutils, per FG-000A-PORT-019. No awk, jq, python or perl.
set -euo pipefail

NF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
NF_REPO=$(cd "$NF_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$NF_REPO/scripts/e2e/lib.sh"

fge_init fg008b-normal-form-corpus
fge_context bead frankengit-fg008b-normalform-corpus-fmx
fge_context crate fgit-txn
fge_context campaign normal_form_corpus

readonly NF_CORPUS="$NF_REPO/crates/fgit-txn/tests/normal_form_corpus.rs"

fge_phase setup

fge_assert_file FG-008B-E2E-001 "$NF_CORPUS" 'the normal-form corpus is present'
fge_artifact "$NF_CORPUS" normal-form-corpus

# The mechanisms the campaign depends on. If any of these goes, the corpus
# becomes a weaker suite that still passes -- which is the failure mode worth
# guarding, because nothing turns red.
nf_missing=''
for nf_needle in \
  'IntentEvaluator' \
  'evaluate' \
  'oracle_fold' \
  'AbsorptionReason' \
  'FoldOutcome' \
  'the_oracle_and_the_evaluator_agree_on_every_generated_program' \
  'the_corpus_reaches_the_dispositions_it_claims_to_test'
do
  if ! grep -q -- "$nf_needle" "$NF_CORPUS"; then
    nf_missing="$nf_missing $nf_needle"
  fi
done

# Independence: the corpus drives the published evaluator seam and must never
# import the reference folder whose behaviour it is checking. `ReferenceFolder`
# is that implementation; its presence here would mean the oracle had stopped
# being independent.
nf_reaches_into_folder=''
if grep -q -- 'ReferenceFolder' "$NF_CORPUS"; then
  nf_reaches_into_folder='ReferenceFolder'
fi

# The absorption reason must be carried into the comparison rather than
# discarded. A bare `Absorbed` on the oracle side would make the two agree
# without testing identity-vs-inverse-vs-overwrite at all.
nf_collapses_reason=''
if ! grep -q -- 'IntentDisposition::Absorbed(reason)' "$NF_CORPUS"; then
  nf_collapses_reason='absorption reason not carried through translate()'
fi

nf_tests=$(grep -c -- '^#\[test\]' "$NF_CORPUS" || true)
fge_step campaign-shape "corpus: $nf_tests tests"

fge_phase action

# FG008B_CORPUS=campaign selects the acceptance bound (>= 10^5 seeded
# programs). A bare `cargo test` runs a much smaller default so a workspace run
# stays fast; both paths run the SAME properties over the SAME generator, so the
# default is a weaker statement of the identical claim rather than a different
# claim. The corpus refuses to start on an unparseable value rather than
# silently falling back, so this lane cannot report a campaign it did not run.
fge_run normal-form-corpus \
  env FG008B_CORPUS=campaign cargo test --locked -p fgit-txn --test normal_form_corpus
nf_corpus_exit=$FGE_LAST_EXIT

# The crate's existing evidence must keep passing alongside the new corpus: a
# campaign that breaks the crate it verifies is not verification.
fge_run txn-combiner-determinism \
  cargo test --locked -p fgit-txn --test combiner_determinism
nf_combiner_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-008B-E2E-010 0 "$nf_corpus_exit" \
  'the oracle and the evaluator agree across the seeded corpus'
fge_assert_exit FG-008B-E2E-011 0 "$nf_combiner_exit" \
  'the crate existing evidence still passes alongside the corpus'

fge_assert_eq FG-008B-E2E-012 '' "$nf_missing" \
  'every mechanism the comparison depends on is still present in it'
fge_assert_eq FG-008B-E2E-013 '' "$nf_reaches_into_folder" \
  'the corpus drives the published seam and never imports the folder it checks'
fge_assert_eq FG-008B-E2E-014 '' "$nf_collapses_reason" \
  'dispositions are compared including their absorption reason'

fge_phase report

# What this lane does and does not establish, stated here so a green receipt
# cannot be read as more than it is.
fge_step non-claim \
  'establishes: an independently derived oracle and the FG-008a evaluator agree on surviving ref effects and on every intent disposition including its absorption reason, across the seeded corpus at this revision'
fge_step non-claim \
  'does NOT establish: anything about forge streams, retention roots or outbox deliveries -- the oracle carries refs only, so DuplicateIdenticalDelivery is unreached by construction'
fge_step non-claim \
  'the 10^5-program acceptance bound is exercised by THIS lane via FG008B_CORPUS=campaign; a bare cargo test runs a smaller default of the same properties, so a green workspace run is a weaker statement of the same claim and must not be cited as the campaign'
fge_step non-claim \
  'assumption under test: on a precondition failure under MismatchPolicy::StatementError the oracle continues with the remaining intents in that statement. NPC 13 does not say whether the rest of the statement evaluates. A disagreement here is a specification ambiguity, not automatically a defect in either side'
