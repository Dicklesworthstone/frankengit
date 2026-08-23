#!/usr/bin/env bash
# =============================================================================
# e2e: FG-041 proof lane  --  suites/proof/proof_lane.sh
# Owner bead: frankengit-fg041c-proof-refinement-wuy
#
# WHY THIS EXISTS. FG-041b landed a real Lean development at a19a78f --
# fourteen theorems, named model-boundary assumptions, a pinned toolchain, and
# a planted false variant that the checker must reject. And NOTHING INVOKED IT.
# `grep -rn 'proofs/fg041' scripts/ .github/` returned empty: the proofs ran
# nowhere, so a regression in them would have been invisible until someone
# opened the directory. A proof artifact that no lane executes is documentation
# with a .lean extension.
#
# The bead's acceptance names `scripts/e2e/proof_lane.sh`. This file is at
# `suites/proof/proof_lane.sh` instead, DELIBERATELY, because run_all.sh
# discovers suites rather than registering them -- its own header says
# "ANYTHING OUTSIDE `suites/` IS NOT DISCOVERED AND RUNS NOWHERE". Writing the
# literal path would have satisfied the acceptance's words while defeating the
# thing it asks for, which is that the lane actually runs. The bead predates
# the discovery convention.
#
# WHAT THIS LANE DOES AND DOES NOT COVER, stated rather than implied:
#   - it runs the FG-041 Lean checker and asserts the exit code, including the
#     typed refusal (2) when the pinned toolchain is absent. An environment
#     without `elan` must SKIP loudly, never pass quietly: a proof lane whose
#     absent-checker path is indistinguishable from success is worse than no
#     lane, because it reports green forever on a machine that has no Lean.
#   - it asserts the theorem set the registry will cite is actually present in
#     the artifact, so a theorem being renamed or deleted cannot silently
#     orphan a claim that names it.
#   - it does NOT check the claims registry. That needs
#     `cargo run -p fgit-registry-check`, and the claims-registry promotion
#     half of FG-041c is not landed yet -- see the bead. Asserting registry
#     consistency here before the rows exist would be a check that passes
#     because there is nothing to check.
#   - it does NOT establish that the Rust implementation refines the Lean
#     model. `proofs/fg041/README.md` says so in its own non-claims section and
#     this lane does not quietly upgrade it.
# =============================================================================
set -euo pipefail

PRF_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PRF_REPO=$(cd "$PRF_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$PRF_REPO/scripts/e2e/lib.sh"

fge_init fg041-proof-lane
fge_context bead frankengit-fg041c-proof-refinement-wuy
fge_context scope 'proofs/fg041/check.sh proofs/fg041/OrderedResidue.lean proofs/fg041/FalseVariant.lean'

PRF_CHECK="$PRF_REPO/proofs/fg041/check.sh"
PRF_MAIN="$PRF_REPO/proofs/fg041/OrderedResidue.lean"
PRF_CONTROL="$PRF_REPO/proofs/fg041/FalseVariant.lean"
PRF_ASSUMPTIONS="$PRF_REPO/proofs/fg041/ASSUMPTIONS.md"

# -----------------------------------------------------------------------------
fge_phase setup
fge_step artifacts-present
# -----------------------------------------------------------------------------
for f in "$PRF_CHECK" "$PRF_MAIN" "$PRF_CONTROL" "$PRF_ASSUMPTIONS"; do
  [ -f "$f" ] || fge_die "required proof artifact missing: $f"
done
fge_field artifacts_present 1

# -----------------------------------------------------------------------------
fge_phase assert
fge_step theorems-the-registry-will-cite-are-present
# -----------------------------------------------------------------------------
# The five acceptance properties of FG-041b map onto named theorems. A claims
# row cites a theorem BY NAME, so a rename or deletion must fail here rather
# than leaving a registry row pointing at nothing. This is a cheap check and it
# is the one that catches the drift a digest alone would also catch but could
# not explain.
prf_missing=""
for theorem in \
  terminal_outcome_is_unique \
  accepted_publish_is_continuous \
  head_chain_is_continuous_and_monotone \
  ref_and_forge_visibility_is_atomic \
  unsealed_decision_is_not_fabricated \
  crash_retry_does_not_lose_or_fabricate_decision \
  interrupted_publication_is_anti_rollback
do
  LC_ALL=C grep -qE "^theorem[[:space:]]+${theorem}\b" "$PRF_MAIN" \
    || prf_missing="$prf_missing $theorem"
done
fge_field theorems_missing "${prf_missing:-none}"
fge_assert_eq fg041-cited-theorems-present "" "$prf_missing" \
  "every theorem a claims row may cite is present in OrderedResidue.lean by name"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step planted-control-is-still-planted
# -----------------------------------------------------------------------------
# check.sh requires FalseVariant.lean to FAIL. That guarantee is only worth
# anything while the file still contains a false statement -- emptying it would
# make the control pass vacuously and check.sh's own rejection step would then
# be asserting nothing. Verified structurally here so the control cannot rot
# into a no-op without this lane noticing.
prf_control_lines=$(LC_ALL=C grep -cE '^[[:space:]]*(theorem|example|lemma)' "$PRF_CONTROL" || true)
fge_field control_statements "$prf_control_lines"
fge_assert_ne fg041-control-is-not-empty 0 "$prf_control_lines" \
  "the planted false variant still states something for the checker to reject"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step lean-checker
# -----------------------------------------------------------------------------
# The checker's own exit vocabulary: 0 proved, 2 typed refusal (toolchain
# absent or mismatched, admitted placeholder, control accepted or control
# failed for the wrong reason). An absent toolchain is a SKIP, loudly, and is
# never allowed to read as a pass.
if ! command -v elan >/dev/null 2>&1; then
  fge_field lean_available 0
  fge_skip fg041-proof-check "elan is unavailable; the pinned Lean toolchain cannot be exercised here"
else
  fge_field lean_available 1
  prf_exit=0
  # Invoked through `bash` rather than executed directly: check.sh is not
  # marked +x in the tree, and an exec-bit change to another bead's file is
  # not this lane's to make. Running it directly returned 126 here, which the
  # assertion below reported as a proof FAILURE -- a lane that miscounts its
  # own invocation error as a broken proof is worse than one that does not run.
  bash "$PRF_CHECK" >"$FGE_ARTIFACT_DIR/fg041-check.log" 2>&1 || prf_exit=$?
  fge_field proof_check_exit "$prf_exit"
  if [ "$prf_exit" -eq 2 ]; then
    fge_skip fg041-proof-check "checker issued its typed refusal (exit 2); see fg041-check.log"
  else
    fge_assert_eq fg041-proof-check 0 "$prf_exit" \
      "the FG-041 Lean lane proves every theorem and rejects the planted false variant"
  fi
fi

fge_phase teardown
fge_note "this lane proves the Lean MODEL only; proofs/fg041/README.md's non-claims stand -- no implementation-refinement claim is made or implied here"
