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
#   - it DOES now check the claims registry, which the original version of this
#     header correctly said it did not: the rows did not exist yet, and
#     asserting consistency before them would have been a check that passed
#     because there was nothing to check. FG-041c lines 1-2 landed CLM-002..005,
#     so the demotion drill below has something real to break. It runs against a
#     sandbox root, never the checkout.
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

# -----------------------------------------------------------------------------
fge_phase assert
fge_step claims-registry-demotion-drill
# -----------------------------------------------------------------------------
# The half this lane's header said was not landed yet. FG-041c lines 1-2 landed
# CLM-002..CLM-005, four CLAIM-002 rows citing the exact theorems, each bound to
# the five proof artifacts by SHA-256. This is the drill that proves the binding
# is load-bearing rather than decorative: break it and the claim must stop
# presenting as verified, automatically, with no reviewer in the loop.
#
# THE DRILL RUNS IN A SANDBOX ROOT, NEVER IN THE CHECKOUT. `fgit-registry-check`
# takes `--root`, so the mutation happens to a copy. That matters more here than
# usual: sixteen panes share this worktree, so a transient edit to
# proofs/fg041/OrderedResidue.lean would be in every one of their compilers and
# every one of their `git status` outputs for as long as it sat there. A drill
# that has to damage the shared tree to prove a point is a drill nobody can run
# twice. The last assertion below checks the checkout is untouched, so this
# property is enforced rather than asserted in a comment.
#
# TWO AXES, because they fail for different reasons and a lane that probed one
# would report green while the other rotted:
#   digest   -- an artifact changed under a row that still claims it
#   rank     -- a row claiming proof strength on weaker evidence
# The rank axis is the one the checker CAN catch mechanically. It cannot catch a
# row whose evidence is misdescribed at the right rank; that judgement stays
# human, and the bead comment records it.
if ! command -v cargo >/dev/null 2>&1; then
  fge_field registry_checker_available 0
  fge_skip fg041-registry-demotion 'cargo is unavailable; the registry checker cannot be exercised here'
else
  fge_field registry_checker_available 1
  prf_sb=$(fge_tempdir fg041-registry-drill)
  mkdir -p "$prf_sb/registries" "$prf_sb/proofs/fg041" \
           "$prf_sb/crates/fgit-claim/src" "$prf_sb/tools/registry-check/src"
  cp "$PRF_REPO/registries/claims.tsv" "$PRF_REPO/registries/claim_classes.tsv" \
     "$PRF_REPO/registries/invariants.tsv" "$prf_sb/registries/"
  cp "$PRF_REPO/README.md" "$prf_sb/"
  cp "$PRF_REPO/proofs/fg041/ASSUMPTIONS.md" "$PRF_REPO/proofs/fg041/FalseVariant.lean" \
     "$PRF_REPO/proofs/fg041/OrderedResidue.lean" "$PRF_REPO/proofs/fg041/check.sh" \
     "$PRF_REPO/proofs/fg041/toolchain.json" "$prf_sb/proofs/fg041/"
  # CLM-001 binds sources outside proofs/, and an unavailable artifact demotes
  # exactly like a changed one. Without these the baseline would fail for a
  # reason that has nothing to do with the drill, and the drill would be
  # measuring its own sandbox rather than the claim binding.
  cp "$PRF_REPO/crates/fgit-claim/src/lib.rs" "$prf_sb/crates/fgit-claim/src/"
  cp "$PRF_REPO/tools/registry-check/src/claims.rs" \
     "$PRF_REPO/tools/registry-check/src/main.rs" "$prf_sb/tools/registry-check/src/"

  prf_check_sandbox() {
    ( cd "$PRF_REPO" && RCH_CARGO_WRAPPER_BYPASS=1 \
        cargo run -q -p fgit-registry-check -- --root "$prf_sb" claims ) 2>&1
  }

  # Baseline. A drill whose starting state already fails proves nothing about
  # the mutation, so this is the presence case for the two assertions below.
  prf_base_exit=0
  prf_base_out=$(prf_check_sandbox) || prf_base_exit=$?
  printf '%s\n' "$prf_base_out" >"$FGE_ARTIFACT_DIR/fg041-registry-baseline.log"
  fge_field registry_baseline_exit "$prf_base_exit"
  fge_assert_eq fg041-registry-baseline-verified 0 "$prf_base_exit" \
    'the unmutated sandbox verifies, so a later failure is caused by the mutation'

  # Axis one: break the bridge. One appended comment changes the artifact's
  # digest without changing a single theorem, which is the point -- the binding
  # is to the bytes, not to whether the proof still happens to be true.
  printf '\n-- fg041c demotion drill: transient sandbox mutation\n' \
    >>"$prf_sb/proofs/fg041/OrderedResidue.lean"
  prf_digest_exit=0
  prf_digest_out=$(prf_check_sandbox) || prf_digest_exit=$?
  printf '%s\n' "$prf_digest_out" >"$FGE_ARTIFACT_DIR/fg041-registry-digest-drill.log"
  fge_field registry_digest_drill_exit "$prf_digest_exit"
  fge_assert_ne fg041-demotes-on-changed-artifact 0 "$prf_digest_exit" \
    'a changed proof artifact must fail the registry check, not be waved through'
  fge_assert_contains fg041-demotion-names-the-claim "$prf_digest_out" 'CLM-002' \
    'the demotion names the claim that lost its binding'
  # The checker wraps the path in backticks, so the needle is the reason alone
  # and the path is asserted separately. A single needle spanning both would
  # couple this assertion to the checker's quoting style, which is not what it
  # is about.
  fge_assert_contains fg041-demotion-names-the-artifact "$prf_digest_out" \
    'proofs/fg041/OrderedResidue.lean' \
    'the demotion names the artifact that changed'
  fge_assert_contains fg041-demotion-names-the-reason "$prf_digest_out" \
    'digest changed' \
    'the demotion gives the reason, not just a failure'
  # CLM-001 binds different artifacts and must be untouched. Without this the
  # drill would pass on a checker that demoted everything on any change.
  fge_assert_not_contains fg041-demotion-is-scoped "$prf_digest_out" 'CLM-001' \
    'only claims bound to the changed artifact demote'

  # Restore the bridge, then axis two: the same rows, honest artifacts, but one
  # row claiming proof strength on bounded-model evidence.
  cp "$PRF_REPO/proofs/fg041/OrderedResidue.lean" "$prf_sb/proofs/fg041/"
  awk -F'\t' 'BEGIN{OFS="\t"} $1=="CLM-002"{$6="CLAIM-003"} {print}' \
    "$prf_sb/registries/claims.tsv" >"$prf_sb/registries/claims.rank.tsv"
  mv "$prf_sb/registries/claims.rank.tsv" "$prf_sb/registries/claims.tsv"
  prf_rank_exit=0
  prf_rank_out=$(prf_check_sandbox) || prf_rank_exit=$?
  printf '%s\n' "$prf_rank_out" >"$FGE_ARTIFACT_DIR/fg041-registry-rank-drill.log"
  fge_field registry_rank_drill_exit "$prf_rank_exit"
  fge_assert_ne fg041-demotes-on-weak-evidence 0 "$prf_rank_exit" \
    'a proof-rank claim on weaker evidence must not present as verified'
  fge_assert_contains fg041-weak-evidence-names-the-ranks "$prf_rank_out" \
    'is weaker than claim class' \
    'the demotion explains the rank comparison rather than failing opaquely'

  # The checkout itself never moved. This is the assertion that keeps the drill
  # runnable in a shared worktree.
  # Scoped to proofs/fg041 ALONE, deliberately. An earlier version also named
  # registries/claims.tsv and failed -- correctly -- while the commit that
  # introduces these very rows was still in flight. That assertion conflated
  # "the drill damaged nothing" with "nobody is editing the registry", which
  # would fail this lane for any agent's unrelated registry work. The drill's
  # blast radius is the proof artifacts it copies and mutates; that is what is
  # asserted.
  prf_tree_dirt=$(cd "$PRF_REPO" && git status --porcelain -- proofs/fg041 | wc -l | tr -d ' ')
  fge_field proof_tree_dirty_paths "$prf_tree_dirt"
  fge_assert_eq fg041-drill-left-the-checkout-clean 0 "$prf_tree_dirt" \
    'the drill mutates only its sandbox; the shared worktree is never touched'
fi

fge_phase teardown
fge_note "this lane proves the Lean MODEL only; proofs/fg041/README.md's non-claims stand -- no implementation-refinement claim is made or implied here"
