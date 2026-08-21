#!/usr/bin/env bash
# e2e: FG-005b -- the FrankenSQLite kill/reopen matrix and its equivalence with
# the pure reference backend, run as one revision-bound lane.
#
# The campaign is written by a pane that did not implement the profile. That
# separation is the point of the bead, so this script asserts it mechanically
# rather than trusting the roster: it fails if the campaign ever starts
# reaching into fgit-authority-fsqlite/src.
#
# It also asserts the two things that would silently hollow the campaign out:
# that the stores are opened on a real path rather than ":memory:" (an
# in-memory database cannot be reopened, so a campaign that drifted back to it
# would still pass while proving nothing about restart), and that the
# differential still names both backends.
#
# Pure bash plus coreutils, per FG-000A-PORT-019. No awk, jq, python or perl.
set -euo pipefail

SQ_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SQ_REPO=$(cd "$SQ_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$SQ_REPO/scripts/e2e/lib.sh"

fge_init fg005b-sqlite-crash-equivalence
fge_context bead frankengit-fg005b-sqlite-crash-equiv-gda
fge_context crate fgit-authority-fsqlite
fge_context campaign crash_equivalence

# Builds run locally (AGENTS.md §16.2). Without this the rch wrapper offloads
# the build: the worker RUNS AND PASSES on the remote host, but any artifact it
# writes lands in the remote directory and only the binary returns. The suite
# then fails for a missing artifact while its own worker reports success --
# which misattributes itself to whichever crate was touched last.
#
# Exported rather than prefixed onto each `cargo` invocation deliberately: a
# per-call `env` has to be remembered by whoever adds the NEXT cargo line, and
# this suite has already grown three of them.
export RCH_CARGO_WRAPPER_BYPASS=1

readonly SQ_CAMPAIGN="$SQ_REPO/crates/fgit-authority-fsqlite/tests/crash_equivalence.rs"

fge_phase setup

fge_assert_file FG-005B-E2E-001 "$SQ_CAMPAIGN" 'the crash/equivalence campaign is present'
fge_artifact "$SQ_CAMPAIGN" crash-equivalence-campaign

# The mechanisms the campaign depends on. If it stops opening a real file, or
# stops naming both backends, it becomes a weaker suite that still passes.
sq_missing=''
for sq_needle in \
  'FsqliteAuthorityStore::open' \
  'MemoryAuthorityStore' \
  'scripted_history' \
  'fn contend' \
  'Defect::SecondWinner' \
  'instance_id()' \
  'distinct_bases' \
  'open_descriptors' \
  'fn kill' \
  'std::env::temp_dir'; do
  if ! grep -qF "$sq_needle" "$SQ_CAMPAIGN"; then
    sq_missing="$sq_missing $sq_needle"
  fi
done

# A campaign that drifted back to ":memory:" cannot reopen anything, so the
# whole restart claim would evaporate while every assertion still passed.
# Comment lines are stripped first. The campaign's own module doc EXPLAINS why
# it avoids ":memory:", so a whole-file grep fires on the documentation and
# reports a defect that is not there -- which is what it did on this lane's
# first real run. The question is whether the campaign USES an in-memory
# database, not whether it mentions one.
sq_in_memory=''
if grep -v '^[[:space:]]*//' "$SQ_CAMPAIGN" | grep -qF '":memory:"'; then
  sq_in_memory='yes'
fi

# Verifier independence, asserted rather than trusted.
sq_reaches_into_src=''
if grep -qE '(include!|path *= *"[^"]*fsqlite/src)' "$SQ_CAMPAIGN"; then
  sq_reaches_into_src='yes'
fi

sq_tests=$(grep -c '^#\[test\]' "$SQ_CAMPAIGN" || true)
sq_kills=$(grep -c '\.kill()' "$SQ_CAMPAIGN" || true)

fge_step campaign-shape "campaign: $sq_tests tests, $sq_kills kill/reopen sites"

fge_phase action

# The filesystem-matrix cell only makes its coverage claim under this flag.
# A bare `cargo test --workspace` stays lenient so a single-filesystem host
# reports thin coverage here instead of failing the suite for everyone.
export FG005B_FS_STRICT=1

fge_run sqlite-crash-equivalence \
  cargo test --locked -p fgit-authority-fsqlite --test crash_equivalence
sq_campaign_exit=$FGE_LAST_EXIT

# The profile's own evidence must keep passing alongside the new campaign: a
# campaign that breaks the crate it verifies is not verification.
fge_run sqlite-engine-conformance \
  cargo test --locked -p fgit-authority-fsqlite --test engine_conformance
sq_conformance_exit=$FGE_LAST_EXIT

fge_run sqlite-lifecycle \
  cargo test --locked -p fgit-authority-fsqlite --test lifecycle
sq_lifecycle_exit=$FGE_LAST_EXIT

# The retry law derived from the specification rather than from the code. This
# is the independent counterpart to the crate's own retry_law.rs, which is
# implementer evidence and cannot catch a misreading of the clause.
fge_run sqlite-retry-law-independent \
  cargo test --locked -p fgit-authority-fsqlite --test retry_law_independent
sq_retry_exit=$FGE_LAST_EXIT

# The concurrency envelope derived from §3.5 rather than from the constant the
# crate's own tests assert against. An off-by-one in
# MAX_ADMITTED_AUTOCOMMIT_WRITERS is invisible to a test that reads it.
fge_run sqlite-envelope-law-independent \
  cargo test --locked -p fgit-authority-fsqlite --test envelope_law_independent
sq_envelope_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-005B-E2E-010 0 "$sq_campaign_exit" \
  'the kill/reopen and equivalence campaign passes'
fge_assert_exit FG-005B-E2E-011 0 "$sq_conformance_exit" \
  'the FG-004 conformance run still passes alongside it'
fge_assert_exit FG-005B-E2E-012 0 "$sq_lifecycle_exit" \
  'the lifecycle evidence still passes alongside it'
fge_assert_exit FG-005B-E2E-018 0 "$sq_retry_exit" \
  'the spec-derived retry law agrees with the implementation'
fge_assert_exit FG-005B-E2E-019 0 "$sq_envelope_exit" \
  'the spec-derived concurrency envelope agrees with the implementation'

fge_assert_eq FG-005B-E2E-013 '' "$sq_missing" \
  'every mechanism the campaign depends on is still present in it'
fge_assert_eq FG-005B-E2E-014 '' "$sq_reaches_into_src" \
  'the campaign drives the published surface and never reaches into the profile src'
fge_assert_eq FG-005B-E2E-015 '' "$sq_in_memory" \
  'the campaign opens real files, never ":memory:", or it cannot reopen anything'

if [ "$sq_kills" -lt 12 ]; then
  fge_fail FG-005B-E2E-016 \
    "only $sq_kills kill/reopen sites; the crash matrix requires at least twelve"
fi
if [ "$sq_tests" -lt 17 ]; then
  fge_fail FG-005B-E2E-017 \
    "only $sq_tests tests in the campaign; the dispatch names more scenarios than that"
fi

# ---------------------------------------------------------- the support matrix
#
# FG-005b's acceptance says the report publishes the support matrix and that
# any unproved cell is "unsupported/non-pass and is admission-capped in
# production". These three cells are unproved, so they are recorded as TYPED
# UNSUPPORTED assertions rather than as a prose note.
#
# That makes this lane's terminal status non-pass, and it should: the harness
# treats an unsupported assertion as non-pass precisely so a partially proved
# profile cannot report a clean green. An earlier version of this file wrote
# the same facts as an `fge_step` and the lane reported PASS -- true of every
# assertion it ran, and misleading about the profile as a whole. A support
# matrix with holes in it must not look like a support matrix without them.
#
# Each of these converts to a pass the moment the named API exists. None is a
# defect in the implementation; all three are absent capability in the surface
# available to a verifier.

fge_unsupported FG-005B-E2E-020 \
  'AF-01..AF-08 injected faults: run_fault_conformance is bound S: FaultableAuthorityStore and MemoryAuthorityStore is the only impl in the workspace, so ambiguity, duplication and lost-request-vs-lost-response are unprovable for this backend by anyone'

fge_unsupported FG-005B-E2E-021 \
  'cancellation mid-operation: AsyncAuthorityStore now exists so a future CAN be held in flight, but AGENTS.md 3.2 says dropping a future is not a complete cancellation protocol (request -> drain -> finalize), and no drain/finalize surface is exposed that a test can drive; the phase semantics are modelled in fgit-authority-fsqlite/tests/lifecycle.rs but nothing drives a real cancel against a real in-flight operation'

# The structural PRECONDITION for that cell, which IS checkable today.
#
# async_contract.rs states the rule and explains why it matters: the context
# "must be per-call, never stored on the store. A single context held for the
# store's lifetime breaks per-request budget and cancellation propagation... A
# backend that stashes one context in its struct has satisfied the type and
# lost the property."
#
# That rule lives only in a doc comment, and a doc comment is not a check. This
# does not prove cancellation works -- FG-005B-E2E-021 above still says it is
# unproved -- but it does prove the precondition has not silently regressed,
# which is the difference between "unproved" and "quietly impossible".
#
# Comments are stripped before matching: the struct's own documentation
# discusses contexts, and a whole-block grep would fire on the prose that
# explains the rule. That mistake has been made in this file before.
# Pure bash, per FG-000A-PORT-019: a state flag over the file rather than an
# awk range. The first version of this stanza used awk and would have tripped
# the portability gate -- the same slip that was caught in the codec suite
# earlier today.
sq_stashed_context=0
sq_in_struct=''
while IFS= read -r sq_line; do
  case "$sq_line" in
    'pub struct FsqliteAuthorityStore'*) sq_in_struct='yes'; continue ;;
  esac
  [ -n "$sq_in_struct" ] || continue
  case "$sq_line" in
    '}'*) break ;;
    *//*) continue ;;
    *Cx*|*Context*) sq_stashed_context=$((sq_stashed_context + 1)) ;;
  esac
done < "$SQ_REPO/crates/fgit-authority-fsqlite/src/engine.rs"
fge_assert_eq FG-005B-E2E-023 '0' "$sq_stashed_context" \
  'the store holds no per-store context, so a per-request cancel can still reach an operation'

# A FOURTH cell, found while re-checking whether the other reasons had gone
# stale. It is the sharpest of the four: the operation whose stated purpose is
# surviving a crash is the one this crash matrix cannot reach.
fge_unsupported FG-005B-E2E-024 \
  'publish_head_with_outcomes (the atomic head+outcomes publication closing the section 5.2 window) cannot be driven from any external test: it requires a DuplicateAbsenceWitness, whose constructor is pub(crate) to fgit-authority by deliberate design so the witness cannot become a rubber stamp, and no public producer exists anywhere; fgit-chronicle/tests/capsule_pointer.rs:664 records the same limit'

fge_unsupported FG-005B-E2E-022 \
  'checkpoint under load: FsqliteAuthorityStore publishes nine methods and none is a checkpoint operation, so this cell cannot be driven from outside the crate at all (the count was eight when first recorded; publish_head_with_outcomes has since landed, which is why it is stated as a count that must be re-checked rather than a bare claim)'
