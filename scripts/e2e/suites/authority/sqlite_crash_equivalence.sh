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
  'publish_decisions_async' \
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
  cargo test --locked -p fgit-authority-fsqlite --test crash_equivalence || true
sq_campaign_exit=$FGE_LAST_EXIT

# The profile's own evidence must keep passing alongside the new campaign: a
# campaign that breaks the crate it verifies is not verification.
fge_run sqlite-engine-conformance \
  cargo test --locked -p fgit-authority-fsqlite --test engine_conformance || true
sq_conformance_exit=$FGE_LAST_EXIT

fge_run sqlite-lifecycle \
  cargo test --locked -p fgit-authority-fsqlite --test lifecycle || true
sq_lifecycle_exit=$FGE_LAST_EXIT

# The retry law derived from the specification rather than from the code. This
# is the independent counterpart to the crate's own retry_law.rs, which is
# implementer evidence and cannot catch a misreading of the clause.
fge_run sqlite-retry-law-independent \
  cargo test --locked -p fgit-authority-fsqlite --test retry_law_independent || true
sq_retry_exit=$FGE_LAST_EXIT

# The concurrency envelope derived from §3.5 rather than from the constant the
# crate's own tests assert against. An off-by-one in
# MAX_ADMITTED_AUTOCOMMIT_WRITERS is invisible to a test that reads it.
fge_run sqlite-envelope-law-independent \
  cargo test --locked -p fgit-authority-fsqlite --test envelope_law_independent || true
sq_envelope_exit=$FGE_LAST_EXIT

# FG-005c: the checkpoint-under-load cell. NPC 5.2 names checkpoint a required
# kill/restart boundary and calls an unexercised matrix cell a terminal
# non-pass, so this cell cannot be closed by a typed non-claim however careful.
# Whether it was even producible was answered wrongly three times by reading
# source before PRAGMA journal_mode settled it; see frankengit-g6s8.
fge_run sqlite-checkpoint-under-load \
  cargo test --locked -p fgit-authority-fsqlite --test checkpoint_under_load || true
sq_checkpoint_exit=$FGE_LAST_EXIT

# The cancellation cells that ARE drivable. The reason this cell carried as
# unsupported ("no drain/finalize surface a test can drive") was derived by
# scanning fgit-authority-fsqlite/src, which indeed never polls cancellation.
# The poll is one layer down: fsqlite's preflight_async_call runs on all
# thirteen async entry points and refuses a cancelled context before dispatch.
# Fifth reason on this bead to fall to a measurement after being derived from
# reading a single layer.
fge_run sqlite-cancellation-matrix \
  cargo test --locked -p fgit-authority-fsqlite --test cancellation_matrix || true
sq_cancellation_exit=$FGE_LAST_EXIT

# AF-01..AF-08 against the real backend. This cell was unsupported on the
# reasoning that run_fault_conformance is bound S: FaultableAuthorityStore and
# MemoryAuthorityStore is its only impl -- both true -- and therefore that the
# cells were "unprovable for this backend by anyone", which does not follow.
# Nothing requires the implementor to BE the backend: a wrapper that counts
# operations, consults the plan and delegates to a real store satisfies the
# trait, and crash_equivalence.rs already carried the sync/async bridge.
fge_run sqlite-fault-conformance \
  cargo test --locked -p fgit-authority-fsqlite --test fault_conformance || true
sq_fault_exit=$FGE_LAST_EXIT

# The measurement any frankengit-w1ik fix must be designed around: fsqlite returns
# FrankenError::Interrupt for BOTH a pre-dispatch and an after-dispatch cancel,
# so the store cannot narrow cancellation to a refusal and must answer
# Ambiguous. Run in the lane rather than left as a one-off, because the whole
# mapping becomes wrong the day that stops being true -- and the probe asserts
# the observation, so it fails instead of going quietly stale.
fge_run sqlite-cancellation-error-probe \
  cargo test --locked -p fgit-authority-fsqlite --test cancellation_error_probe || true
sq_probe_exit=$FGE_LAST_EXIT

# The declared resource ceilings, differentially against the reference. Only
# the presence case runs green: the two engine cells carry #[ignore] naming
# frankengit-nv0a, because the store publishes four ceilings through limits()
# and enforces one.
fge_run sqlite-resource-ceilings \
  cargo test --locked -p fgit-authority-fsqlite --test resource_ceilings || true
sq_ceilings_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-005B-E2E-010 0 "$sq_campaign_exit" \
  'the kill/reopen and equivalence campaign passes'
fge_assert_exit FG-005B-E2E-011 0 "$sq_conformance_exit" \
  'the FG-004 conformance run still passes alongside it'
fge_assert_exit FG-005B-E2E-012 0 "$sq_lifecycle_exit" \
  'the lifecycle evidence still passes alongside it'
fge_assert_exit FG-005B-E2E-018 0 "$sq_retry_exit" \
  'the spec-derived retry law agrees with the implementation'
fge_assert_exit FG-005C-E2E-001 0 "$sq_checkpoint_exit" \
  'the checkpoint-under-load kill/restart boundary is exercised, not documented away'
fge_assert_exit FG-005B-E2E-019 0 "$sq_envelope_exit" \
  'the spec-derived concurrency envelope agrees with the implementation'
fge_assert_exit FG-005B-E2E-022 0 "$sq_cancellation_exit" \
  'cancellation before dispatch refuses AND leaves no effect, and is never retried'
fge_assert_exit FG-005B-E2E-020 0 "$sq_fault_exit" \
  'AF-01..AF-08 pass against a real FrankenSQLite database: effects reach real SQL, ambiguity resolves by real exact-key read, and lost-request is distinguished from lost-response by the effect log. Scope: faults are injected at the STORE BOUNDARY, so faults originating inside SQLite are not exercised'
fge_assert_exit FG-005B-E2E-026 0 "$sq_ceilings_exit" \
  'the reference genuinely refuses past its declared ceiling -- the presence case the engine cells below are measured against'
fge_assert_exit FG-005B-E2E-025 0 "$sq_probe_exit" \
  'the premise any frankengit-w1ik fix must rest on: fsqlite returns Interrupt for BOTH a pre-dispatch and an after-dispatch cancel, so the store cannot narrow cancellation to a refusal and must answer Ambiguous. If this cell fails the two points have become separable and the mapping should be re-derived, not patched'

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
if [ "$sq_tests" -lt 19 ]; then
  fge_fail FG-005B-E2E-017 \
    "only $sq_tests tests in the campaign; the dispatch names more scenarios than that"
fi

# ---------------------------------------------------------- the support matrix
#
# FG-005b's acceptance says the report publishes the support matrix and that
# any unproved cell is "unsupported/non-pass and is admission-capped in
# production". Two cells are unproved, so both are recorded as TYPED
# UNSUPPORTED assertions rather than as prose notes. They are unproved for
# DIFFERENT reasons and the cells say which: E2E-021 is absent capability,
# E2E-027 is present capability blocked by a defect (frankengit-nv0a).
#
# That makes this lane's terminal status non-pass, and it should: the harness
# treats an unsupported assertion as non-pass precisely so a partially proved
# profile cannot report a clean green. An earlier version of this file wrote
# the same facts as an `fge_step` and the lane reported PASS -- true of every
# assertion it ran, and misleading about the profile as a whole. A support
# matrix with holes in it must not look like a support matrix without them.
#
# E2E-021 converts to a pass the moment the named capability exists. It is not
# a defect in the implementation; it is absent capability in the surface
# available to a verifier.
#
# THREE cells used to sit here and no longer do, and they left for three
# different reasons worth keeping straight:
#
#   - cancellation was assumed undrivable and was drivable;
#   - fault injection was assumed unreachable for this backend "by anyone" and
#     was reachable through a wrapper;
#   - E2E-024 is a cell BLOCKED BY A DEFECT rather than by absent capability --
#     the test exists and fails because the store reports non-commit for a
#     cancellation that committed. That is `frankengit-w1ik`. It is still here,
#     and the reason it is still here is an OWNERSHIP decision rather than a
#     technical one: the fix was written and verified, then deliberately
#     reverted so the crate's owner can land it, because this campaign's whole
#     value rests on its author not having implemented the crate. See the
#     reverted commit for the patch.
#
# The first two are why these reasons are re-measured at every pass instead of
# inherited: on this bead the base rate of a wrong impossibility claim has been
# high, and every one was derived by reading a single layer of a stack.
#
# The third is why "unsupported" must stay honest about WHICH kind it is. A
# defect-blocked cell and an absent-capability cell both read as non-pass, but
# one is waiting on a capability and the other on a bug nobody may be fixing.

fge_unsupported FG-005B-E2E-021 \
  'cancellation of a statement the VDBE is ACTIVELY STEPPING, i.e. observing the ENGINE-SIDE cancellation rather than the caller-side one. Not reachable through this store published surface, and the reason is structural rather than a matter of effort. CORRECTED: this cell previously said the store statements are too short to reach a VDBE opcode checkpoint, and stamped that MEASURED. It is false. The guard is opcode_count & (4096-1) == 0 with opcode_count initialised to 0 and incremented AFTER the test, so the checkpoint fires on opcode 0 of EVERY statement however short. Length was never the barrier. The real barrier is preemption: the caller await observes cancellation first and returns, so the VDBE Abort never becomes the caller-visible answer. Measured by FG-005B-E2E-025, which pins an after-dispatch cancel surfacing as Interrupt (caller-side) and not Abort (engine-side). This was the third correction to this cell and the worst of them, because a false mechanism carrying a MEASURED label is exactly what the labelling was introduced to prevent

fge_unsupported FG-005B-E2E-027 \
  'resource/mailbox/connection admission exhaustion is DEFECT-BLOCKED, not unwritten. The tests exist and are correct: resource_ceilings::the_engine_enforces_every_ceiling_it_declares and ::the_engine_enforces_the_head_slot_ceiling_it_declares, both #[ignore] naming frankengit-nv0a. MEASURED: AuthorityLimits declares four ceilings and FsqliteAuthorityStore enforces one -- self.limits.body_bytes at engine.rs:466 is the only limits.-field access in the crate, while MemoryAuthorityStore enforces all four and refuses with CapacityExhausted. The store ACCEPTS and PUBLISHES limits it does not apply, which NPC 3.1 calls a secret fallback. Nothing caught it because the shared FG-004 suite tests body_bytes (ac_16) and has no CapacityExhausted check at all, so covering one member of the family made the other three look covered. Un-ignore both and delete this cell when nv0a lands

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

fge_context covered 'checkpoint under load: EXERCISED by checkpoint_under_load.rs, not documented away. NPC 5.2 names checkpoint a required kill/restart boundary and calls an unexercised matrix cell a terminal non-pass, so a typed non-claim could never have closed it however carefully worded. The drill kills at a boundary with bodies written both before and after it, and requires every one back after reopen. It DRIVES the checkpoint from a second connection rather than waiting on the adaptive threshold, because the earlier probe recorded here measured that automatic checkpointing did not fire at 200 writes / 3MB and that the target is multiplied by 1.5 above 512 frames/sec, so heavier load makes an automatic checkpoint LESS likely. The boundary is witnessed rather than assumed: PRAGMA wal_checkpoint must report a non-empty log with every frame backfilled, and a companion case proves that number tracks this store writes rather than being a constant. Whether the cell was even producible was answered wrongly three times by READING source before PRAGMA journal_mode measured wal; two drafts of the witness were also wrong and were caught by their own absence half rather than by review. See frankengit-g6s8 and NEG-022'
