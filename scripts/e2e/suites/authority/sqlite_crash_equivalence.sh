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
  'fn kill' \
  'std::env::temp_dir'; do
  if ! grep -qF "$sq_needle" "$SQ_CAMPAIGN"; then
    sq_missing="$sq_missing $sq_needle"
  fi
done

# A campaign that drifted back to ":memory:" cannot reopen anything, so the
# whole restart claim would evaporate while every assertion still passed.
sq_in_memory=''
if grep -qF '":memory:"' "$SQ_CAMPAIGN"; then
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

if [ "$sq_kills" -lt 9 ]; then
  fge_fail FG-005B-E2E-016 \
    "only $sq_kills kill/reopen sites; the crash matrix requires at least nine"
fi
if [ "$sq_tests" -lt 15 ]; then
  fge_fail FG-005B-E2E-017 \
    "only $sq_tests tests in the campaign; the dispatch names more scenarios than that"
fi

# The honest limit of this lane, recorded rather than left for a reader to
# infer from a green run: the injected-fault half of FG-005b is ABSENT, not
# passing. run_fault_conformance is bound S: FaultableAuthorityStore and
# MemoryAuthorityStore is the only implementation in the workspace, so
# ambiguity, duplication and lost-request-versus-lost-response are unproved for
# this backend until the profile grows an injection point.
fge_step non-claim \
  'AF-01..AF-08 are not run against this backend: FsqliteAuthorityStore does not implement FaultableAuthorityStore'
