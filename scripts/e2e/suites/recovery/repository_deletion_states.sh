#!/usr/bin/env bash
# e2e: FG-059's distinct repository deletion claims and stale-incarnation guard.
set -euo pipefail

RD_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RD_REPO=$(cd "$RD_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$RD_REPO/scripts/e2e/lib.sh"

fge_init fg059-repository-deletion-states
fge_context bead frankengit-fg059-incarnations-migration-v6f
fge_context crate fgit-repair
fge_context state_model 'hidden -> tombstoned grace -> physical deletion authorized -> deleted from hot placements -> recovery material expired -> cryptographically erased'
fge_context non_claim 'This lane proves typed disclosure and monotonic transitions. It does not establish deletion from every replica, archive, caller copy, or physical medium.'

fge_phase setup
fge_assert_file FG-059-E2E-020 "$RD_REPO/crates/fgit-repair/src/repository_deletion.rs" \
  'the typed six-state repository deletion API is present'
fge_assert_file FG-059-E2E-021 "$RD_REPO/crates/fgit-repair/tests/repository_deletion.rs" \
  'the deletion-state and stale-token corpus is checked in'

fge_phase action
fge_run fg059-repository-deletion-tests \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked -p fgit-repair --test repository_deletion || true
rd_exit=$FGE_LAST_EXIT

fge_phase assert
fge_assert_exit FG-059-E2E-022 0 "$rd_exit" \
  'all six disclosure states, skipped-state refusals, and the stale/current incarnation pair are covered'
fge_assert_cmd FG-059-E2E-023 'the exact six state vocabulary remains explicit' \
  grep -qF 'CryptographicallyErased' "$RD_REPO/crates/fgit-repair/src/repository_deletion.rs"
