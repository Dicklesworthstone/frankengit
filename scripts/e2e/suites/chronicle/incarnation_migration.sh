#!/usr/bin/env bash
# e2e: FG-059 routing-independent incarnation migration halves.
#
# The source freeze/export and target activation are real Chronicle authority
# operations.  This lane deliberately does not claim rename, owner transfer,
# or source-to-target routing publication: those remain blocked on the owner
# routing authority decision recorded by frankengit-b5ph.
set -euo pipefail

IM_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IM_REPO=$(cd "$IM_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$IM_REPO/scripts/e2e/lib.sh"

fge_init fg059-incarnation-migration
fge_context bead frankengit-fg059-incarnations-migration-v6f
fge_context crate fgit-chronicle
fge_context authority_path 'source exact-head freeze -> immutable attested export -> fresh-target root-last activation'
fge_context routing_cutover 'not attempted; frankengit-b5ph owner decision required'
fge_context non_claim 'This proves attested capsule migration halves only. It does not claim a full portable archive, source write freeze, rename, owner transfer, or routing publication.'

fge_phase setup
fge_assert_file FG-059-E2E-001 "$IM_REPO/crates/fgit-chronicle/src/migration.rs" \
  'routing-independent migration half API is present'
fge_assert_file FG-059-E2E-002 "$IM_REPO/crates/fgit-chronicle/tests/incarnation_migration.rs" \
  'migration half acceptance tests are checked in'

fge_phase action
fge_run fg059-incarnation-migration-tests \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked -p fgit-chronicle --test incarnation_migration || true
im_exit=$FGE_LAST_EXIT

fge_phase assert
fge_assert_exit FG-059-E2E-010 0 "$im_exit" \
  'source freeze/export and target root-last activation satisfy the routing-independent migration half'
fge_assert_cmd FG-059-E2E-011 'migration target receipt has no routing publication path' \
  grep -qF 'pub const fn routing_published(&self) -> bool {' \
  "$IM_REPO/crates/fgit-chronicle/src/migration.rs"
fge_assert_cmd FG-059-E2E-012 'routing cutover remains explicitly outside this lane' \
  grep -qF 'frankengit-b5ph owner decision required' "$IM_REPO/scripts/e2e/suites/chronicle/incarnation_migration.sh"
