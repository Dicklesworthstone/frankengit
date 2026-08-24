#!/usr/bin/env bash
# e2e: FG-059 creation-attempt lost request/response/crash recovery matrix.
set -euo pipefail

CA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CA_REPO=$(cd "$CA_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CA_REPO/scripts/e2e/lib.sh"

fge_init fg059-creation-attempt-faults
fge_context bead frankengit-fg059-incarnations-migration-v6f
fge_context crate fgit-authority
fge_context fault_matrix 'put lost response after effect; crash after effect then restart; lost request before effect'
fge_context non_claim 'This exercises the canonical immutable creation-attempt record. Node/CLI process wiring remains a separate caller boundary and must reuse this same record, never derive a replacement key.'

fge_phase setup
fge_assert_file FG-059-E2E-030 "$CA_REPO/crates/fgit-authority/tests/creation_attempt_faults.rs" \
  'the real faultable-authority creation recovery matrix is checked in'

fge_phase action
fge_run fg059-creation-attempt-faults \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo test --locked -p fgit-authority --test creation_attempt_faults || true
ca_exit=$FGE_LAST_EXIT

fge_phase assert
fge_assert_exit FG-059-E2E-031 0 "$ca_exit" \
  'loss after put recovers the first mint, while loss before put creates only on retry'
fge_assert_cmd FG-059-E2E-032 'post-effect crash is explicitly covered' \
  grep -qF 'FaultPosition::AfterEffect' "$CA_REPO/crates/fgit-authority/tests/creation_attempt_faults.rs"
