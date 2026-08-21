#!/usr/bin/env bash
# FG-026b — independent TreeFS path-security and capability corpus.
#
# `scripts/e2e/run_all.sh` discovers scripts beneath `suites/` directly. This
# is therefore the registered suite entry for the current harness; no workflow
# or hand-maintained second registry carries test logic.
#
# Claim boundary: this executes the public-API adversarial corpus. It does not
# claim host-adapter, FUSE, watcher, hardlink/reparse-point, or secret-broker
# enforcement, because no such TreeFS surface exists in this source tree.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg026b-treefs-path-security
fge_context bead frankengit-fg026b-treefs-pathsec-37z
fge_context evidence_class E1+E4
fge_context corpus crates/fgit-treefs/tests/path_security_adversarial.rs
fge_context non_claim 'no host adapter or brokered secret-handle API exists; this corpus detects missing enforcement rather than claiming it'
fge_context seed "${FGIT_TREEFS_PATHSEC_SEED:-2602}"

fge_phase setup
fge_assert_file FG-026B-E2E-001 \
  "$E2E_ROOT/../../crates/fgit-treefs/tests/path_security_adversarial.rs" \
  'the independent adversarial corpus is present in the repository'

fge_phase action
test_exit=0
fge_run FG-026B-E2E-002-run \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  FGIT_TREEFS_PATHSEC_SEED="${FGIT_TREEFS_PATHSEC_SEED:-2602}" \
  cargo test --locked -p fgit-treefs --test path_security_adversarial \
  || test_exit=$?

fge_phase assert
fge_assert_exit FG-026B-E2E-002 0 "$test_exit" \
  'all traversal, symlink-policy, attenuation, root-scope, encoding, and seeded-secret detector assertions hold'
