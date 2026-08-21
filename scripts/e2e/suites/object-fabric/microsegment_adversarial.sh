#!/usr/bin/env bash
# FG-020b — independent object-fabric microsegment adversarial corpus.
#
# `scripts/e2e/run_all.sh` discovers scripts beneath `suites/` directly.  This
# is consequently the registered entry for the current harness without a
# second, mutable workflow registry.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg020b-microsegment-adversarial
fge_context bead frankengit-fg020b-microsegment-evidence-664
fge_context evidence_class E1+E4+benchmark
fge_context corpus crates/fgit-object-fabric/tests/microsegment_adversarial.rs
fge_context economics crates/fgit-object-fabric/tests/corpus/microsegment_economics_v1.tsv
fge_context non_claim 'the pack and loose columns are explicit uncompressed/no-delta size and request-count models, not end-to-end performance claims'
fge_context seed "${FGIT_MICROSEGMENT_CORPUS_SEED:-2002}"

fge_phase setup
fge_assert_file FG-020B-E2E-001 \
  "$E2E_ROOT/../../crates/fgit-object-fabric/tests/microsegment_adversarial.rs" \
  'the independent byte-level adversarial corpus is present in the repository'
fge_assert_file FG-020B-E2E-002 \
  "$E2E_ROOT/../../crates/fgit-object-fabric/tests/corpus/microsegment_economics_v1.tsv" \
  'the benchmark-class economics fixture is present in the repository'

fge_phase action
test_exit=0
fge_run FG-020B-E2E-003-run \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  FGIT_MICROSEGMENT_CORPUS_SEED="${FGIT_MICROSEGMENT_CORPUS_SEED:-2002}" \
  cargo test --locked -p fgit-object-fabric --test microsegment_adversarial \
  || test_exit=$?

fge_phase assert
fge_assert_exit FG-020B-E2E-003 0 "$test_exit" \
  'all truncation, record-transplant, namespace, duplicate, determinism, and economics assertions hold'
