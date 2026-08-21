#!/usr/bin/env bash
# e2e: FG-067 benchmark evidence harness records A/A controls and never lets a
# missing correctness oracle turn into a speedup claim.
#
# The bead names `scripts/e2e/benchmark_harness.sh`; `run_all.sh` deliberately
# discovers executable scripts under `suites/`, so this capability is
# registered as `suites-benchmark-benchmark_harness` without adding a brittle
# hand-maintained list to the runner.
set -euo pipefail

BH_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BH_REPO=$(cd "$BH_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$BH_REPO/scripts/e2e/lib.sh"

fge_init fg067-benchmark-harness
fge_context bead frankengit-fg067-benchmark-harness-fvut
fge_context crate fgit-benchmark
fge_context claim_class benchmark_evidence_harness_self_test

benchmark_metrics_present() {
  local artifact=$1 field
  for field in \
    '"latency_ns"' \
    '"cpu_ns"' \
    '"memory_bytes"' \
    '"object_requests"' \
    '"egress_bytes"' \
    '"storage"' \
    '"amplification_ppm"' \
    '"decisions_per_cas_ppm"'; do
    grep -qF "$field" "$artifact" || return 1
  done
}

benchmark_has_an_oracle_for_every_sample() {
  local artifact=$1
  [ "$(grep -cF '"oracle"' "$artifact")" -eq 9 ]
}

fge_phase setup
artifact_dir=$(fge_tempdir benchmark-harness)
fge_context artifact_directory "$artifact_dir"

fge_assert_file FG-067-E2E-001 "$BH_REPO/crates/fgit-benchmark/src/lib.rs" \
  'the benchmark evidence library is present'
fge_assert_file FG-067-E2E-002 "$BH_REPO/crates/fgit-benchmark/src/main.rs" \
  'the benchmark harness self-test driver is present'

fge_phase action
fge_run benchmark-harness-self-test \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo run -p fgit-benchmark -- self-test --out "$artifact_dir" || true

fge_phase assert
fge_assert_exit FG-067-E2E-003 0 "$FGE_LAST_EXIT" \
  'known-cost workload and its oracle complete successfully'
fge_assert_file FG-067-E2E-004 "$artifact_dir/benchmark.ndjson" \
  'runner writes its pinned evidence artifact'
fge_assert_file FG-067-E2E-005 "$artifact_dir/replay-and-rollback.txt" \
  'runner writes replay and rollback instructions'
fge_assert_file FG-067-E2E-006 "$artifact_dir/negative-evidence.ndjson" \
  'non-speedup self-test automatically writes negative evidence'
fge_assert_cmd FG-067-E2E-007 \
  'artifact pins the benchmark schema' \
  grep -qF '"schema":"frankengit.benchmark.evidence.v1"' "$artifact_dir/benchmark.ndjson"
fge_assert_cmd FG-067-E2E-008 \
  'artifact records the A/A noise control before an A/B claim can be admitted' \
  grep -qF '"aa_noise"' "$artifact_dir/benchmark.ndjson"
fge_assert_cmd FG-067-E2E-009 \
  'artifact contains latency, request, egress, storage, and CAS metric families' \
  benchmark_metrics_present "$artifact_dir/benchmark.ndjson"
fge_assert_cmd FG-067-E2E-010 \
  'artifact records a correctness receipt for every measured sample' \
  benchmark_has_an_oracle_for_every_sample "$artifact_dir/benchmark.ndjson"
fge_assert_cmd FG-067-E2E-011 \
  'negative evidence names the rejected speedup claim' \
  grep -qF '"disproven_speedup"' "$artifact_dir/negative-evidence.ndjson"
