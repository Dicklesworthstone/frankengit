#!/usr/bin/env bash
# FG-052 — derived Git-materializer equivalence lane.
#
# `run_all.sh` discovers executable suites beneath `suites/**`; this location
# is therefore the registration boundary.  It runs the checked-in real-pack,
# real-idx, and strict-native-commit corpora which compare each accelerator
# answer with the corresponding exact computation.  The Rust implementation
# never invokes Git.  This lane does not claim foreign-parser compatibility:
# a pinned-Git consumer lane remains separately required for that claim.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

readonly PACK_ROOT="$E2E_ROOT/../../crates/fgit-pack"

fge_init fg052-materializers-equivalence
fge_context bead frankengit-fg052-materializers-gy4
fge_context evidence_class E1
fge_context materializers 'commit-graph-v1,pack-bitmap-v1,midx-v1,bundle-uri-v1'
fge_context non_claim 'this lane establishes in-repository exact-computation equivalence only; it does not establish pinned-Git parser acceptance, archive/FUSE behaviour, or authority freshness'

fge_phase setup
fge_assert_file FG-052-E2E-001 "$PACK_ROOT/tests/commit_graph.rs" \
  'the strict native-commit graph-walk corpus is checked in'
fge_assert_file FG-052-E2E-002 "$PACK_ROOT/tests/bitmap.rs" \
  'the writer-bound pack reachability corpus is checked in'
fge_assert_file FG-052-E2E-003 "$PACK_ROOT/tests/midx.rs" \
  'the parsed-idx MIDX lookup corpus is checked in'
fge_assert_file FG-052-E2E-004 "$PACK_ROOT/tests/bundle_uri.rs" \
  'the completed-bundle URI materialization corpus is checked in'
fge_assert_cmd FG-052-E2E-005 \
  'the reachability comparison retains an independent exact side' \
  grep -q exact_reaches "$PACK_ROOT/tests/bitmap.rs"
fge_assert_cmd FG-052-E2E-006 \
  'the commit-walk comparison retains an independent exact side' \
  grep -q exact_parents "$PACK_ROOT/tests/commit_graph.rs"

fge_phase action
materializers_exit=0
fge_run FG-052-E2E-010-run \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-pack \
    --test commit_graph \
    --test bitmap \
    --test midx \
    --test bundle_uri \
  || materializers_exit=$?

fge_phase assert
fge_assert_exit FG-052-E2E-010 0 "$materializers_exit" \
  'every materializer corpus agrees with its named exact computation and refusal controls'
