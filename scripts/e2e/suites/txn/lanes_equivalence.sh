#!/usr/bin/env bash
# e2e: lane/combiner equivalence and the section 38.4 proof contract.
#
# FG-014b. The bead names `scripts/e2e/lanes_equivalence.sh`; discovery is by
# directory under `scripts/e2e/suites`, so this registers as
# `suites-txn-lanes_equivalence` with no edit to run_all.sh.
#
# Two halves, and the second is worthless without the first:
#
#   1. equivalence — the combiner's published output must be a function of the
#      capsule SET, not of the order they arrived in, across a counted schedule
#      space including CAS-loss storms and cancellation mid-combine;
#   2. economics — decisions per authority CAS, with an A/A control and the
#      countermetric that stops the headline standing alone.
#
# A performance comparison between two workloads that published different
# things is void, which is why the equivalence obligation is asserted inside
# the benchmark before any metric is read, and why this suite runs the
# equivalence binary first.
set -euo pipefail

LE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LE_REPO=$(cd "$LE_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$LE_REPO/scripts/e2e/lib.sh"

fge_init fg014b-lanes-equivalence
fge_context bead frankengit-fg014b-lanes-evidence-j1n
fge_context crate fgit-txn
fge_context harness_seed "$(fge_seed)"

# The permutation sweep is seeded and its seeds are derived from the batch size
# and permutation index, so a divergence is replayable from the failure message
# rather than from a captured RNG state.
fge_context sampling "seeded permutations, 6 batch sizes x 12 permutations"

fge_phase setup

fge_assert_file FG-014b-E2E-001 "$LE_REPO/crates/fgit-txn/tests/lanes_equivalence.rs" \
  'the equivalence campaign is checked in'
fge_assert_file FG-014b-E2E-002 "$LE_REPO/crates/fgit-txn/tests/lanes_economics.rs" \
  'the section 38.4 benchmark is checked in'

fge_phase action

fge_run txn-lanes-equivalence \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-txn --test lanes_equivalence || true
le_equivalence_exit=$FGE_LAST_EXIT

fge_run txn-lanes-economics \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-txn --test lanes_economics || true
le_economics_exit=$FGE_LAST_EXIT

# fg014a's determinism suite is the foundation this campaign extends. If it
# regresses, the extension is resting on a broken anchor.
fge_run txn-combiner-determinism \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-txn --test combiner_determinism || true
le_determinism_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-014b-E2E-010 0 "$le_equivalence_exit" \
  'the combiner output is order-independent across the counted schedule space'
fge_assert_exit FG-014b-E2E-011 0 "$le_economics_exit" \
  'the benchmark produces an A/A-controlled artifact and its equivalence oracle agrees'
fge_assert_exit FG-014b-E2E-012 0 "$le_determinism_exit" \
  'the fg014a determinism anchor this campaign extends still holds'

# The sweep must compare the EMITTED order, not a sorted set. Sorting before
# comparing would let a combiner that leaked input order into its output pass a
# permutation sweep, because the sort normalises the very thing under test.
# Asserted against the source because it is a property of the comparison's
# shape, not of one run.
fge_assert_cmd FG-014b-E2E-013 \
  'the equivalence comparison is over emitted order, not a sorted set' \
  grep -qE 'Deliberately not sorted' \
  "$LE_REPO/crates/fgit-txn/tests/lanes_equivalence.rs"

# The countermetric must stay asserted. A benchmark that reported only
# decisions-per-CAS would be selecting the metric that flatters combining,
# since the cost of the change lands entirely in loss granularity.
fge_assert_cmd FG-014b-E2E-014 \
  'the benchmark asserts work-lost-per-lost-CAS alongside the headline metric' \
  grep -qE 'a lost batch CAS discards every decision it carried' \
  "$LE_REPO/crates/fgit-txn/tests/lanes_economics.rs"

# Fixtures must not encode a combination the crypto registry forbids: code
# point 1 is GitIdentityOnly, "never an internal body identity".
le_forbidden=$(grep -c 'DigestAlgorithmId::try_new(1)' \
  "$LE_REPO/crates/fgit-txn/tests/lanes_equivalence.rs" \
  "$LE_REPO/crates/fgit-txn/tests/lanes_economics.rs" 2>/dev/null | grep -c ':[1-9]' || true)
fge_assert_cmd FG-014b-E2E-015 \
  'this campaign builds no internal identity on a git-identity-only algorithm' \
  test "$le_forbidden" = "0"
fge_note 'files using the forbidden code point' "$le_forbidden"
