#!/usr/bin/env bash
# e2e: the raptorq corruption, malicious-symbol, and reconstruction drills.
#
# FG-024b. The bead names `scripts/e2e/raptorq_drill.sh`; discovery is by
# directory under `scripts/e2e/suites`, so this registers as
# `suites-raptorq-raptorq_drill` with no edit to run_all.sh.
#
# The property these drills exist to defend is narrow and absolute:
# ERASURE CODING MUST NEVER FABRICATE. A decoder given insufficient or hostile
# symbols has to fail closed, because the one outcome worse than losing a
# segment is confidently returning a different one. Every beyond-envelope
# assertion in the campaign is written so that a SUCCESS carrying non-original
# bytes fails loudly, rather than only checking that an error occurred --
# "it errored" and "it did not invent data" are different claims.
set -euo pipefail

RQ_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RQ_REPO=$(cd "$RQ_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$RQ_REPO/scripts/e2e/lib.sh"

fge_init fg024b-raptorq-drill
fge_context bead frankengit-fg024b-raptorq-campaigns-kp1
fge_context crate fgit-raptorq
fge_context harness_seed "$(fge_seed)"

# The hostile corpus is exhaustive over the attacks an EXTERNAL adversary can
# construct, not sampled. It is bounded by what the public API permits: see the
# recorded limit below on ScopedSymbol having no public constructor.
fge_context sampling none

fge_phase setup

fge_assert_file FG-024b-E2E-001 \
  "$RQ_REPO/crates/fgit-raptorq/tests/raptorq_adversarial.rs" \
  'the independent adversarial campaign is checked in'

fge_phase action

fge_run raptorq-adversarial \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-raptorq --test raptorq_adversarial
rq_adversarial_exit=$FGE_LAST_EXIT

# fg024a's own inline tests reach private state this campaign cannot. They are
# the implementer's half of the coverage and must stay green beside it.
fge_run raptorq-implementer-tests \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-raptorq --lib
rq_lib_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-024b-E2E-010 0 "$rq_adversarial_exit" \
  'no hostile or starved symbol set reconstructs to non-original bytes'
fge_assert_exit FG-024b-E2E-011 0 "$rq_lib_exit" \
  'the fg024a implementer tests this campaign complements still hold'

# The anti-fabrication assertions must remain assertions about the BYTES, not
# merely about an error being returned. A campaign rewritten to check only
# `is_err()` would still pass its own suite while no longer testing the property
# the drills exist for, so the shape is pinned against the source.
rq_fabrication=$(grep -c 'FABRICATION' \
  "$RQ_REPO/crates/fgit-raptorq/tests/raptorq_adversarial.rs" || true)
fge_assert_cmd FG-024b-E2E-012 \
  'beyond-envelope cases still assert on the reconstructed bytes, not just on an error' \
  test "$rq_fabrication" -ge 3
fge_note 'anti-fabrication assertions' "$rq_fabrication"

# The reconstruction report must be countersigned by an AUTHORITY key. fgit-crypto
# withholds SignatureCapable from Evidence precisely so that "this evidence
# exists" cannot blur into "this authority asserts it"; a report signed by an
# evidence key would erase that distinction.
fge_assert_cmd FG-024b-E2E-013 \
  'the reconstruction report is countersigned by an authority key, not an evidence key' \
  grep -qE 'SecretKey::<AuthorityAdmin>::derive' \
  "$RQ_REPO/crates/fgit-raptorq/tests/raptorq_adversarial.rs"

# The paper overhead ratio may not be cited without drill evidence, so the
# economics control reports its numbers rather than asserting a threshold. A
# threshold here would be a performance claim; this drill establishes
# durability behaviour.
fge_assert_cmd FG-024b-E2E-014 \
  'the replication control reports overhead rather than asserting a target' \
  grep -qE 'Reported, not asserted as a threshold' \
  "$RQ_REPO/crates/fgit-raptorq/tests/raptorq_adversarial.rs"

# The recorded limit on this bead's independence, asserted so it cannot quietly
# disappear from the record: an external adversary cannot forge a symbol while
# ScopedSymbol has no public constructor. If one is ever added, this fails and
# the bit-level corruption corpus becomes writable -- which is the outcome
# wanted, and it should be noticed rather than sit unnoticed.
rq_ctor=$(grep -cE 'pub (const )?fn (new|from_parts|try_new)[^a-z_]' \
  "$RQ_REPO/crates/fgit-raptorq/src/lib.rs" || true)
fge_assert_cmd FG-024b-E2E-015 \
  'ScopedSymbol still has no public constructor, bounding what this campaign can attack' \
  test "$rq_ctor" = "0"
fge_note 'public constructors exported by fgit-raptorq' "$rq_ctor"
