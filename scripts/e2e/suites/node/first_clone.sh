#!/usr/bin/env bash
# e2e: FG-028b FIRST CLONE -- a real `git clone` from a live fgit-node, receipted
# here (bead frankengit-ipo5, owned by BoldMoose).
#
# WHY THIS FILE EXISTS BEFORE THE CAPABILITY DOES. ipo5 records that the live
# git-daemon clone is expected-red. But a suite that does not exist is not red,
# it is ABSENT: the board shows nothing for FIRST CLONE, and a reader cannot
# tell "blocked on a named enabler" from "nobody has looked at this". That is
# the frankengit-osqi defect in another costume -- there, 30 assertion ids read
# as coverage for FG-001 while the file lived outside suites/ and never ran.
#
# So this is discovered like every other suite and REFUSES BY DEFAULT, naming
# the enabler it waits on. AGENTS.md §3.1: unsupported behaviour returns a typed
# refusal, it never falls back secretly. Silence was the alternative and silence
# is what is being fixed.
#
# SCOPE CLAIM, deliberately narrow: this file is harness plumbing only
# (SnowyFortress, bead frankengit-o40p, at BoldMoose's request). It asserts
# NOTHING about clone behaviour, starts no node, and contains no fgit-node code.
# The live body and every claim it will make belong to BoldMoose.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init first-clone

# ---------------------------------------------------------------------------
# THE REPLACEMENT SEAM.
#
# This is a CAPABILITY declaration, not a policy switch. It names the bead whose
# delivery unblocks the live body below. Deliberately NOT an environment gate:
# the osqi probe is env-gated because running it is FORBIDDEN (verify.sh is the
# orchestrator's lane), whereas this body is merely IMPOSSIBLE. Conflating "may
# not" with "cannot" would misreport why the cell is unsupported.
#
# Verified at this tree rather than copied from the request that prompted it:
#   frankengit-u8tx   CLOSED   closure reader + closure-to-pack materializer
#   frankengit-600m   BLOCKED  durable admission materialization
# The request named both; u8tx has since closed, so only 600m is outstanding.
#
# WHEN 600m LANDS: clear FIRST_CLONE_BLOCKED_ON, write the body under the marker
# below, and delete this block. One constant is the whole seam.
#
# DELETION CONDITION: goes when the live clone body runs. If this file still
# refuses once every named enabler is closed, the constant is stale and that is
# itself the defect -- a skeleton that outlives its blocker is the absence it
# replaced, wearing a cell id.
# ---------------------------------------------------------------------------
FIRST_CLONE_BLOCKED_ON='frankengit-600m'

if [ -n "$FIRST_CLONE_BLOCKED_ON" ]; then
  fge_phase action
  fge_unsupported FG-028B-CLONE-000 \
    "no live clone attempted: FG-028b needs durable admission materialization (${FIRST_CLONE_BLOCKED_ON}), which is not delivered; frankengit-u8tx (closure reader) IS closed, so this cell names the one enabler still outstanding rather than the pair ipo5 was filed against"
  exit 0
fi

# ---------------------------------------------------------------------------
# LIVE BODY -- BoldMoose owns everything below this marker.
#
# Expected shape per ipo5: start the node, run a real `git clone` against it,
# byte-compare the cloned tree, and exercise the mid-clone reap case. None of
# that is written here, because writing a clone assertion against capability
# that does not exist would be a fixture presented as live proof (§16.3).
# ---------------------------------------------------------------------------
fge_fail FG-028B-CLONE-001 \
  'the live clone body has not been written; clearing FIRST_CLONE_BLOCKED_ON without writing it is a false green'
