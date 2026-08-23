#!/usr/bin/env bash
# e2e: FG-028b FIRST CLONE -- a real `git clone` from a live fgit-node, receipted
# here (bead frankengit-ipo5, owned by BoldMoose).
#
# WHY THIS FILE EXISTS BEFORE THE LIVE BODY DOES. ipo5 records that the live
# git-daemon clone is expected-red. But a suite that does not exist is not red,
# it is ABSENT: the board shows nothing for FIRST CLONE, and a reader cannot
# tell "body not delivered" from "nobody has looked at this". That is the
# frankengit-osqi defect in another costume -- there, 30 assertion ids read as
# coverage for FG-001 while the file lived outside suites/ and never ran.
#
# So this is discovered like every other suite and emits an explicit failure
# until the owner supplies real clone behaviour. Silence was the alternative,
# and silence is what is being fixed.
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
# `frankengit-600m` is no longer a capability blocker.  Its close record names
# central verification at cec21b7 (durable admission materialization with the
# visibility, not durable-epoch, non-claim).  Keep the missing live body loud:
# an e2e cell which is discovered but emits no concrete disposition would again
# make FIRST CLONE absent rather than honestly pending its owner work.
# ---------------------------------------------------------------------------

# LIVE BODY -- BoldMoose owns everything below this marker.
#
# Expected shape per ipo5: start the node, run a real `git clone` against it,
# byte-compare the cloned tree, and exercise the mid-clone reap case. None of
# that is written here, because writing clone assertions before the owner has
# implemented the body would present a fixture as live proof (§16.3).
# ---------------------------------------------------------------------------
fge_phase action
fge_fail FG-028B-CLONE-001 \
  'the live clone body has not been written; frankengit-600m closed at cec21b7, but clearing its stale seam is not a clone implementation'
