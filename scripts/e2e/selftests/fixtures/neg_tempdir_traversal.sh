#!/usr/bin/env bash
# e2e-fixture: PLANTED NEGATIVE -- fge_tempdir must refuse a NAME that escapes
# the artifact work directory (frankengit-e4gj).
#
# Every directory fge_tempdir hands out is recorded in FGE_TEMPDIRS and later
# deleted recursively and forcibly by cleanup. Before the guard existed, NAME
# was interpolated into the path unvalidated, so a caller mistake could aim
# that cleanup outside FGE_ARTIFACT_DIR.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"
fge_init selftest-neg-tempdir-traversal
fge_phase setup

# THE PERMITTED TWIN COMES FIRST, and it is not decoration. The guard has to
# reject traversal WITHOUT rejecting the names the suites actually pass, and
# the widest of those is the license suite's "bad-README.md" -- uppercase and
# a dot. If a future tightening breaks that, this fixture dies here instead,
# with a different message, rather than silently still "passing" because
# something refused.
safe=$(fge_tempdir bad-README.md)

fge_phase assert
fge_assert_dir FG-000A-NEG-TMPDIR-OK "$safe" \
  'a charset-legal NAME with uppercase and a dot is still accepted'

# This call must NOT return. "../escape" resolves out of FGE_ARTIFACT_DIR and
# would still be recorded for recursive cleanup.
fge_tempdir '../escape'

# Reached only if the guard is absent or lets traversal through. Without this
# line an unguarded fge_tempdir would succeed and the fixture would end with
# one passing assertion, which run_all reports as a pass -- the exact
# vacuous-negative shape the xypf beads were about.
fge_fail FG-000A-NEG-TMPDIR-UNREACHED \
  'fge_tempdir returned for a traversal NAME instead of refusing'
