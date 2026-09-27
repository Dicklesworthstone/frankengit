#!/usr/bin/env bash
# e2e: scripts/e2e/issue_smoke.py against a prebuilt fg.
# Fresh-process native issue lifecycle; no upstream Git or mock authority.
# Registered by frankengit-root-doctrine-x2mv.4.18; drives the product binary,
# not a cargo-test wrapper.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
# shellcheck source=campaign.bash
. "$E2E_ROOT/suites/smokes/campaign.bash"
fge_init
fge_context bead frankengit-root-doctrine-x2mv.4.18
fge_smoke_campaign issue_smoke SMOKE-ISSUE 'issue_smoke completes its campaign against the product binary'
