#!/usr/bin/env bash
# e2e: scripts/e2e/source_browse_smoke.py against a prebuilt fg.
# Fresh-process exact source browsing and read-to-patch integration. No Git subprocess.
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
fge_smoke_campaign source_browse_smoke SMOKE-SOURCE-BROWSE 'source_browse_smoke completes its campaign against the product binary'
