#!/usr/bin/env bash
# e2e: scripts/e2e/initial_commit_smoke.py against a prebuilt fg.
# Fresh fg init -> exact root patch -> reviewed publish -> verified bytes; no Git subprocess.
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
fge_smoke_campaign initial_commit_smoke SMOKE-INITIAL-COMMIT 'initial_commit_smoke completes its campaign against the product binary'
