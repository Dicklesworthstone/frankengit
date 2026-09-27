#!/usr/bin/env bash
# e2e: scripts/e2e/pull_request_smoke.py against a prebuilt fg.
# Fresh-process fg pr lifecycle/merge campaign; self-test checks fixtures/checkers only.
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
fge_smoke_campaign pull_request_smoke SMOKE-PULL-REQUEST 'pull_request_smoke completes its campaign against the product binary'
