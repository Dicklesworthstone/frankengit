#!/usr/bin/env bash
# e2e: scripts/e2e/source_review_smoke.py against a prebuilt fg.
# Real fg source-review campaign. --self-test validates fixtures/checker only.
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
fge_smoke_campaign source_review_smoke SMOKE-SOURCE-REVIEW 'source_review_smoke completes its campaign against the product binary'
