#!/usr/bin/env bash
# e2e: scripts/e2e/tag_smoke.py against a prebuilt fg.
# Real fg processes: native tags, exact retries, and complete bundle transfer.
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
fge_smoke_campaign tag_smoke SMOKE-TAG 'tag_smoke completes its campaign against the product binary'
