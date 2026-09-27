#!/usr/bin/env bash
# e2e: scripts/e2e/quarantine_typed_graph_smoke.py against a prebuilt fg.
# Checksum-valid graph fixtures and the actual raw receive-pack boundary.
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
fge_smoke_campaign quarantine_typed_graph_smoke SMOKE-QUARANTINE-TYPED-GRAPH 'quarantine_typed_graph_smoke completes its campaign against the product binary'
