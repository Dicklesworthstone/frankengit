#!/usr/bin/env bash
# e2e: the actual product binary, native HEAD publication and cold-process recovery.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
# shellcheck source=campaign.bash
. "$E2E_ROOT/suites/smokes/campaign.bash"
fge_init
fge_context bead frankengit-head-symref-canonical-state-iahh
fge_smoke_campaign default_branch_smoke SMOKE-DEFAULT-BRANCH 'canonical HEAD changes and recovery use the product binary'
