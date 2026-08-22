#!/usr/bin/env bash
# FG-075: trust-scoped ATP transfer-cache campaign.
#
# The runner discovers executable suites below scripts/e2e/suites/; this path
# is therefore the registered execution path without a second manifest.  The
# underlying cache is a bounded local, non-authoritative view.  This suite
# checks its grant boundary, poison quarantine, non-shareable secret lease,
# domain separation, and deterministic per-scope eviction -- not durable cache
# replication, hosted key management, or live network transport.
set -euo pipefail

TC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
TC_REPO=$(cd "$TC_DIR/../../../.." && pwd -P)
# shellcheck source=/dev/null
. "$TC_REPO/scripts/e2e/lib.sh"

readonly TC_TEST="$TC_REPO/crates/fgit-atp-git/tests/trust_scoped_cache.rs"
readonly TC_SOURCE="$TC_REPO/crates/fgit-atp-git/src/cache.rs"

fge_init fg075-atp-trust-cache
fge_context bead frankengit-fg075-atp-trust-cache-5myo
fge_context crate fgit-atp-git
fge_context evidence_class bounded_local_cache_policy_campaign
fge_context non_claim 'This suite does not claim durable cache replication, hosted key management, or live transport behavior; it exercises the bounded local policy engine through its public API.'

export RCH_CARGO_WRAPPER_BYPASS=1

fge_phase setup
fge_assert_file FG-075-E2E-001 "$TC_SOURCE" \
  'the trust-scoped cache policy surface is present'
fge_assert_file FG-075-E2E-002 "$TC_TEST" \
  'the cache grant, poisoning, secret-lease, and eviction campaign is present'

fge_phase action
fge_capture atp-trust-cache \
  cargo test --locked -p fgit-atp-git --test trust_scoped_cache || cache_exit=$?
cache_exit=${cache_exit:-0}

fge_phase assert
fge_assert_exit FG-075-E2E-010 0 "$cache_exit" \
  'repository-private cross-tenant reads refuse before probing, poisoned pieces quarantine and penalize their peer, secret leases remain separate from grants, and scope-local eviction is deterministic'
