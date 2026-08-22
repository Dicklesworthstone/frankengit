#!/usr/bin/env bash
# FG-023b: bounded ATP-Git path and swarm campaign.
#
# The bead's literal requested location was `scripts/e2e/atp_swarm_campaign.sh`,
# but the repository-owned runner discovers executable suites only under
# `scripts/e2e/suites/<area>/`. This registered transport suite is therefore
# the executable equivalent; changing the frozen runner would make the test
# depend on a private registration path.
#
# This is evidence about the SANS-I/O implementation's bounded logical traces,
# not live packet delivery or socket-timeout behavior. The action target covers
# receipt-or-named-refusal partition outcomes, failover obligation ordering,
# corrupt-piece penalty, and the ordinary Git-pack transport selection. It is
# explicitly not a substitution for the absent controller evidence-gap API.
# The adjacent actor target supplies the cancellation request/drain/finalize
# matrix.
set -euo pipefail

ATP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ATP_REPO=$(cd "$ATP_DIR/../../../.." && pwd -P)
# shellcheck source=/dev/null
. "$ATP_REPO/scripts/e2e/lib.sh"

readonly ATP_TESTS="$ATP_REPO/crates/fgit-atp-git/tests"
readonly ATP_SOURCE="$ATP_REPO/crates/fgit-atp-git/src"

fge_init fg023b-atp-swarm-campaign
fge_context bead frankengit-fg023b-atp-paths-evidence-t3h
fge_context crate fgit-atp-git
fge_context evidence_class bounded_logical_trace_campaign
fge_context non_claim 'This SANS-I/O crate has no socket, packet codec, async runtime, or wall-clock budget. The campaign does not claim live loss/reordering/slow-peer behavior or deadline enforcement.'
fge_context non_claim 'The GitPackFallback path receipt is a selected path candidate. Plan-level FullFallbackReason behavior remains covered by fallback_reasons.rs; this does not claim a controller evidence-gap API that the crate does not expose.'

export RCH_CARGO_WRAPPER_BYPASS=1

fge_phase setup
fge_assert_file FG-023B-E2E-001 "$ATP_TESTS/path_swarm_campaign.rs" \
  'the bounded partition, peer-penalty, and fallback campaign is present'
fge_assert_file FG-023B-E2E-002 "$ATP_TESTS/path_swarm_actor.rs" \
  'the cancellation request-drain-finalize matrix is present'
fge_assert_file FG-023B-E2E-003 "$ATP_TESTS/fallback_reasons.rs" \
  'the plan-level deterministic fallback receipt campaign is present'

campaign_reaches_into_source=''
if grep -Eq '(include!|path[[:space:]]*=[[:space:]]*"[^"]*atp-git/src)' \
  "$ATP_TESTS/path_swarm_campaign.rs"; then
  campaign_reaches_into_source='yes'
fi

# The terminality claim has a structural precondition: no timer, timeout, or
# async operation is available to this pure bounded state machine. If a future
# implementation adds one, this guard fails and forces a new time-aware test;
# it must not silently inherit the present construction argument.
fge_run atp-no-time-dependency \
  grep -REn '(^|[^[:alnum:]_])(Duration|Instant|SystemTime|deadline|timeout|async[[:space:]]+fn)([^[:alnum:]_]|$)' \
  "$ATP_SOURCE" || true
atp_time_surface_exit=$FGE_LAST_EXIT

fge_phase action
fge_capture atp-path-swarm-campaign \
  cargo test --locked -p fgit-atp-git --test path_swarm_campaign || campaign_exit=$?
campaign_exit=${campaign_exit:-0}
fge_capture atp-path-swarm-actor \
  cargo test --locked -p fgit-atp-git --test path_swarm_actor || actor_exit=$?
actor_exit=${actor_exit:-0}
fge_capture atp-plan-fallback-reasons \
  cargo test --locked -p fgit-atp-git --test fallback_reasons || fallback_exit=$?
fallback_exit=${fallback_exit:-0}

fge_phase assert
fge_assert_exit FG-023B-E2E-010 0 "$campaign_exit" \
  'every named partition shape returns a bounded receipt or its named refusal; loser effects abort before the winner commits; invalid availability cannot verify a piece and is penalized'
fge_assert_exit FG-023B-E2E-011 0 "$actor_exit" \
  'cancellation in every active actor phase records request, drain, and finalization before close'
fge_assert_exit FG-023B-E2E-012 0 "$fallback_exit" \
  'every published FullFallbackReason is selected by its mapped condition and emitted in a plan receipt'
fge_assert_exit FG-023B-E2E-013 1 "$atp_time_surface_exit" \
  'the bounded SANS-I/O source has no timer, timeout, or async surface that could block without a new time-aware campaign'
fge_assert_eq FG-023B-E2E-014 '' "$campaign_reaches_into_source" \
  'the independent campaign drives the public API rather than including implementation source'
