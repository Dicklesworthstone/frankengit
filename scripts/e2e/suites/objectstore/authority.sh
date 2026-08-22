#!/usr/bin/env bash
# e2e: FG-006b -- object-store authority fault-injection campaign receipt.
#
# PLACED UNDER suites/ DELIBERATELY. The bead's acceptance names
# `scripts/e2e/objectstore_authority.sh` "registered in run_all.sh". Both halves
# are wrong: run_all discovers `suites/**` and nothing else, and there is no
# registration mechanism. A script at the e2e root executes nowhere, which is the
# exact defect bead frankengit-osqi exists to fix. This is the fourth bead
# carrying that wording after fg093a, fg094a and fg076; reported for amendment
# rather than obeyed into an orphan.
#
# WHAT THIS RECEIPT ADDS OVER THE RUST CAMPAIGN. crates/fgit-object-store/tests/
# authority_campaign.rs proves the in-process properties. This suite records them
# as swarm-visible evidence with a seed and a revision, and carries the one
# acceptance line that CANNOT be satisfied today as a typed non-claim rather than
# letting it read as covered.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init

fge_phase setup
work=$(fge_tempdir objectstore-authority)

fge_context suite_scope 'FG-006b object-store authority campaign: connection drop, rejection, duplicated delivery and stale-proxy read injected at the transport boundary of the real adapter; admission ABA drill observed in the provider store'

# ---------------------------------------------------------------------------
# the campaign
# ---------------------------------------------------------------------------
fge_phase action

# `|| true` is load-bearing. fge_run RETURNS the command's exit status and this
# script runs under `set -euo pipefail`, so an unguarded failing campaign would
# kill the script ON THIS LINE -- before campaign_exit is read and before the
# assertion below could record the failure. The run would then report fewer
# assertions than it discovered: a truncated record rather than a damning one.
# fge_capture, not fge_run: only capture sets FGE_LAST_STDOUT. Using fge_run
# left the haystack empty, and the three contains-assertions below correctly
# failed -- while FG-006B-E2E-003, a not_contains, PASSED on the empty string.
# It was recorded as `absent (empty haystack)` by the lib.sh hardening landed at
# 16696c6 earlier tonight, which is how the vacuous pass was visible at all
# rather than sitting green in the receipt.
fge_capture FG-006B-E2E-001-run \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-object-store --test authority_campaign -- --nocapture || true
campaign_exit=$FGE_LAST_EXIT
campaign_output="$FGE_LAST_STDOUT"

fge_phase assert
fge_assert_exit FG-006B-E2E-001 0 "$campaign_exit" \
  'the fault-injection campaign passes against the real adapter boundary'

# The campaign must actually have RUN tests, not merely exited zero. A filter
# typo or a renamed target exits 0 having executed nothing, which is the
# "green while measuring nothing" shape this whole lane exists to prevent.
fge_assert_contains FG-006B-E2E-002 "$campaign_output" 'test result: ok.' \
  'the campaign reports a test result rather than exiting zero having run nothing'
fge_assert_not_contains FG-006B-E2E-003 "$campaign_output" '0 passed' \
  'the campaign executed at least one test'

# ---------------------------------------------------------------------------
# the positive control is named, not merely counted
# ---------------------------------------------------------------------------
#
# The campaign's provider states the wire vocabulary independently of the
# adapter's private header constants, so a renamed header would make it answer
# 400/412 to everything while the refusal assertions kept passing. The happy-path
# control is what fails instead. Asserting it BY NAME here means the receipt
# records that the anti-vacuity guard ran, not just that some tests passed.
fge_assert_contains FG-006B-E2E-004 "$campaign_output" 'the_happy_path_control_still_works' \
  'the vocabulary-drift control is present in the run, so the refusal assertions are not vacuous'
fge_assert_contains FG-006B-E2E-005 "$campaign_output" 'admission_exercises_the_aba_drill' \
  'the ABA drill is observed in the provider store rather than inferred from a probe return value'

# ---------------------------------------------------------------------------
# the acceptance line that cannot be satisfied today
# ---------------------------------------------------------------------------
#
# NOT a skip of work that could have been done. AsupersyncHttpTransport::new
# returns Err(TlsTransportNotAdmitted) unconditionally, because the closed
# dependency set has not admitted Asupersync's Rustls closure -- a deliberate
# refusal the crate documents and which fg006a's owner asked explicitly not to
# soften. There is therefore no HTTP transport to point at a server, and no
# server to spin.
#
# Emitted as fge_unsupported rather than omitted, because an omitted cell is
# invisible: the receipt would simply report fewer assertions and nothing would
# say why. An unsupported cell is a terminal non-pass naming the exact missing
# thing.
#
# DELETION CONDITION: when the dependency policy admits Asupersync's TLS closure
# and AsupersyncHttpTransport::new can return Ok, this becomes a live-server
# campaign case and this line is deleted.
fge_unsupported FG-006B-E2E-010 \
  'acceptance names "spins the local test server"; AsupersyncHttpTransport::new returns Err(TlsTransportNotAdmitted) because the closed dependency set has not admitted Asupersync TLS, so no live server is exercised and no network-transport claim is made'

fge_field campaign_faults 4
fge_field live_server_exercised false
fge_note campaign-scope \
  'four transport faults injected into the real adapter: dropped acknowledgement, rejection before effect, duplicated delivery, stale-proxy read. Each forbidden case is paired with a permitted twin, and the effect count in the provider store is asserted alongside the caller-visible outcome so that "it errored" cannot stand in for "no effect occurred".'
