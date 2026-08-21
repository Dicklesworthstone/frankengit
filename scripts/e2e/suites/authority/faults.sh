#!/usr/bin/env bash
# FG-004c authority fault campaign wrapper. The harness captures the Rust test
# output as an artifact; each test prints one deterministic campaign NDJSON
# record containing the seed, fault script, full history projection, raw
# caller results, and lincheck verdict.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"

fge_init
fge_phase setup
fge_context suite authority-faults
seed=$(fge_seed)
fge_context authority_fault_seed "$seed"
fge_step configure "FG_AUTHORITY_FAULT_SEED=$seed"

fge_phase action
fge_capture authority-fault-campaign \
  env "FG_AUTHORITY_FAULT_SEED=0x$seed" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test -p fgit-authority --test fault_campaign -- --nocapture || true
campaign_exit=$FGE_LAST_EXIT
# `FGE_LAST_STDOUT` is intentionally capped for harness NDJSON records.  The
# campaign emits one large evidence line per seed, so assertions must inspect
# the complete captured artifact rather than treating the diagnostic preview
# as the campaign transcript.
campaign_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_phase assert
fge_assert_exit FG-004C-E2E-001 0 "$campaign_exit" \
  'the seeded authority fault campaign succeeds'
fge_assert_contains FG-004C-E2E-002 "$campaign_output" \
  '"schema":"fgit.authority.fault-campaign.v1"' \
  'the captured campaign artifact contains checker evidence records'
fge_assert_contains FG-004C-E2E-003 "$campaign_output" \
  '"verdict":"linearizable"' \
  'the reference campaign reports linearizable histories'
fge_assert_contains FG-004C-E2E-004 "$campaign_output" \
  '"verdict":"not_linearizable"' \
  'the planted double-success backend is rejected by lincheck'
