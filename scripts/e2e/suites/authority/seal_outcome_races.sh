#!/usr/bin/env bash
# FG-007b — logical seal/outcome race, crash, and retry recovery campaign.
#
# `run_all.sh` discovers executable scripts below `suites/`, so this is the
# registered E2E entry.  The Rust corpus drives the authority reference/lab
# profile; it does not claim native scheduler, media-loss, or runtime-adapter
# cancellation coverage.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg007b-seal-outcome-races
fge_context bead frankengit-fg007b-seal-races-ujf
fge_context evidence_class E1+E4
fge_context corpus crates/fgit-txn/tests/seal_races_authority.rs
fge_context schedule_engine 'FG-013 DPOR for duplicate seals; seeded LabSchedule for retry storm'
fge_context non_claim 'logical reference-store campaign only; native process/media loss and runtime-adapter cancellation are out of scope'

fge_phase setup
seed=$(fge_seed)
fge_context seal_race_seed "0x$seed"
fge_context seed "0x$seed"
fge_assert_file FG-007B-E2E-001 \
  "$E2E_ROOT/../../crates/fgit-txn/tests/seal_races_authority.rs" \
  'the independent seal/outcome campaign corpus is present'

fge_phase action
fge_capture seal-outcome-races \
  env RCH_CARGO_WRAPPER_BYPASS=1 "FGIT_SEAL_RACE_SEED=0x$seed" \
  cargo test --locked -p fgit-txn --test seal_races_authority -- --nocapture || true
campaign_exit=$FGE_LAST_EXIT
campaign_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_phase assert
fge_assert_exit FG-007B-E2E-002 0 "$campaign_exit" \
  'all DPOR, retry, crash, lost-response, accelerator-recovery, and cancellation-contract cases hold'
fge_assert_contains FG-007B-E2E-003 "$campaign_output" \
  "fgit.seal-race.seed=$((16#$seed))" \
  'the exact seeded retry schedule is emitted by the corpus for replay'
