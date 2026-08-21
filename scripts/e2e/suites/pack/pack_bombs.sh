#!/usr/bin/env bash
# FG-016b pack quarantine bomb corpus: bounded reader, delta resolver, and
# idx-to-pack association refusals. Each captured test has an accepted
# near-neighbor and runs against the production pack API.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"

fge_init
fge_phase setup
fge_context suite pack-bombs
seed=$(fge_seed)
fge_context pack_bomb_seed "$seed"
fge_step configure "FG_PACK_BOMB_SEED=$seed"

fge_phase action
fge_capture pack-bombs-reader \
  env "FG_PACK_BOMB_SEED=0x$seed" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test -p fgit-pack --test bombs_reader -- --nocapture || true
reader_exit=$FGE_LAST_EXIT
reader_output=$FGE_LAST_STDOUT$'\n'$FGE_LAST_STDERR

fge_capture pack-bombs-resolver \
  env "FG_PACK_BOMB_SEED=0x$seed" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test -p fgit-pack --test bombs_resolver -- --nocapture || true
resolver_exit=$FGE_LAST_EXIT
resolver_output=$FGE_LAST_STDOUT$'\n'$FGE_LAST_STDERR

fge_capture pack-bombs-idx \
  env "FG_PACK_BOMB_SEED=0x$seed" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test -p fgit-pack --test bombs_idx -- --nocapture || true
idx_exit=$FGE_LAST_EXIT
idx_output=$FGE_LAST_STDOUT$'\n'$FGE_LAST_STDERR

fge_phase assert
fge_assert_exit FG-016B-E2E-001 0 "$reader_exit" \
  'reader input, size, ratio, and trailer bomb corpus succeeds'
fge_assert_contains FG-016B-E2E-002 "$reader_output" \
  'declared_size_and_aggregate_bombs_trip_before_entry_output_allocation' \
  'reader corpus records pre-allocation declared-size accounting'
fge_assert_exit FG-016B-E2E-003 0 "$resolver_exit" \
  'OFS/REF chain, fanout, thin-base, ratio, and work bomb corpus succeeds'
fge_assert_contains FG-016B-E2E-004 "$resolver_output" \
  'ref_cycles_and_absent_thin_bases_refuse_without_a_resolved_object' \
  'resolver corpus records cyclic REF and missing thin-base refusal coverage'
fge_assert_exit FG-016B-E2E-005 0 "$idx_exit" \
  'idx CRC and pack-count association bomb corpus succeeds'
fge_assert_contains FG-016B-E2E-006 "$idx_output" \
  'idx_crc_and_pack_count_mismatches_refuse_index_association' \
  'idx corpus records both association refusal classes'
