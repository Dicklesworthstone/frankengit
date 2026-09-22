#!/usr/bin/env bash
# FG-046 — Webhook delivery product over transactional outbox evidence campaign.
#
# Proves:
# 1. SSRF prevention: loopback/private/metadata blocked under strict policy.
# 2. HMAC-SHA256 signing and dual-secret rotation window.
# 3. Webhook delivery over transactional outbox with duplicate suppression.
# 4. Receiver-down drill: retries exhaust to terminal dead-letter queue.
# 5. CLI porcelain: register, list, rotate, deliver, dead-letter list and replay.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init fg046-webhook-delivery
fg_target_dir="${CARGO_TARGET_DIR:-/data/frankengit-targets/antigravity_rc}"
fge_context bead frankengit-fg046-webhooks-qs6
fge_context evidence_class E1
fge_context forge_unit_tests crates/fgit-forge/src/webhook/tests.rs
fge_context node_delivery_tests crates/fgit-node/src/webhook/tests.rs

fge_phase setup
work="$(fge_tempdir fg046_webhook)"
repo_dir="$work/repo"
mkdir -p "$repo_dir"

tenant_id="00000000000000000000000000000001"
repo_id="00000000000000000000000000000002"
valid_secret="0123456789abcdef0123456789abcdef"
rotated_secret="fedcba9876543210fedcba9876543210"

# Build fg binary if needed
fge_run_ok fg-build env CARGO_TARGET_DIR="$fg_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo build --locked -p fgit-cli --bin fg

FG_BIN="$fg_target_dir/debug/fg"
if [ ! -x "$FG_BIN" ]; then
  FG_BIN="$(command -v fg || echo "$E2E_ROOT/../../target/debug/fg")"
fi

fge_phase action

# 1. Run fgit-forge unit tests (SSRF policy, rotation window, retry schedule jitter)
fge_capture forge-unit-tests \
  env CARGO_TARGET_DIR="$fg_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-forge --lib webhook -- --nocapture || true
forge_test_exit=$FGE_LAST_EXIT
forge_test_output=$(<"$FGE_LAST_STDOUT_FILE")

# 2. Run fgit-node integration tests (HTTP delivery, signature verification, dead-letter queue, store persistence)
fge_capture node-delivery-tests \
  env CARGO_TARGET_DIR="$fg_target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo test --locked -p fgit-node --lib webhook -- --nocapture || true
node_test_exit=$FGE_LAST_EXIT
node_test_output=$(<"$FGE_LAST_STDOUT_FILE")

# 3. CLI: SSRF rejection of cloud metadata address (169.254.169.254)
fge_capture cli-ssrf-metadata \
  "$FG_BIN" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --id 101 --url "http://169.254.169.254/latest/meta-data" --secret "$valid_secret" || true
ssrf_meta_exit=$FGE_LAST_EXIT

# 4. CLI: SSRF rejection of private IPv4 network (10.0.0.1)
fge_capture cli-ssrf-private \
  "$FG_BIN" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --id 102 --url "http://10.0.0.1/hook" --secret "$valid_secret" || true
ssrf_priv_exit=$FGE_LAST_EXIT

# 5. CLI: Successful registration with permissive policy for loopback integration
fge_capture cli-register-valid \
  "$FG_BIN" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --id 1 --url "http://127.0.0.1:18999/hook" --secret "$valid_secret" --permissive-for-tests || true
reg_exit=$FGE_LAST_EXIT
reg_output=$(<"$FGE_LAST_STDOUT_FILE")

# 6. CLI: List registered webhooks
fge_capture cli-list-webhooks \
  "$FG_BIN" webhook list "$repo_dir" "$tenant_id" "$repo_id" --trusted-local || true
list_exit=$FGE_LAST_EXIT
list_output=$(<"$FGE_LAST_STDOUT_FILE")

# 7. CLI: Secret rotation with window
fge_capture cli-rotate-secret \
  "$FG_BIN" webhook rotate "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --id 1 --new-secret "$rotated_secret" --window-secs 3600 || true
rotate_exit=$FGE_LAST_EXIT
rotate_output=$(<"$FGE_LAST_STDOUT_FILE")

# 8. CLI: Receiver-down drill (target port 18999 has no listener)
# Attempt 1: TransientFailure (exit 1)
fge_capture cli-deliver-down-attempt1 \
  "$FG_BIN" webhook deliver "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --id 1 --delivery-id "deliv-down-test" --attempt 1 --permissive-for-tests || true
down_att1_exit=$FGE_LAST_EXIT

# Attempt 5: Exhaustion -> PermanentRejection -> DeadLetter (exit 2)
fge_capture cli-deliver-down-attempt5 \
  "$FG_BIN" webhook deliver "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --id 1 --delivery-id "deliv-down-test" --attempt 5 --permissive-for-tests || true
down_att5_exit=$FGE_LAST_EXIT

# 9. CLI: Dead-letter queue listing
fge_capture cli-dead-letter-list \
  "$FG_BIN" webhook dead-letter list "$repo_dir" "$tenant_id" "$repo_id" --trusted-local || true
dl_list_exit=$FGE_LAST_EXIT
dl_list_output=$(<"$FGE_LAST_STDOUT_FILE")

# 10. CLI: Dead-letter replay
fge_capture cli-dead-letter-replay \
  "$FG_BIN" webhook dead-letter replay "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
  --delivery-id "deliv-down-test" || true
dl_replay_exit=$FGE_LAST_EXIT
dl_replay_output=$(<"$FGE_LAST_STDOUT_FILE")

# 11. CLI: Dead-letter list after replay is empty
fge_capture cli-dead-letter-list-after \
  "$FG_BIN" webhook dead-letter list "$repo_dir" "$tenant_id" "$repo_id" --trusted-local || true
dl_after_exit=$FGE_LAST_EXIT
dl_after_output=$(<"$FGE_LAST_STDOUT_FILE")

fge_phase assert

# Assertions for forge unit tests
fge_assert_exit FG-046-E2E-001 0 "$forge_test_exit" \
  'fgit-forge webhook unit tests passed'
fge_assert_contains FG-046-E2E-002 "$forge_test_output" \
  'test webhook::tests::ssrf_strict_blocks_loopback_private_and_metadata_addresses ... ok' \
  'SSRF strict policy blocks loopback, private and cloud metadata addresses'
fge_assert_contains FG-046-E2E-003 "$forge_test_output" \
  'test webhook::tests::webhook_secret_rotation_window ... ok' \
  'Webhook secret rotation window verifies both active and expiring secrets'
fge_assert_contains FG-046-E2E-004 "$forge_test_output" \
  'test webhook::tests::webhook_retry_schedule_exponential_backoff_and_jitter ... ok' \
  'Webhook retry schedule computes bounded exponential backoff with deterministic jitter'

# Assertions for node integration tests
fge_assert_exit FG-046-E2E-005 0 "$node_test_exit" \
  'fgit-node webhook integration tests passed'
fge_assert_contains FG-046-E2E-006 "$node_test_output" \
  'test webhook::tests::webhook_delivery_successful_acknowledgement_and_signature_verification ... ok' \
  'Webhook HTTP delivery verifies signature and delivery headers on mock receiver'
fge_assert_contains FG-046-E2E-007 "$node_test_output" \
  'test webhook::tests::webhook_duplicate_delivery_reports_duplicate_suppressed ... ok' \
  'Duplicate delivery with same delivery ID reports DuplicateSuppressed'
fge_assert_contains FG-046-E2E-008 "$node_test_output" \
  'test webhook::tests::webhook_receiver_down_drill_retries_and_exhausts_to_dead_letter ... ok' \
  'Receiver-down drill retries to exhaustion and logs dead-letter entry'
fge_assert_contains FG-046-E2E-009 "$node_test_output" \
  'test webhook::tests::webhook_store_persists_registrations_and_dead_letters ... ok' \
  'WebhookStore persists registrations and dead-letter log across reopening'

# Assertions for CLI commands
fge_assert_exit FG-046-E2E-010 2 "$ssrf_meta_exit" \
  'fg webhook register refuses cloud metadata target'
fge_assert_exit FG-046-E2E-011 2 "$ssrf_priv_exit" \
  'fg webhook register refuses private network target'
fge_assert_exit FG-046-E2E-012 0 "$reg_exit" \
  'fg webhook register succeeds with valid configuration'
fge_assert_contains FG-046-E2E-013 "$reg_output" \
  '"type":"webhook_registered"' \
  'Webhook registration output conforms to schema'

fge_assert_exit FG-046-E2E-014 0 "$list_exit" \
  'fg webhook list succeeds'
fge_assert_contains FG-046-E2E-015 "$list_output" \
  '"id":1' \
  'Webhook list output includes registered webhook ID'

fge_assert_exit FG-046-E2E-016 0 "$rotate_exit" \
  'fg webhook rotate succeeds'
fge_assert_contains FG-046-E2E-017 "$rotate_output" \
  '"type":"webhook_secret_rotated"' \
  'Webhook rotation receipt emitted'

fge_assert_exit FG-046-E2E-018 1 "$down_att1_exit" \
  'Receiver down attempt 1 returns TransientFailure (exit 1)'
fge_assert_exit FG-046-E2E-019 2 "$down_att5_exit" \
  'Receiver down attempt 5 returns PermanentRejection (exit 2)'

fge_assert_exit FG-046-E2E-020 0 "$dl_list_exit" \
  'fg webhook dead-letter list succeeds'
fge_assert_contains FG-046-E2E-021 "$dl_list_output" \
  'deliv-down-test' \
  'Dead-letter list contains the terminal failure delivery ID'

fge_assert_exit FG-046-E2E-022 0 "$dl_replay_exit" \
  'fg webhook dead-letter replay succeeds'
fge_assert_contains FG-046-E2E-023 "$dl_replay_output" \
  '"status":"replayed"' \
  'Dead-letter replay confirmation emitted'

fge_assert_exit FG-046-E2E-024 0 "$dl_after_exit" \
  'fg webhook dead-letter list after replay succeeds'
fge_assert_contains FG-046-E2E-025 "$dl_after_output" \
  '"count":0' \
  'Dead-letter queue is empty after replaying entry'
