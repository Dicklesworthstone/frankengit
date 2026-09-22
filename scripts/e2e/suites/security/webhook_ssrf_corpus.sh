#!/usr/bin/env bash
# FG-046b — Webhook SSRF and retry adversarial corpus evidence campaign.
#
# Asserts:
# 1. SSRF probes (metadata, loopback, private IPv4, link-local/ULA/NAT64 IPv6,
#    credentials, non-HTTP schemes) are refused with typed errors; zero internal-target deliveries.
# 2. Permitted public targets are accepted.
# 3. Dual-secret rotation window: both secrets valid during window, then prior secret expires.
# 4. Duplicate deliveries share delivery ID; duplicate delivery is suppressed.
# 5. Receiver-down drill: unreachable receiver reaches typed terminal failure with dead-letter entry.
# 6. Emits per-probe NDJSON verdicts artifact.
#
# Pure bash plus coreutils, per FG-000A-PORT-019.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly DEFAULT_TARGET_DIR="/data/frankengit-targets/antigravity_rc"

main() {
  local target_dir="${CARGO_TARGET_DIR:-$DEFAULT_TARGET_DIR}"
  local artifact_dir
  local verdict_ndjson
  local test_exit=0
  local test_output=''

  fge_phase setup
  fge_context bead frankengit-fg046b-webhook-ssrf-rdro
  fge_context suite webhook-ssrf-corpus
  fge_context evidence_class local_exact
  fge_context non_claim 'Adversarial validation runs within sandboxed pure-Rust engine; does not claim live WAN public internet connectivity.'

  artifact_dir="$(fge_tempdir webhook-ssrf-corpus)"
  verdict_ndjson="$artifact_dir/webhook_ssrf_verdicts.ndjson"
  : >"$verdict_ndjson"

  local repo_dir="$artifact_dir/repo"
  mkdir -p "$repo_dir"
  local tenant_id="00000000000000000000000000000001"
  local repo_id="00000000000000000000000000000002"
  local secret_v1="0123456789abcdef0123456789abcdef"
  local secret_v2="fedcba9876543210fedcba9876543210"

  # Ensure fg CLI binary is built with current workspace crates
  fge_run_ok fg-build env CARGO_TARGET_DIR="$target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo build --locked -p fgit-cli --bin fg
  local fg_bin="$target_dir/debug/fg"

  fge_phase action

  # 1. Run fgit-forge integration test target: webhook_ssrf_corpus
  fge_capture webhook-ssrf-rust-corpus \
    env CARGO_TARGET_DIR="$target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-forge --test webhook_ssrf_corpus -- --nocapture || test_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" webhook-ssrf-corpus-stdout
    test_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" webhook-ssrf-corpus-stderr
    test_output="${test_output}"$'\n'"$(<"$FGE_LAST_STDERR_FILE")"
  fi

  # Helper to record probe verdict to NDJSON
  record_verdict() {
    local probe_id="$1"
    local category="$2"
    local url="$3"
    local expected="$4"
    local actual="$5"
    local verdict="$6"
    printf '{"schema":"frankengit.security.webhook_ssrf_verdict.v1","id":"%s","category":"%s","url":"%s","expected":"%s","actual":"%s","verdict":"%s"}\n' \
      "$probe_id" "$category" "$url" "$expected" "$actual" "$verdict" >>"$verdict_ndjson"
  }

  # 2. CLI Adversarial SSRF Probes
  # Probe 1: AWS/GCP Metadata IP
  local meta_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 101 --url "http://169.254.169.254/latest/meta-data" --secret "$secret_v1" >/dev/null 2>&1 || meta_exit=$?
  if [ "$meta_exit" -ne 0 ]; then
    record_verdict "SSRF-META-001" "cloud_metadata" "http://169.254.169.254/latest/meta-data" "refused" "refused" "pass"
  else
    record_verdict "SSRF-META-001" "cloud_metadata" "http://169.254.169.254/latest/meta-data" "refused" "accepted" "fail"
  fi

  # Probe 2: Loopback IPv4
  local loop_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 102 --url "http://127.0.0.1:8080/hook" --secret "$secret_v1" >/dev/null 2>&1 || loop_exit=$?
  if [ "$loop_exit" -ne 0 ]; then
    record_verdict "SSRF-LOOP-001" "loopback_ipv4" "http://127.0.0.1:8080/hook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-LOOP-001" "loopback_ipv4" "http://127.0.0.1:8080/hook" "refused" "accepted" "fail"
  fi

  # Probe 3: RFC 1918 Class A (10.0.0.0/8)
  local priv10_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 103 --url "http://10.0.0.1/webhook" --secret "$secret_v1" >/dev/null 2>&1 || priv10_exit=$?
  if [ "$priv10_exit" -ne 0 ]; then
    record_verdict "SSRF-PRIV-010" "rfc1918_class_a" "http://10.0.0.1/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-PRIV-010" "rfc1918_class_a" "http://10.0.0.1/webhook" "refused" "accepted" "fail"
  fi

  # Probe 4: RFC 1918 Class B (172.16.0.0/12)
  local priv172_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 104 --url "http://172.16.0.1/webhook" --secret "$secret_v1" >/dev/null 2>&1 || priv172_exit=$?
  if [ "$priv172_exit" -ne 0 ]; then
    record_verdict "SSRF-PRIV-172" "rfc1918_class_b" "http://172.16.0.1/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-PRIV-172" "rfc1918_class_b" "http://172.16.0.1/webhook" "refused" "accepted" "fail"
  fi

  # Probe 5: RFC 1918 Class C (192.168.0.0/16)
  local priv192_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 105 --url "http://192.168.1.1/webhook" --secret "$secret_v1" >/dev/null 2>&1 || priv192_exit=$?
  if [ "$priv192_exit" -ne 0 ]; then
    record_verdict "SSRF-PRIV-192" "rfc1918_class_c" "http://192.168.1.1/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-PRIV-192" "rfc1918_class_c" "http://192.168.1.1/webhook" "refused" "accepted" "fail"
  fi

  # Probe 6: Carrier-Grade NAT (100.64.0.0/10)
  local cgnat_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 106 --url "http://100.64.0.1/webhook" --secret "$secret_v1" >/dev/null 2>&1 || cgnat_exit=$?
  if [ "$cgnat_exit" -ne 0 ]; then
    record_verdict "SSRF-CGNAT-001" "carrier_grade_nat" "http://100.64.0.1/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-CGNAT-001" "carrier_grade_nat" "http://100.64.0.1/webhook" "refused" "accepted" "fail"
  fi

  # Probe 7: IPv6 Loopback [::1]
  local ip6_loop_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 107 --url "http://[::1]/webhook" --secret "$secret_v1" >/dev/null 2>&1 || ip6_loop_exit=$?
  if [ "$ip6_loop_exit" -ne 0 ]; then
    record_verdict "SSRF-IP6-LOOP" "ipv6_loopback" "http://[::1]/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-IP6-LOOP" "ipv6_loopback" "http://[::1]/webhook" "refused" "accepted" "fail"
  fi

  # Probe 8: IPv6 Link-Local [fe80::1]
  local ip6_ll_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 108 --url "http://[fe80::1]/webhook" --secret "$secret_v1" >/dev/null 2>&1 || ip6_ll_exit=$?
  if [ "$ip6_ll_exit" -ne 0 ]; then
    record_verdict "SSRF-IP6-LL" "ipv6_link_local" "http://[fe80::1]/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-IP6-LL" "ipv6_link_local" "http://[fe80::1]/webhook" "refused" "accepted" "fail"
  fi

  # Probe 9: IPv6 Unique Local Address [fc00::1]
  local ip6_ula_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 109 --url "http://[fc00::1]/webhook" --secret "$secret_v1" >/dev/null 2>&1 || ip6_ula_exit=$?
  if [ "$ip6_ula_exit" -ne 0 ]; then
    record_verdict "SSRF-IP6-ULA" "ipv6_unique_local" "http://[fc00::1]/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-IP6-ULA" "ipv6_unique_local" "http://[fc00::1]/webhook" "refused" "accepted" "fail"
  fi

  # Probe 10: IPv4-Mapped IPv6 Cloud Metadata [::ffff:169.254.169.254]
  local ip6_mapped_meta_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 110 --url "http://[::ffff:169.254.169.254]/webhook" --secret "$secret_v1" >/dev/null 2>&1 || ip6_mapped_meta_exit=$?
  if [ "$ip6_mapped_meta_exit" -ne 0 ]; then
    record_verdict "SSRF-IP6-MAPMETA" "ipv6_mapped_metadata" "http://[::ffff:169.254.169.254]/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-IP6-MAPMETA" "ipv6_mapped_metadata" "http://[::ffff:169.254.169.254]/webhook" "refused" "accepted" "fail"
  fi

  # Probe 11: NAT64 Prefix Embedding Loopback [64:ff9b::127.0.0.1]
  local nat64_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 111 --url "http://[64:ff9b::127.0.0.1]/webhook" --secret "$secret_v1" >/dev/null 2>&1 || nat64_exit=$?
  if [ "$nat64_exit" -ne 0 ]; then
    record_verdict "SSRF-NAT64-LOOP" "nat64_loopback" "http://[64:ff9b::127.0.0.1]/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-NAT64-LOOP" "nat64_loopback" "http://[64:ff9b::127.0.0.1]/webhook" "refused" "accepted" "fail"
  fi

  # Probe 12: Embedded Credentials in Authority
  local creds_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 112 --url "http://admin:secret@api.example.com/webhook" --secret "$secret_v1" >/dev/null 2>&1 || creds_exit=$?
  if [ "$creds_exit" -ne 0 ]; then
    record_verdict "SSRF-AUTH-CREDS" "embedded_credentials" "http://admin:secret@api.example.com/webhook" "refused" "refused" "pass"
  else
    record_verdict "SSRF-AUTH-CREDS" "embedded_credentials" "http://admin:secret@api.example.com/webhook" "refused" "accepted" "fail"
  fi

  # Probe 13: Unsupported Scheme (file://)
  local file_scheme_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 113 --url "file:///etc/passwd" --secret "$secret_v1" >/dev/null 2>&1 || file_scheme_exit=$?
  if [ "$file_scheme_exit" -ne 0 ]; then
    record_verdict "SSRF-SCHEME-FILE" "unsupported_scheme" "file:///etc/passwd" "refused" "refused" "pass"
  else
    record_verdict "SSRF-SCHEME-FILE" "unsupported_scheme" "file:///etc/passwd" "refused" "accepted" "fail"
  fi

  # Probe 14: Unsupported Scheme (gopher://)
  local gopher_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 114 --url "gopher://127.0.0.1:70/" --secret "$secret_v1" >/dev/null 2>&1 || gopher_exit=$?
  if [ "$gopher_exit" -ne 0 ]; then
    record_verdict "SSRF-SCHEME-GOPHER" "unsupported_scheme" "gopher://127.0.0.1:70/" "refused" "refused" "pass"
  else
    record_verdict "SSRF-SCHEME-GOPHER" "unsupported_scheme" "gopher://127.0.0.1:70/" "refused" "accepted" "fail"
  fi

  # Probe 15: Valid Public Target (Accepted)
  local public_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 200 --url "https://api.github.com/webhook" --secret "$secret_v1" >/dev/null 2>&1 || public_exit=$?
  if [ "$public_exit" -eq 0 ]; then
    record_verdict "SSRF-VALID-PUB" "public_target" "https://api.github.com/webhook" "accepted" "accepted" "pass"
  else
    record_verdict "SSRF-VALID-PUB" "public_target" "https://api.github.com/webhook" "accepted" "refused" "fail"
  fi

  # Probe 16: Permissive Local Target for Receiver-Down and Dedup Drills
  local drill_reg_exit=0
  "$fg_bin" webhook register "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 1 --url "http://127.0.0.1:19876/hook" --secret "$secret_v1" --permissive-for-tests >/dev/null 2>&1 || drill_reg_exit=$?

  # Probe 17: Secret Rotation Window (Dual-Secret Grace Period)
  local rotate_exit=0
  "$fg_bin" webhook rotate "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 1 --new-secret "$secret_v2" --window-secs 3600 >/dev/null 2>&1 || rotate_exit=$?
  if [ "$rotate_exit" -eq 0 ]; then
    record_verdict "SEC-ROT-001" "secret_rotation" "http://127.0.0.1:19876/hook" "rotated_window" "rotated_window" "pass"
  else
    record_verdict "SEC-ROT-001" "secret_rotation" "http://127.0.0.1:19876/hook" "rotated_window" "rotation_failed" "fail"
  fi

  # Probe 18: In-Engine Webhook Delivery & Deduplication Tests
  local node_test_exit=0
  local node_test_output=''
  fge_capture webhook-node-delivery-tests \
    env CARGO_TARGET_DIR="$target_dir" RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-node --lib webhook -- --nocapture || node_test_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    node_test_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    node_test_output="${node_test_output}"$'\n'"$(<"$FGE_LAST_STDERR_FILE")"
  fi
  if [ "$node_test_exit" -eq 0 ]; then
    record_verdict "SSRF-DEDUP-001" "delivery_deduplication" "http://127.0.0.1/hook" "duplicate_suppressed" "duplicate_suppressed" "pass"
  else
    record_verdict "SSRF-DEDUP-001" "delivery_deduplication" "http://127.0.0.1/hook" "duplicate_suppressed" "failed" "fail"
  fi

  # Probe 19: Receiver-down Drill (attempt 5 exhausts to DeadLetter)
  local down_exhaust_exit=0
  "$fg_bin" webhook deliver "$repo_dir" "$tenant_id" "$repo_id" --trusted-local \
    --id 1 --delivery-id "deliv-down-ssrf-002" --attempt 5 --permissive-for-tests >/dev/null 2>&1 || down_exhaust_exit=$?
  if [ "$down_exhaust_exit" -eq 2 ]; then
    record_verdict "REC-DOWN-001" "receiver_down_drill" "http://127.0.0.1:19876/hook" "dead_letter" "dead_letter" "pass"
  else
    record_verdict "REC-DOWN-001" "receiver_down_drill" "http://127.0.0.1:19876/hook" "dead_letter" "non_terminal" "fail"
  fi

  # Probe 20: Dead-letter queue listing verification
  local dl_output=''
  fge_capture cli-dead-letter-list \
    "$fg_bin" webhook dead-letter list "$repo_dir" "$tenant_id" "$repo_id" --trusted-local || true
  dl_output="$(<"$FGE_LAST_STDOUT_FILE")"
  if [[ "$dl_output" == *"deliv-down-ssrf-002"* ]]; then
    record_verdict "DEAD-LETTER-001" "dead_letter_persistence" "http://127.0.0.1:19876/hook" "recorded" "recorded" "pass"
  else
    record_verdict "DEAD-LETTER-001" "dead_letter_persistence" "http://127.0.0.1:19876/hook" "recorded" "missing" "fail"
  fi

  fge_artifact "$verdict_ndjson" webhook-ssrf-verdicts

  fge_phase assert

  # Rust integration test assertion
  fge_assert_exit FG-046B-E2E-001 0 "$test_exit" \
    'webhook SSRF rust integration tests target completes successfully'
  fge_assert_contains FG-046B-E2E-002 "$test_output" \
    'ssrf_corpus_blocks_all_metadata_targets ... ok' \
    'corpus blocks all cloud metadata IP variants (dotted, decimal, hex, octal)'
  fge_assert_contains FG-046B-E2E-003 "$test_output" \
    'ssrf_corpus_blocks_all_private_and_loopback_ipv4 ... ok' \
    'corpus blocks RFC 1918, loopback, CGNAT, and broadcast/multicast IPv4 targets'
  fge_assert_contains FG-046B-E2E-004 "$test_output" \
    'ssrf_corpus_blocks_all_forbidden_ipv6_addresses ... ok' \
    'corpus blocks IPv6 loopback, ULA, link-local, IPv4-mapped, NAT64, 6to4, and discard prefixes'
  fge_assert_contains FG-046B-E2E-005 "$test_output" \
    'ssrf_corpus_blocks_embedded_credentials_and_unsupported_schemes ... ok' \
    'corpus blocks userinfo in URL authority and non-HTTP schemes'
  fge_assert_contains FG-046B-E2E-006 "$test_output" \
    'ssrf_corpus_accepts_valid_public_targets ... ok' \
    'corpus accepts valid public HTTPS endpoints'
  fge_assert_contains FG-046B-E2E-007 "$test_output" \
    'ssrf_corpus_redirect_validation ... ok' \
    'corpus blocks redirects targeting internal or metadata IPs'
  fge_assert_contains FG-046B-E2E-008 "$test_output" \
    'dual_secret_rotation_window_full_lifecycle ... ok' \
    'both secrets validate during rotation window, then prior secret strictly expires'
  fge_assert_contains FG-046B-E2E-009 "$test_output" \
    'retry_schedule_exponential_backoff_bounds_and_jitter ... ok' \
    'exponential retry schedule enforces bounds and jitter'

  # CLI SSRF Assertions
  fge_assert_exit FG-046B-E2E-010 2 "$meta_exit" \
    'CLI refuses cloud metadata target 169.254.169.254'
  fge_assert_exit FG-046B-E2E-011 2 "$loop_exit" \
    'CLI refuses loopback target 127.0.0.1 under strict policy'
  fge_assert_exit FG-046B-E2E-012 2 "$priv10_exit" \
    'CLI refuses RFC 1918 Class A private IP 10.0.0.1'
  fge_assert_exit FG-046B-E2E-013 2 "$priv172_exit" \
    'CLI refuses RFC 1918 Class B private IP 172.16.0.1'
  fge_assert_exit FG-046B-E2E-014 2 "$priv192_exit" \
    'CLI refuses RFC 1918 Class C private IP 192.168.1.1'
  fge_assert_exit FG-046B-E2E-015 2 "$cgnat_exit" \
    'CLI refuses carrier grade NAT target 100.64.0.1'
  fge_assert_exit FG-046B-E2E-016 2 "$ip6_loop_exit" \
    'CLI refuses IPv6 loopback [::1]'
  fge_assert_exit FG-046B-E2E-017 2 "$ip6_ll_exit" \
    'CLI refuses IPv6 link-local [fe80::1]'
  fge_assert_exit FG-046B-E2E-018 2 "$ip6_ula_exit" \
    'CLI refuses IPv6 unique local [fc00::1]'
  fge_assert_exit FG-046B-E2E-019 2 "$ip6_mapped_meta_exit" \
    'CLI refuses IPv4-mapped IPv6 cloud metadata [::ffff:169.254.169.254]'
  fge_assert_exit FG-046B-E2E-020 2 "$nat64_exit" \
    'CLI refuses NAT64 prefix embedding loopback [64:ff9b::127.0.0.1]'
  fge_assert_exit FG-046B-E2E-021 2 "$creds_exit" \
    'CLI refuses URL with embedded credentials'
  fge_assert_exit FG-046B-E2E-022 2 "$file_scheme_exit" \
    'CLI refuses file:// scheme'
  fge_assert_exit FG-046B-E2E-023 2 "$gopher_exit" \
    'CLI refuses gopher:// scheme'
  fge_assert_exit FG-046B-E2E-024 0 "$public_exit" \
    'CLI accepts valid public HTTPS target https://api.github.com/webhook'

  # Rotation window, Dedup, Receiver-down assertions
  fge_assert_exit FG-046B-E2E-025 0 "$rotate_exit" \
    'CLI successfully initiates dual-secret rotation window'
  fge_assert_exit FG-046B-E2E-026 0 "$node_test_exit" \
    'fgit-node webhook delivery and deduplication unit tests pass'
  fge_assert_contains FG-046B-E2E-027 "$node_test_output" \
    'webhook_duplicate_delivery_reports_duplicate_suppressed ... ok' \
    'duplicate delivery with same delivery ID reports DuplicateSuppressed'
  fge_assert_exit FG-046B-E2E-028 2 "$down_exhaust_exit" \
    'receiver down attempt 5 exhausts retries to terminal failure (exit 2)'
  fge_assert_contains FG-046B-E2E-029 "$dl_output" \
    'deliv-down-ssrf-002' \
    'exhausted delivery is permanently recorded in dead-letter queue'

  # Verdict bundle artifact assertions
  fge_assert_file FG-046B-E2E-030 "$verdict_ndjson" \
    'per-probe NDJSON verdicts artifact file is created'
  fge_assert_cmd FG-046B-E2E-031 \
    'verdict bundle contains at least 15 tested probes' \
    test "$(wc -l <"$verdict_ndjson")" -ge 15
  fge_assert_cmd FG-046B-E2E-032 \
    'verdict bundle contains zero fail verdicts' \
    test "$(grep -c '"verdict":"fail"' "$verdict_ndjson" || true)" -eq 0
}

fge_init webhook_ssrf_corpus
fge_context bead frankengit-fg046b-webhook-ssrf-rdro
fge_context suite webhook-ssrf-corpus
fge_context evidence_class local_exact
fge_context non_claim 'Adversarial validation runs within sandboxed pure-Rust engine; does not claim live WAN public internet connectivity.'
main
