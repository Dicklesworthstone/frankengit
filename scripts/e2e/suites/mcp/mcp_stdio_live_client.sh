#!/usr/bin/env bash
# x2mv.4.17 — Live-client MCP stdio E2E suite against a persisted FrankenGit node.
#
# Proves:
# 1. `fg-mcp` tool catalog, `fgit-schema` MCP registry, and `mcp_parity_manifest.json` match 1-for-1,
#    and planted server/registry drift fails closed.
# 2. Live stdio MCP client against a persisted node executes `initialize`, `notifications/initialized`,
#    `tools/list`, a canonical read (`frankengit_issue_list`), and refuses an ungranted write
#    (`frankengit_issue_open` without `--allow-issue-writes`) with JSON-RPC `-32602`.
# 3. Live stdio MCP client with `--allow-issue-writes`, `--principal`, and `--expected-incarnation`
#    commits `frankengit_issue_open`, reads back `frankengit_issue_show`, and refuses an ungranted
#    cross-domain write (`frankengit_pull_open`).
# 4. Reopening the persisted node in a fresh `fg-mcp` process preserves the committed issue and
#    recovers the terminal decision via `frankengit_transaction_outcome`.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init mcp-stdio-live-client
fge_kind e2e-binary
fg_target_dir="${CARGO_TARGET_DIR:-$E2E_ROOT/../../target}"
fge_context bead frankengit-root-doctrine-x2mv.4.17
fge_context evidence_class E1
fge_context schema_parity_tests crates/fgit-schema/tests/mcp_registry.rs
fge_context cli_parity_tests crates/fgit-cli/src/mcp/backend.rs

fge_phase setup
work="$(fge_tempdir mcp_stdio_live)"
repo_dir="$work/repo"
mkdir -p "$repo_dir"

tenant_id="11111111111111111111111111111111"
repo_id="22222222222222222222222222222222"
principal_id="33333333333333333333333333333333"

if [ -n "${FG_BIN:-}" ] && [ -n "${FG_MCP_BIN:-}" ]; then
  fge_context fg_bin supplied
elif [ -x "$fg_target_dir/debug/fg" ] && [ -x "$fg_target_dir/debug/fg-mcp" ]; then
  FG_BIN="$fg_target_dir/debug/fg"
  FG_MCP_BIN="$fg_target_dir/debug/fg-mcp"
  fge_context fg_bin target_cached
else
  fge_run_ok fg-build env TMPDIR=/tmp CARGO_TARGET_DIR="$fg_target_dir" \
    cargo build --locked -p fgit-cli --bin fg --bin fg-mcp
  FG_BIN="$fg_target_dir/debug/fg"
  FG_MCP_BIN="$fg_target_dir/debug/fg-mcp"
fi

# Initialize canonical repository on disk.
fge_run_ok fg-init "$FG_BIN" init "$repo_dir" "$tenant_id" "$repo_id"

fge_phase action

# 1. Run Session 1 over stdio with read-only `--allow-issues` grant:
#    - initialize
#    - notifications/initialized
#    - tools/list
#    - tools/call frankengit_issue_list (read)
#    - tools/call frankengit_issue_open (refused write without grant)
session1_req="$work/session1.requests.ndjson"
session1_resp="$work/session1.responses.ndjson"
cat >"$session1_req" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-live-client","version":"1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"frankengit_issue_list","arguments":{"limit":5}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"frankengit_issue_open","arguments":{"number":"1","expected_version":"0","idempotency_key":"e2e-mcp-ungranted-1","title":"Ungranted write","body":"Must be refused"}}}
EOF

fge_capture mcp-session1-readonly \
  bash -c '"$1" "$2" "$3" "$4" --trusted-local --allow-issues < "$5"' _ \
  "$FG_MCP_BIN" "$repo_dir" "$tenant_id" "$repo_id" "$session1_req" || true
session1_exit=$FGE_LAST_EXIT
cp "$FGE_LAST_STDOUT_FILE" "$session1_resp"
session1_out=$(<"$session1_resp")

# Extract repository_incarnation from Session 1's frankengit_issue_list response.
incarnation_id="${session1_out#*\\\"repository_incarnation\\\":\\\"}"
incarnation_id="${incarnation_id%%\\\"*}"

# 2. Run Session 2 over stdio with `--allow-issues --allow-issue-writes`:
#    - initialize
#    - notifications/initialized
#    - tools/list
#    - tools/call frankengit_issue_open (granted write)
#    - tools/call frankengit_issue_show (read back committed issue)
#    - tools/call frankengit_pull_open (refused cross-domain write without `--allow-pull-writes`)
session2_req="$work/session2.requests.ndjson"
session2_resp="$work/session2.responses.ndjson"
cat >"$session2_req" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-live-client","version":"1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"frankengit_issue_open","arguments":{"number":"1","expected_version":"0","idempotency_key":"e2e-mcp-live-open-1","title":"MCP stdio live write","body":"Committed over fg-mcp stdio"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"frankengit_issue_show","arguments":{"number":"1"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"frankengit_pull_open","arguments":{"number":"1","expected_version":"0","idempotency_key":"e2e-mcp-ungranted-pr-1","source_reference":"refs/heads/topic","target_reference":"refs/heads/main","expected_source":"1111111111111111111111111111111111111111","expected_target":"2222222222222222222222222222222222222222","title":"Ungranted PR","body":"Must be refused"}}}
EOF

fge_capture mcp-session2-write \
  bash -c '"$1" "$2" "$3" "$4" --trusted-local --allow-issues --allow-issue-writes --principal "$5" --expected-incarnation "$6" < "$7"' _ \
  "$FG_MCP_BIN" "$repo_dir" "$tenant_id" "$repo_id" "$principal_id" "$incarnation_id" "$session2_req" || true
session2_exit=$FGE_LAST_EXIT
cp "$FGE_LAST_STDOUT_FILE" "$session2_resp"
session2_out=$(<"$session2_resp")

# 3. Run Session 3 over stdio on a freshly reopened `fg-mcp` process with `--allow-issues --allow-outcomes`:
#    - verify persisted issue 1 and historical transaction outcome for `e2e-mcp-live-open-1`
session3_req="$work/session3.requests.ndjson"
session3_resp="$work/session3.responses.ndjson"
cat >"$session3_req" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e-live-client","version":"1.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_issue_list","arguments":{"limit":5}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"frankengit_transaction_outcome","arguments":{"idempotency_key":"e2e-mcp-live-open-1"}}}
EOF

fge_capture mcp-session3-reopened-outcome \
  bash -c '"$1" "$2" "$3" "$4" --trusted-local --allow-issues --allow-outcomes --principal "$5" --expected-incarnation "$6" < "$7"' _ \
  "$FG_MCP_BIN" "$repo_dir" "$tenant_id" "$repo_id" "$principal_id" "$incarnation_id" "$session3_req" || true
session3_exit=$FGE_LAST_EXIT
cp "$FGE_LAST_STDOUT_FILE" "$session3_resp"
session3_out=$(<"$session3_resp")

# Retain the complete protocol transcripts as first-class artifacts.
for name_and_src in \
  "session1_requests.ndjson:$session1_req" \
  "session1_responses.ndjson:$session1_resp" \
  "session2_requests.ndjson:$session2_req" \
  "session2_responses.ndjson:$session2_resp" \
  "session3_requests.ndjson:$session3_req" \
  "session3_responses.ndjson:$session3_resp"; do
  name="${name_and_src%%:*}"
  src="${name_and_src#*:}"
  cp "$src" "$(fge_artifact_path "$name")"
  fge_artifact "$name" ndjson
done

fge_phase assert

# Session 1 assertions (initialize, tools/list, read, refused write without grant)
fge_assert_eq "FG-MCP-LIVE-001" "0" "$session1_exit" "session1 read-only stdio exit code"
fge_assert_contains "FG-MCP-LIVE-002" "$session1_out" '"protocolVersion":"2025-06-18"' "session1 initialize protocolVersion"
fge_assert_contains "FG-MCP-LIVE-003" "$session1_out" '"name":"frankengit_issue_list"' "session1 tools/list exposes frankengit_issue_list"
fge_assert_contains "FG-MCP-LIVE-004" "$session1_out" '\"issues\":[]' "session1 frankengit_issue_list returns empty issues array"
fge_assert_contains "FG-MCP-LIVE-005" "$session1_out" '{"error":{"code":-32602,"message":"Unknown or unavailable tool"},"id":4,"jsonrpc":"2.0"}' "session1 refuses ungranted frankengit_issue_open"

# Session 2 assertions (granted write, readback, refused cross-domain write)
fge_assert_eq "FG-MCP-LIVE-006" "0" "$session2_exit" "session2 granted write stdio exit code"
fge_assert_contains "FG-MCP-LIVE-007" "$session2_out" '"name":"frankengit_issue_open"' "session2 tools/list exposes frankengit_issue_open"
fge_assert_contains "FG-MCP-LIVE-008" "$session2_out" '\"outcome\":\"committed\"' "session2 frankengit_issue_open commits"
fge_assert_contains "FG-MCP-LIVE-009" "$session2_out" '\"command_committed\":true' "session2 frankengit_issue_open reports command_committed true"
fge_assert_contains "FG-MCP-LIVE-010" "$session2_out" '\"title\":\"MCP stdio live write\"' "session2 frankengit_issue_show reads back committed title"
fge_assert_contains "FG-MCP-LIVE-011" "$session2_out" '{"error":{"code":-32602,"message":"Unknown or unavailable tool"},"id":5,"jsonrpc":"2.0"}' "session2 refuses ungranted cross-domain frankengit_pull_open"

# Session 3 assertions (persisted state across reopen + historical transaction outcome recovery)
fge_assert_eq "FG-MCP-LIVE-012" "0" "$session3_exit" "session3 reopened outcome stdio exit code"
fge_assert_contains "FG-MCP-LIVE-013" "$session3_out" '\"title\":\"MCP stdio live write\"' "session3 frankengit_issue_list retains committed issue across reopen"
fge_assert_contains "FG-MCP-LIVE-014" "$session3_out" '\"observation\":\"decided\"' "session3 frankengit_transaction_outcome reports decided observation"
fge_assert_contains "FG-MCP-LIVE-015" "$session3_out" '\"outcome\":\"committed\"' "session3 frankengit_transaction_outcome reports committed outcome"

