#!/usr/bin/env bash
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-remote-branch-transaction
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.81
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-BRANCH-TRANSACTION-001 'A prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir operator-remote-branch-transaction)"
fge_phase action
fge_run_timeout 360 campaign python3 "$E2E_ROOT/operator_branch_transaction_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK" || true
fge_assert_exit OPERATOR-BRANCH-TRANSACTION-002 0 "$FGE_LAST_EXIT" 'Native split-grant branch transactions complete'
fge_phase assert
for format in sha1 sha256; do
  if [ -f "$WORK/$format-terminal.json" ]; then
    fge_artifact "$WORK/$format-terminal.json" "operator-branch-$format-terminal"
  else
    fge_fail "OPERATOR-BRANCH-TRANSACTION-$format" "Missing native $format terminal commit and refusal"
  fi
done
if [ -f "$WORK/commands.jsonl" ]; then
  fge_artifact "$WORK/commands.jsonl" operator-and-native-command-journal
fi
fge_phase teardown
