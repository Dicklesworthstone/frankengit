#!/usr/bin/env bash
# Shipped protection CLI -> actual native policy admission and original outcomes.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-protection
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Basic policy-only SHA1/SHA256 fixture; no Git objects/oracle, branch writer enforcement, queue/candidate-check/DSL behavior, TLS, hostile isolation, hardware crash durability, current-native or every-operator qualification.'
fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ] || [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ] || ! command -v python3 >/dev/null; then
  fge_skip OPERATOR-PROTECTION-001 'A supplied prebuilt FG_BIN, pinned Node and Python 3 are required'
  exit 0
fi
fge_context binary_sha256 "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir operator-protection)"
SUMMARY="$WORK/summary.json"
fge_phase action
fge_run_timeout 420 campaign python3 "$E2E_ROOT/operator_protection_smoke.py" \
  --fg "$FG_BIN" --node "$NODE" --work "$WORK/campaign" --summary "$SUMMARY" || true
fge_assert_exit OPERATOR-PROTECTION-002 0 "$FGE_LAST_EXIT" 'actual protection CLI lifecycle and canonical Rust policy reads complete'
fge_phase assert
fact() {
  python3 - "$SUMMARY" "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding='utf-8') as source:
        summary = json.load(source)
    result = summary.get('complete') is True and summary.get('facts', {}).get(sys.argv[2]) is True
except (OSError, ValueError) as error:
    print(f'protection operator summary unavailable: {error}', file=sys.stderr)
    result = False
print(str(result).lower())
PY
}
for format in sha1 sha256; do
  for property in bootstrap_refusal_and_local_twin exact_inspect_and_readonly_prepare committed_change_and_canonical_policy stale_refusal_and_current_twin independent_grant_and_recovery_twins admin_rotation_and_current_authority original_key_terminal_cache_after_restart retained_intents_private_and_token_free disabled_scope_refuses_without_change owned_services_drained; do
    fge_assert_eq "OPERATOR-PROTECTION-$format-$property" true "$(fact "${format}_$property")" "native protection operator $property"
  done
done
if [ -f "$SUMMARY" ]; then fge_artifact "$SUMMARY" operator-protection-summary; fi
if [ -f "$WORK/campaign/commands.jsonl" ]; then fge_artifact "$WORK/campaign/commands.jsonl" native-operator-command-journal; fi
fge_phase teardown
