#!/usr/bin/env bash
# e2e: real CLI/HTTP additive labels and durable recovery in both hash formats.
# Bead: frankengit-root-doctrine-x2mv.4.39 (bounded additive-intent slice)
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init issue-labels
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.39
fge_context evidence_class e2e_binary_cli_http
fge_context non_claim 'One persisted native node; strict label replacement remains versioned. No general CRDT, multi-node throughput or tracker-closure claim.'
fge_phase setup
FG_BIN="${FG_BIN:-}"
fge_assert_cmd IL-001 'FG_BIN names a prebuilt fg binary' test -x "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
WORK="$(fge_tempdir issue-labels)"
field() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$SUMMARY" "$1"
}
fge_phase action
for format in sha1 sha256; do
  SUMMARY="$WORK/$format.json"
  fge_run_timeout 900 "campaign-$format" python3 "$E2E_ROOT/issue_labels_smoke.py" \
    --fg "$FG_BIN" --root "$WORK/$format" --summary "$SUMMARY" --object-format "$format" || true
  fge_assert_exit "IL-$format-002" 0 "$FGE_LAST_EXIT" 'CLI, concurrent labels, refusal twins and restart recovery complete'
  if [ -f "$SUMMARY" ]; then
    fge_context "campaign_artifacts_$format" "$(field artifacts)"
    fge_assert_eq "IL-$format-010" 8 "$(field concurrent_additions)" 'eight independent overlapping additions commit'
    ordinal=11
    for property in cli_typed_profile cli_union_exact cli_retry_exact cli_retry_publishes_nothing \
      cli_removal_exact cli_recovery_does_not_readd typed_profiles transactions_unique union_exact \
      one_event_per_addition label_history_exact unrelated_fields_preserved same_server_retries \
      retries_publish_nothing strict_stale_refuses scope_refuses version_field_refuses \
      changed_key_refuses missing_issue_refuses refusals_preserve_issue exact_bound_commits \
      overflow_refuses overflow_preserves_issue overlap_at_bound_commits removal_exact \
      old_outcome_does_not_readd restart_preserves_state restart_retries_original \
      restart_retries_publish_nothing refused_outcome_survives_restart refused_retry_preserves_state \
      new_intent_uses_freed_capacity services_drained; do
      fge_assert_eq "IL-$format-$ordinal" True "$(field "$property")" "$property"
      ordinal=$((ordinal + 1))
    done
  fi
done
fge_phase teardown
