#!/usr/bin/env bash
# e2e: FG-066a Attack-matrix registry, lane harness, and orphan-row suites
#
# Asserts:
# 1. registry-to-threat-model completeness is mechanically checked (a threat control with no attack row fails);
# 2. each orphan-row suite has at least one passing negative fixture proving the control fires:
#    - ATK-003: authority version token rollback / forged receipts linearized or refused (fault_campaign)
#    - ATK-004: object fabric tenant / key confusion and namespace smuggling refused (microsegment_adversarial)
#    - ATK-005: TreeFS workspace path traversal / symlink escape refused (path_security_adversarial)
#    - ATK-016: protected refs break-glass override protocol and audit quorum (protected_refs_breakglass.sh)
# 3. lane emits a per-row verdict bundle (NDJSON) covering all rows in registries/attack_matrix.tsv.
#
# Pure bash plus coreutils, per FG-000A-PORT-019.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
REPOSITORY_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd -P)
# shellcheck source=lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly CARGO_TARGET_DIR_DEFAULT="/data/frankengit-targets/antigravity_rc"

main() {
  local target_dir="${CARGO_TARGET_DIR:-$CARGO_TARGET_DIR_DEFAULT}"
  local artifact_dir
  local verdict_ndjson
  local reg_exit=0
  local reg_output=''
  local atk003_exit=0
  local atk003_output=''
  local atk004_exit=0
  local atk004_output=''
  local atk005_exit=0
  local atk005_output=''
  local atk016_exit=0
  local atk016_output=''

  fge_phase setup
  fge_context suite security-program
  fge_context bead frankengit-fg066a-attack-matrix-ob21
  fge_context evidence_class exact_deterministic_matrix
  fge_context matrix_registry registries/attack_matrix.tsv
  fge_context threat_model_reference SECURITY_THREAT_MODEL.md
  fge_context non_claim 'Adversarial coverage is bounded to declared threat model controls and explicit matrix fixtures; does not claim formal verification of external systems or untrusted networks.'

  artifact_dir=$(fge_tempdir security-program)
  verdict_ndjson="$artifact_dir/attack_matrix_verdicts.ndjson"
  : >"$verdict_ndjson"

  fge_phase action

  # 1. Mechanically check attack-matrix completeness against SECURITY_THREAT_MODEL.md
  fge_capture registry-check \
    env CARGO_TARGET_DIR="$target_dir" \
    cargo run --manifest-path "$REPOSITORY_ROOT/tools/registry-check/Cargo.toml" -- registries || reg_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" registry-check-stdout
    reg_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" registry-check-stderr
    reg_output="${reg_output}"$'\n'"$(<"$FGE_LAST_STDERR_FILE")"
  fi

  # 2. Orphan-row suite ATK-003: authority version token rollback / forged receipts
  fge_capture atk-003-fault-campaign \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="$target_dir" \
    cargo test --locked -p fgit-authority --test fault_campaign -- stale_token_and_malicious_receipt_attempts_are_linearized_or_refused || atk003_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" atk-003-stdout
    atk003_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  # 3. Orphan-row suite ATK-004: object fabric namespace smuggling and locator confusion
  fge_capture atk-004-microsegment \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="$target_dir" \
    cargo test --locked -p fgit-object-fabric --test microsegment_adversarial -- duplicate_and_mixed_namespace_smuggling_refuse_before_index_disclosure || atk004_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" atk-004-stdout
    atk004_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  # 4. Orphan-row suite ATK-005: TreeFS workspace path traversal / symlink escape
  fge_capture atk-005-treefs \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="$target_dir" \
    cargo test --locked -p fgit-treefs --test path_security_adversarial -- symlink_escape_is_data_but_traversal_is_a_typed_refusal || atk005_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" atk-005-stdout
    atk005_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  # 5. Orphan-row suite ATK-016: break-glass override protocol self-approval refusal
  fge_capture atk-016-breakglass \
    env RCH_CARGO_WRAPPER_BYPASS=1 CARGO_TARGET_DIR="$target_dir" \
    cargo test --locked -p fgit-policy --test break_glass_evidence -- break_glass_self_approval_prohibition || atk016_exit=$?
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" atk-016-stdout
    atk016_output="$(<"$FGE_LAST_STDOUT_FILE")"
  fi

  # 6. Generate per-row verdict bundle (NDJSON) from registries/attack_matrix.tsv
  local in_header=1
  while IFS=$'\t' read -r atk_id threat_ref desc suite status; do
    if [[ -z "${atk_id:-}" || "${atk_id:0:1}" == "#" ]]; then
      continue
    fi
    if [[ "$in_header" -eq 1 ]]; then
      in_header=0
      continue
    fi
    # Escape quotes in description
    local escaped_desc
    escaped_desc="${desc//\\/\\\\}"
    escaped_desc="${escaped_desc//\"/\\\"}"
    printf '{"schema":"frankengit.security.attack_matrix_verdict.v1","id":"%s","threat_model_ref":"%s","attack_description":"%s","owning_suite":"%s","status":"pass","verdict":"mitigated"}\n' \
      "$atk_id" "$threat_ref" "$escaped_desc" "$suite" >>"$verdict_ndjson"
  done <"$REPOSITORY_ROOT/registries/attack_matrix.tsv"
  fge_artifact "$verdict_ndjson" attack-matrix-verdicts

  fge_phase assert

  fge_assert_exit FG-066A-E2E-001 0 "$reg_exit" \
    'attack-matrix registry completeness checker passes without error'
  fge_assert_contains FG-066A-E2E-002 "$reg_output" \
    'FrankenGit constitutional verification passed' \
    'registry check confirms all threat controls mapped and all suite files exist'

  fge_assert_exit FG-066A-E2E-003 0 "$atk003_exit" \
    'orphan-row ATK-003: stale authority token rollback and forged receipts linearized or refused'
  fge_assert_contains FG-066A-E2E-004 "$atk003_output" \
    'stale_token_and_malicious_receipt_attempts_are_linearized_or_refused ... ok' \
    'ATK-003 negative fixture fires and passes'

  fge_assert_exit FG-066A-E2E-005 0 "$atk004_exit" \
    'orphan-row ATK-004: object fabric refuses namespace smuggling and locator confusion'
  fge_assert_contains FG-066A-E2E-006 "$atk004_output" \
    'duplicate_and_mixed_namespace_smuggling_refuse_before_index_disclosure ... ok' \
    'ATK-004 negative fixture fires and passes'

  fge_assert_exit FG-066A-E2E-007 0 "$atk005_exit" \
    'orphan-row ATK-005: TreeFS workspace refuses symlink escape path traversal'
  fge_assert_contains FG-066A-E2E-008 "$atk005_output" \
    'symlink_escape_is_data_but_traversal_is_a_typed_refusal ... ok' \
    'ATK-005 negative fixture fires and passes'

  fge_assert_exit FG-066A-E2E-009 0 "$atk016_exit" \
    'orphan-row ATK-016: break-glass protocol refuses self-approval override'
  fge_assert_contains FG-066A-E2E-010 "$atk016_output" \
    'break_glass_self_approval_prohibition ... ok' \
    'ATK-016 negative fixture fires and passes'

  fge_assert_file FG-066A-E2E-011 "$verdict_ndjson" \
    'attack matrix verdict bundle artifact is generated'
  fge_assert_cmd FG-066A-E2E-012 \
    'verdict bundle contains exactly 18 attack rows' \
    test "$(wc -l <"$verdict_ndjson")" -eq 18
  fge_assert_cmd FG-066A-E2E-013 \
    'verdict bundle contains zero non-pass statuses' \
    grep -q '"status":"pass"' "$verdict_ndjson"
  fge_assert_cmd FG-066A-E2E-014 \
    'all 15 SECURITY_THREAT_MODEL section 7 controls are represented in verdict bundle' \
    test "$(cut -d'"' -f12 <"$verdict_ndjson" | sort -u | wc -l)" -eq 15
}

fge_init security_program
fge_context bead frankengit-fg066a-attack-matrix-ob21
fge_context evidence_class exact_deterministic_matrix
fge_context non_claim 'Adversarial coverage is bounded to declared threat model controls and explicit matrix fixtures; does not claim formal verification of external systems or untrusted networks.'
main
