#!/usr/bin/env bash
# e2e: executes the FG-030c adversarial Agent Protocol corpus and preserves
# the real crate-test output as local exact evidence.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='agent_adversarial'
readonly RUN_OBLIGATION='fg030c-agent-adversarial-test-runner'

main() {
  local test_exit=0
  local output=''

  fge_phase setup
  fge_context bead frankengit-fg030c-agent-adversarial-diw
  fge_context suite agent-adversarial
  fge_context evidence_class local_exact
  fge_context non_claim 'the downstream channel is an in-process bounded model; this suite does not claim live-provider delivery or durable journal publication'

  fge_phase action
  fge_obligation_open "$RUN_OBLIGATION" RunnerSlot
  fge_capture agent-adversarial-tests \
    env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-agent --test "$TEST_NAME" -- --nocapture || test_exit=$?
  fge_obligation_close "$RUN_OBLIGATION"
  if [[ -n "${FGE_LAST_STDOUT_FILE:-}" && -f "${FGE_LAST_STDOUT_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDOUT_FILE" agent-adversarial-stdout
    output="$(<"${FGE_LAST_STDOUT_FILE}")"
  fi
  if [[ -n "${FGE_LAST_STDERR_FILE:-}" && -f "${FGE_LAST_STDERR_FILE}" ]]; then
    fge_artifact "$FGE_LAST_STDERR_FILE" agent-adversarial-stderr
  fi

  fge_phase assert
  fge_assert_exit 'FG-030C-E2E-001' 0 "$test_exit" \
    'the agent adversarial corpus test target completes successfully'
  fge_assert_contains 'FG-030C-E2E-002' "$output" \
    'untrusted_corpus_cannot_widen_effect_capabilities_or_request_secrets' \
    'repository and issue text cannot widen broker operations or obtain a secret handle'
  fge_assert_contains 'FG-030C-E2E-003' "$output" \
    'fabricated_evidence_identity_is_refused_by_the_real_evidence_verifier' \
    'a receipt whose claimed identity does not match its canonical bytes is refused'
  fge_assert_contains 'FG-030C-E2E-004' "$output" \
    'interrupted_external_effects_are_reconciled_or_explicitly_escalated_then_quiesced' \
    'an interrupted weak external effect escalates explicitly and settles only through named resolution'
}

fge_init fg030c-agent-adversarial
main
