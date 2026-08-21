#!/usr/bin/env bash
# e2e: runs the FG-079 canonical compaction, crash, epoch, and retention drill.
#
# The suite is discovered recursively by scripts/e2e/run_all.sh. It owns no
# registration list and shells out only through the repository-owned Rust test
# target, whose assertions cover the authority publication rather than a local
# compaction index.
set -euo pipefail

CP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CP_REPO=$(cd "$CP_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CP_REPO/scripts/e2e/lib.sh"

readonly CP_TEST="$CP_REPO/crates/fgit-compaction/tests/compaction_protocol.rs"

fge_init fg079-compaction-protocol
fge_context bead frankengit-fg079-compaction-protocol-8v5g
fge_context crate fgit-compaction
fge_context authority_path ordinary_decision_batch_and_authority_head_cas
fge_context non_claim 'The conservative interim profile has no performance claim; numeric layout sizes and a compaction trigger remain measurement-gated by ADR-0004.'
fge_context non_claim 'This reference drill proves protocol behavior only. It does not establish durable-media fault tolerance beyond the supplied epoch and authenticated-retention witnesses.'

# Builds must stay in this checkout so the harness records artifacts created by
# the target it actually invoked (AGENTS.md 16.2).
export RCH_CARGO_WRAPPER_BYPASS=1

fge_phase setup
fge_assert_file FG-079-E2E-001 "$CP_TEST" 'the compaction protocol drill is present'
fge_artifact "$CP_TEST" compaction-protocol-drill

fge_phase action
fge_capture compaction-protocol \
  cargo test --locked -p fgit-compaction --test compaction_protocol || cp_exit=$?
cp_exit=${cp_exit:-0}
cp_output=''
if [ -n "${FGE_LAST_STDOUT_FILE:-}" ] && [ -f "$FGE_LAST_STDOUT_FILE" ]; then
  fge_artifact "$FGE_LAST_STDOUT_FILE" compaction-protocol-stdout
  cp_output=$(<"$FGE_LAST_STDOUT_FILE")
fi

fge_phase assert
fge_assert_exit FG-079-E2E-010 0 "$cp_exit" \
  'the decision-log and segment-compaction protocol drill passes'
fge_assert_contains FG-079-E2E-011 "$cp_output" \
  'interrupted_output_or_unpublished_staging_leaves_the_old_authority_head_complete' \
  'crash during output and after staging before publication leave the old complete head'
fge_assert_contains FG-079-E2E-012 "$cp_output" \
  'ordinary_decision_makes_complete_generation_visible_then_durable_retention_controls_deletion' \
  'visible and durable epochs stay distinct and deletion requires authenticated retention'
fge_assert_contains FG-079-E2E-013 "$cp_output" \
  'publication_without_rcr_evidence_link_stays_staged_even_when_batch_evidence_matches' \
  'an index-like evidence root without the ordinary RCR link cannot publish a generation'
