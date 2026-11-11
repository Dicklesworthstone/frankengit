#!/usr/bin/env bash
# e2e: Native discussion lifecycle, independent issue state, retained pages and original outcome recovery.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-discussions
fge_kind e2e-binary
fge_context bead frankengit-fg045-issues-notifications-n70
fge_phase setup
fge_assert_cmd DISCUSSION-PREBUILT 'FG_BIN names the prebuilt native fg' test -x "${FG_BIN:-}"
if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    fge_die 'FG_BIN must name the prebuilt native fg'
fi
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir native-discussions)"
fge_phase action
fge_run_timeout 600 DISCUSSION-CAMPAIGN python3 "$E2E_ROOT/helpers/discussions.py" --fg "$FG_BIN" --work "$WORK" || true
fge_assert_exit DISCUSSION-EXIT 0 "$FGE_LAST_EXIT"
fge_phase assert
fge_assert_file DISCUSSION-RESULTS "$WORK/results.json"
if [[ -f "$WORK/results.json" ]]; then
    fge_artifact "$WORK/results.json" native_discussion_results
fi
for format in sha1 sha256; do
    for criterion in LIFECYCLE LOCK-REFUSAL STALE-REFUSAL KEY-REUSE RESTART-RECOVERY \
        PINNED-PAGES PIN-REQUIRED ISSUE-ISOLATION LITERAL-TEXT PARSER-BEFORE-IO BODY-REFUSAL MISSING \
        APPEND-PRESERVES-CHANGES APPEND-LOCK-STRICT-TWINS APPEND-ORIGINAL-RECOVERY; do
        fge_assert_cmd "DISCUSSION-$format-$criterion" "native $format $criterion" \
            python3 -c 'import json,sys; rows=json.load(open(sys.argv[1])); row=next(r for r in rows if r["format"] == sys.argv[2]); assert row["result"] == "passed" and sys.argv[3] in row["checks"]' \
            "$WORK/results.json" "$format" "$criterion"
    done
done
