#!/usr/bin/env bash
# e2e: Materialize real sparse TreeFS workspaces, enforce host safety/refusals, contain timeouts, and share immutable bases across parallel batch runs (frankengit-audit-treefs-host-zb0q).
set -euo pipefail

if [[ -z "${FG_BIN:-}" || ! -x "$FG_BIN" ]]; then
    printf '%s\n' 'sparse_workspace_host requires a prebuilt native Linux FG_BIN' >&2
    exit 2
fi

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init treefs-sparse-workspace-host
fge_kind e2e-binary
fge_context bead frankengit-audit-treefs-host-zb0q
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context host_profile linux-openat2-v2
fge_context non_claim 'Linux openat2 + verified FICLONE-or-copy trusted local tool profile; no FUSE, cross-platform host parity, or hostile-process namespace isolation is claimed.'

fge_phase setup
WORK="$(fge_tempdir treefs-sparse-host)"
EXTRA_ARGS=()
if [[ -n "${FGIT_SHARED_WORKSPACE_TEST_ROOT:-}" && -d "${FGIT_SHARED_WORKSPACE_TEST_ROOT}" ]]; then
    PARENT_ROOT="${FGIT_SHARED_WORKSPACE_TEST_ROOT}/fge-zb0q-$$"
    mkdir -m 0700 -p "$PARENT_ROOT"
    fge_cleanup_register python3 -c 'import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)' "$PARENT_ROOT"
    EXTRA_ARGS=(--parent-root "$PARENT_ROOT")
fi

fge_phase action
fge_resource_mark before_campaign
fge_run_timeout 240 ZB0Q-CAMPAIGN python3 "$E2E_ROOT/helpers/sparse_workspace_host.py" --fg "$FG_BIN" --work "$WORK" "${EXTRA_ARGS[@]}" || true
campaign_rc="$FGE_LAST_EXIT"
fge_resource_mark after_campaign

fge_phase assert
fge_assert_exit ZB0Q-AC1-MATERIALIZE-EXPORT-APPLY-REOPEN 0 "$campaign_rc" "SHA-1 and SHA-256 sparse materialization, tool execution, candidate export, canonical apply, and reopen verification"
fge_assert_file ZB0Q-AC2-HOST-BOUNDARY-REPORT "$WORK/zb0q_report.json" "structured report emitted for canonical symlink/gitlink refusals, symlink-output/hardlink/undeclared/permission boundaries, and permitted twins"
fge_assert_ndjson ZB0Q-AC3-INVOCATION-NDJSON "$WORK/zb0q_steps.ndjson" "every CLI step exit and bounded timeout/containment/recovery check recorded as valid NDJSON"
fge_assert_dir ZB0Q-AC3-CONTAINED-WORKSPACE-SHA1 "$WORK/ac3-sha1-private/workspace-c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3" "timed-out SHA-1 workspace retained for operator reconciliation"
fge_assert_no_file ZB0Q-AC3-NO-PARTIAL-BUNDLE-SHA1 "$WORK/ac3-sha1-private/timeout.bundle" "timed-out SHA-1 workspace published no partial bundle"
fge_assert_dir ZB0Q-AC3-CONTAINED-WORKSPACE-SHA256 "$WORK/ac3-sha256-private/workspace-c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3" "timed-out SHA-256 workspace retained for operator reconciliation"
fge_assert_no_file ZB0Q-AC3-NO-PARTIAL-BUNDLE-SHA256 "$WORK/ac3-sha256-private/timeout.bundle" "timed-out SHA-256 workspace published no partial bundle"
fge_assert_contains ZB0Q-AC4-SHARED-BATCH-TELEMETRY "$(cat "$WORK/zb0q_report.json" 2>/dev/null || true)" '"prefer_cache"' "parallel shared-base batch telemetry and destroy/rebuild equivalence recorded"

if [[ -f "$WORK/zb0q_report.json" ]]; then
    fge_artifact "$WORK/zb0q_report.json" zb0q_report
fi
if [[ -f "$WORK/zb0q_steps.ndjson" ]]; then
    fge_artifact "$WORK/zb0q_steps.ndjson" zb0q_steps
fi
