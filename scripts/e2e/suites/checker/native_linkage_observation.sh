#!/usr/bin/env bash
# Consumer: the constitution/release verifier. Observed defect: the pinned
# Cargo run/stdout layout was invisible even after a real build. Retire this
# layout-specific cell when the supported Cargo layouts are superseded.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
. "$E2E_ROOT/lib.sh"
fge_init native-linkage-observation
fge_context bead frankengit-audit-native-linkage-l0xt
fge_context non_claim 'cached build-script inspection is not a current release attestation'

fge_phase setup
export RCH_CARGO_WRAPPER_BYPASS=1
export CARGO_TARGET_DIR="$(fge_tempdir native-linkage-target)"
export CARGO_NET_OFFLINE=true
export FGIT_LINKAGE_PROFILE=debug
unset CARGO_BUILD_TARGET

# Build real admitted dependencies in the private target. No fixture build.rs
# or production registry relaxation supplies the positive result.
fge_capture dependency-build cargo check --locked -p fgit-object-store -p fgit-authority-fsqlite || true
fge_assert_exit FG-AUDIT-LINKAGE-001 0 "$FGE_LAST_EXIT" 'real dependencies compile in a fresh private target'
fge_capture checker-build cargo build --locked -p fgit-registry-check || true
fge_assert_exit FG-AUDIT-LINKAGE-002 0 "$FGE_LAST_EXIT" 'the assessed checker binary builds'
CHECKER="$CARGO_TARGET_DIR/debug/fgit-registry-check"

fge_phase action
fge_capture current-observation "$CHECKER" constitution || true
fge_assert_exit FG-AUDIT-LINKAGE-003 0 "$FGE_LAST_EXIT" 'the admitted dependency graph satisfies constitution'
fge_assert_contains FG-AUDIT-LINKAGE-004 "$(cat "$FGE_LAST_STDOUT_FILE" "$FGE_LAST_STDERR_FILE")" \
  'native-linkage policy evaluated against cached build-script observations' \
  'actual build output reaches linkage policy evaluation'

# Only this suite's private output is altered. The parser and policy are the
# production implementation, and the original positive case precedes it.
OUTPUT=$(python3 - "$CARGO_TARGET_DIR" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1]) / 'debug' / 'build'
paths = sorted(root.glob('crc32c/*/run/stdout'))
paths += sorted(root.glob('crc32c/*/output'))
paths += sorted(root.glob('crc32c-*/output'))
if not paths:
    raise SystemExit('real crc32c build-script output was not produced')
print(paths[0])
PY
)
printf '\ncargo::rustc-link-lib=static=fgit_planted_foreign_engine\n' >> "$OUTPUT"
fge_capture forbidden-observation "$CHECKER" constitution || true
fge_assert_exit FG-AUDIT-LINKAGE-005 1 "$FGE_LAST_EXIT" 'a forbidden emission from the same enabled package is refused'
fge_assert_contains FG-AUDIT-LINKAGE-006 "$(cat "$FGE_LAST_STDOUT_FILE" "$FGE_LAST_STDERR_FILE")" \
  'fgit_planted_foreign_engine' 'the refusal identifies the planted foreign linkage'
fge_phase assert
