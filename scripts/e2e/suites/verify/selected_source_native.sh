#!/usr/bin/env bash
# Actual source-package CLI/API and native HTTP/proof consumers, no Cargo build.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ROOT="$(cd "$E2E_ROOT/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init selected-source-native
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'One operator entrypoint; supplied prebuilt binary, generated saved context, four explicit peer/provider controls and two real native scenarios; no new Rust build, search oracle, retained authority-proof package or full operator lane.'
fge_phase setup
FG_BIN="${FG_BIN:-}"
NODE="${FGE_NODE:-$(command -v node || true)}"
fge_assert_cmd NATIVE-PACKAGE-001 'FG_BIN is a supplied executable' test -x "$FG_BIN"
[[ "$FG_BIN" = /* && -x "$FG_BIN" && -x "$NODE" ]] || fge_die 'Absolute qualified FG_BIN and pinned Node are required'
fge_assert_eq NATIVE-PACKAGE-002 "v$(cat "$ROOT/tests/node-version")" "$("$NODE" --version)" 'Node matches the repository pin'
[[ "$("$NODE" --version)" = "v$(cat "$ROOT/tests/node-version")" ]] || fge_die 'Node version differs from the repository pin'
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
WORK="$(fge_tempdir native-package)"
fge_phase action
FGE_MAX_CAPTURE=16384 fge_capture native-package-tap fge_run_timeout 480 native-package env FG_NATIVE_BIN="$FG_BIN" TMPDIR="$WORK" \
  "$NODE" --test --test-reporter=tap "$ROOT/scripts/tests/source_package_native.test.mjs" || true
RC=$FGE_LAST_EXIT
OUTPUT=$FGE_LAST_STDOUT
fge_phase assert
fge_assert_eq NATIVE-PACKAGE-003 0 "$RC" 'Actual native capture/refusal/cancellation scenarios and owned server drains complete'
fge_assert_contains NATIVE-PACKAGE-004 "$OUTPUT" '# pass 6' 'All six declared test scenarios passed'
fge_assert_contains NATIVE-PACKAGE-005 "$OUTPUT" '# fail 0' 'No test scenario failed'
fge_assert_contains NATIVE-PACKAGE-006 "$OUTPUT" '# skipped 0' 'Real native scenarios were executed, not skipped'
fge_assert_contains NATIVE-PACKAGE-007 "$OUTPUT" 'sha1: real native proofs gate package publication and offline interchange' 'SHA1 native scenario discovered'
fge_assert_contains NATIVE-PACKAGE-008 "$OUTPUT" 'sha256: real native proofs gate package publication and offline interchange' 'SHA256 native scenario discovered'
