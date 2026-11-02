#!/usr/bin/env bash
# Discovered operator/script module tests, including their real native child cells.
# The shared verifier owns the Node pin, VM flags, deadlines and process drain.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init operator-contract-tests
fge_kind js-unit
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'Existing module/schema-peer tests plus explicitly enabled native child cases; not every operator entrypoint against fg serve-http, a real browser, Git differential parity, D10 ratification or full/release evidence. TAP skips earn no coverage credit.'

fge_phase setup
NODE="${FGE_NODE:-$(command -v node || true)}"
if [ -z "$NODE" ]; then
  fge_skip OPERATOR-CONTRACT-001 'Node is absent; the pinned module profile cannot run'
  exit 0
fi
if [ -z "${FG_BIN:-}" ] || [ ! -x "$FG_BIN" ]; then
  fge_skip OPERATOR-CONTRACT-002 'FG_BIN must name a prebuilt native fg; native cases cannot be silently skipped'
  exit 0
fi
REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
fge_context node "$("$NODE" --version 2>&1)"
fge_context native_binary_sha256 "$(fge_digest_file "$FG_BIN")"
# verify.sh e2e builds this binary once. The existing tests otherwise skip
# their native bundle/import/backup/recovery cases because they use another key.
export FG_NATIVE_BIN="$FG_BIN"

fge_phase action
fge_capture operator-owner-selftests env FGE_NODE="$NODE" python3 "$E2E_ROOT/selftests/test_operator_command.py" || true
fge_phase assert
fge_assert_exit OPERATOR-CONTRACT-OWNER-001 0 "$FGE_LAST_EXIT" 'real-process operator owner success, refusal, interruption, timeout and forced-containment regressions complete'

for scope in operator scripts; do
  fge_phase action
  test_exit=0
  fge_capture "node-test-$scope" "$NODE" "$REPO_ROOT/scripts/verify_js.mjs" "$scope" || test_exit=$?
  fge_phase assert
  fge_assert_exit "OPERATOR-CONTRACT-$scope-001" 0 "$test_exit" "the complete $scope profile completed successfully"
  # Require the final counts rather than accepting an empty exit-zero command.
  # The original TAP remains an artifact; skipped native/oracle cells never
  # become passing cells merely because the module process returned zero.
  summary_exit=0
  summary=$(python3 - "$FGE_LAST_STDOUT_FILE" <<'PY'
import re
import sys
from pathlib import Path

counts = {}
for line in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    match = re.fullmatch(r'# (tests|pass|fail|cancelled|skipped|todo) ([0-9]+)', line)
    if match:
        name, value = match.groups()
        if name in counts:
            raise SystemExit('duplicate TAP summary counter: ' + name)
        counts[name] = int(value)
required = {'tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'}
if counts.keys() != required or counts['tests'] == 0 or counts['pass'] == 0:
    raise SystemExit('missing, empty or entirely skipped TAP corpus')
if any(counts[name] for name in ('fail', 'cancelled', 'todo')):
    raise SystemExit('non-passing TAP corpus: ' + str(counts))
if counts['tests'] != counts['pass'] + counts['skipped']:
    raise SystemExit('inconsistent TAP summary counters')
print(' '.join(name + '=' + str(counts[name]) for name in sorted(counts)))
PY
  ) || summary_exit=$?
  fge_context "tap_summary_$scope" "$summary"
  fge_assert_exit "OPERATOR-CONTRACT-$scope-002" 0 "$summary_exit" "nonempty terminal $scope TAP counters are complete and contain no failures"
done
fge_phase teardown
