#!/usr/bin/env bash
# Tier A (frankengit-root-doctrine-x2mv.4.60): ordinary import, clone, fetch and
# push through `fg serve`, run differentially against the pinned upstream Git
# oracle. registries/compatibility_tiers.tsv declares the rows; every row below
# is asserted from scripts/e2e/helpers/tier_a_differential.py's per-check
# results. Upstream Git runs only through scripts/e2e/oracle/oracle.sh.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REPOSITORY_ROOT="$(cd "${E2E_ROOT}/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init tier-a-git-daemon-differential
fge_kind pinned-oracle
fge_context bead frankengit-root-doctrine-x2mv.4.60
fge_context non_claim 'Tier A covers git:// loopback service only: no smart HTTP, SSH, partial clone, LFS, signed push or general Git-compatibility claim.'

readonly ORACLE="${FGIT_ORACLE:-${E2E_ROOT}/oracle/oracle.sh}"
readonly ORACLE_PIN="${FGIT_ORACLE_PIN:-git-2.54.0}"
readonly SUITE_PATH='scripts/e2e/suites/tier-a/git_daemon_differential.sh'
# Exactly the registry rows this suite owns; checked against the registry below.
ROWS=(
  TA-ADV-RECEIVE-SHA1 TA-ADV-RECEIVE-SHA256
  TA-ADV-V0-SHA1 TA-ADV-V0-SHA256
  TA-ADV-V2-SHA1 TA-ADV-V2-SHA256
  TA-CLONE-SHA1 TA-CLONE-SHA256
  TA-FETCH-V0-SHA1 TA-FETCH-V0-SHA256
  TA-FETCH-V1-SHA1 TA-FETCH-V1-SHA256
  TA-FETCH-V2-SHA1 TA-FETCH-V2-SHA256
  TA-IMPORT-SHA1 TA-IMPORT-SHA256
  TA-PUSH-SHA1 TA-PUSH-SHA256
)

fge_phase setup
declared=$(awk -F'\t' -v suite="${SUITE_PATH}" '!/^#/ && $10 == suite { print $1 }' \
  "${REPOSITORY_ROOT}/registries/compatibility_tiers.tsv" | LC_ALL=C sort | tr '\n' ' ')
listed=$(printf '%s\n' "${ROWS[@]}" | LC_ALL=C sort | tr '\n' ' ')
fge_assert_eq TIER-A-DECLARATION "${declared}" "${listed}" 'the suite asserts exactly the registry rows it owns'
fge_assert_cmd TIER-A-FG-BIN 'a prebuilt executable fg binary is supplied' test -x "${FG_BIN:-}"
fge_context fg_digest "$(fge_digest_file "${FG_BIN}")"
fge_run oracle-verify "${ORACLE}" verify "${ORACLE_PIN}" || true
if [ "${FGE_LAST_EXIT}" -ne 0 ]; then
  # No ambient Git fallback: an unavailable oracle leaves every row unsupported.
  for row in "${ROWS[@]}"; do
    fge_unsupported "${row}" "pinned oracle ${ORACLE_PIN} is unavailable; the row did not run"
  done
  exit 0
fi
RUN_DIRECTORY="$("${ORACLE}" create-run "${ORACLE_PIN}" tier-a)"
fge_context oracle_run_directory "${RUN_DIRECTORY}"
WORK="$(fge_tempdir tier-a)"

fge_phase action
fge_run_timeout 5400 tier-a-differential env PYTHONDONTWRITEBYTECODE=1 python3 -I \
  "${E2E_ROOT}/helpers/tier_a_differential.py" "${FG_BIN}" "${ORACLE}" "${ORACLE_PIN}" \
  "${RUN_DIRECTORY}" "${WORK}" "${WORK}/results.json" || true
fge_assert_exit TIER-A-HARNESS 0 "${FGE_LAST_EXIT}" 'the differential harness ran to completion'

fge_phase assert
if [ -f "${WORK}/results.json" ]; then
  fge_artifact "${WORK}/results.json" tier-a-results
  fge_artifact "${WORK}/commands.log" tier-a-commands
fi
# One line per row: ID, status, and a bounded summary of the failed checks.
summary=$(python3 -I -c '
import json, sys
try:
    rows = json.load(open(sys.argv[1]))["rows"]
except (OSError, ValueError, KeyError):
    rows = {}
for row_id in sys.argv[2:]:
    row = rows.get(row_id)
    if row is None:
        print(row_id, "missing", "no result for this row", sep="\t")
        continue
    failed = [check["check"] for check in row["failed"]]
    detail = str(row["checks"]) + " checks, " + str(len(failed)) + " failed"
    if failed:
        detail += ": " + "; ".join(failed[:6])
    print(row_id, row["status"], detail, sep="\t")
' "${WORK}/results.json" "${ROWS[@]}")
for row in "${ROWS[@]}"; do
  line=$(printf '%s\n' "${summary}" | awk -F'\t' -v id="${row}" '$1 == id')
  status=$(printf '%s' "${line}" | cut -f2)
  detail=$(printf '%s' "${line}" | cut -f3)
  fge_assert_eq "${row}" pass "${status:-missing}" "${row}: ${detail:-no result}"
done
