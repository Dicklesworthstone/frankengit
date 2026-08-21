#!/usr/bin/env bash
# =============================================================================
# FrankenGit e2e harness self-test  --  scripts/e2e/self_test.sh
# Owner bead: frankengit-fg000a-e2e-harness-4ci
#
# Drives scripts/e2e/run_all.sh over the fixtures in selftests/fixtures/ and
# asserts the EXACT disposition each one must produce. Every planted negative
# is paired with a near-identical permitted case that proceeds, so a green run
# proves the harness both catches the defect and does not cry wolf.
#
# usage: scripts/e2e/self_test.sh
#
# SCOPE CLAIM, stated plainly: this proves the harness's own mechanics and
# nothing else. It is not subsystem evidence, it is not release coverage, and
# no number of self-test assertions says anything about a FrankenGit
# capability. `full` and `release` stay dormant until FG-091 lands the exact
# expected-suite manifest.
#
# This driver is deliberately NOT under suites/, because it invokes run_all.sh
# recursively and its fixtures are designed to fail.
# =============================================================================
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
. "$HERE/lib.sh"

fge_init harness-self-test

RUN_ALL="$HERE/run_all.sh"
FIXTURES="$HERE/selftests/fixtures"
CASES="$(fge_tempdir cases)"

# Set by run_case:
CASE_RC=0
CASE_DISPOSITION=''
CASE_DETAIL=''
CASE_SUITE_STATUS=''
CASE_RECEIPT=''
CASE_OUT=''
declare -a CASE_FAILED_IDS=()
declare -a CASE_CROSS_DUP=()

# run_case NAME TIMEOUT ATTEMPTS FIXTURE...
#
# run_all's own stderr is captured to an artifact rather than discarded: it is
# the subject under test here, and the file is registered as evidence below.
run_case() {
  local name=$1 secs=$2 attempts=$3
  shift 3
  CASE_OUT="$CASES/$name"
  mkdir -p "$CASE_OUT"
  local -a fixtures=()
  local f
  for f in "$@"; do fixtures+=("$FIXTURES/$f"); done

  CASE_RC=0
  "$RUN_ALL" --out "$CASE_OUT/run" --timeout "$secs" --attempts "$attempts" \
    "${fixtures[@]}" >"$CASE_OUT/stdout.log" 2>"$CASE_OUT/stderr.log" || CASE_RC=$?

  CASE_RECEIPT="$CASE_OUT/run/receipt.ndjson"
  CASE_DISPOSITION=''
  CASE_DETAIL=''
  CASE_SUITE_STATUS=''
  CASE_FAILED_IDS=()
  CASE_CROSS_DUP=()

  local line
  line=$(grep -m1 '"kind":"suite_script"' "$CASE_RECEIPT" 2>/dev/null || printf '')
  if [ -n "$line" ] && fge_json_top "$line"; then
    CASE_DISPOSITION=$(fge_json_unquote "${FGE_JSON[disposition]-\"\"}")
    CASE_DETAIL=$(fge_json_unquote "${FGE_JSON[detail]-\"\"}")
    if fge_json_array_strings "${FGE_JSON[failed_ids]-[]}"; then
      CASE_FAILED_IDS=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}")
    fi
  fi

  line=$(grep -m1 '"kind":"suite_terminal"' "$CASE_RECEIPT" 2>/dev/null || printf '')
  if [ -n "$line" ] && fge_json_top "$line"; then
    CASE_SUITE_STATUS=$(fge_json_unquote "${FGE_JSON[status]-\"\"}")
    if fge_json_array_strings "${FGE_JSON[cross_script_duplicate_ids]-[]}"; then
      CASE_CROSS_DUP=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}")
    fi
  fi
  return 0
}

# expect_case ID_PREFIX NAME EXPECTED_RC EXPECTED_DISPOSITION FIXTURE [TIMEOUT]
expect_case() {
  local idp=$1 name=$2 want_rc=$3 want_disp=$4 fixture=$5 secs=${6:-60}
  run_case "$name" "$secs" 1 "$fixture"
  fge_assert_eq "${idp}-RC" "$want_rc" "$CASE_RC" \
    "run_all exit status for $name"
  fge_assert_eq "${idp}-DISP" "$want_disp" "$CASE_DISPOSITION" \
    "disposition for $name"
}

# ---------------------------------------------------------------------------
# permitted controls: the harness must NOT cry wolf
# ---------------------------------------------------------------------------
fge_phase action
fge_step controls 'permitted counterparts run first'
fge_phase assert

expect_case FG-000A-ST-CTL   control-basic       0 ok pos_control.sh
expect_case FG-000A-ST-CLNOK control-cleanup-ok  0 ok pos_cleanup_ok.sh
expect_case FG-000A-ST-OBLOK control-obligation  0 ok pos_obligation_closed.sh

# The permitted control must produce a receipt that is itself valid NDJSON.
run_case receipt-shape 60 1 pos_control.sh
fge_assert_ndjson FG-000A-ST-RECEIPT-NDJSON "$CASE_RECEIPT" \
  'the suite receipt is valid NDJSON'
fge_assert_eq FG-000A-ST-RECEIPT-STATUS pass "$CASE_SUITE_STATUS" \
  'a clean suite reports status pass'

# ---------------------------------------------------------------------------
# planted negatives, one disposition each
# ---------------------------------------------------------------------------
expect_case FG-000A-ST-CMDFAIL  command-failure    1 failed           neg_command_failure.sh
expect_case FG-000A-ST-MISMATCH assert-mismatch    1 failed           neg_assert_mismatch.sh
expect_case FG-000A-ST-ZERO     zero-assertions    1 zero_assertions  neg_zero_assertions.sh
expect_case FG-000A-ST-DUP      duplicate-id       1 duplicate_ids    neg_duplicate_id.sh
expect_case FG-000A-ST-CLEANUP  cleanup-failure    1 cleanup_failed   neg_cleanup_failure.sh
expect_case FG-000A-ST-SKIP     skipped-assertion  1 skipped          neg_skip.sh
expect_case FG-000A-ST-UNSUP    unsupported-result 1 unsupported      neg_unsupported.sh
expect_case FG-000A-ST-OBLIG    obligation-leak    1 containment      neg_obligation_leak.sh
expect_case FG-000A-ST-ORPHAN   orphan-child       1 containment      neg_orphan_child.sh
expect_case FG-000A-ST-COLLIDE  artifact-collision 1 failed           neg_artifact_collision.sh

# Log-shape negatives.
expect_case FG-000A-ST-MALFORM  malformed-ndjson   1 malformed_log    corrupt_malformed.sh
expect_case FG-000A-ST-TRUNCSEQ truncated-record   1 truncated_log    corrupt_truncated_seq.sh
expect_case FG-000A-ST-NONEWL   truncated-stream   1 truncated_log    corrupt_no_newline.sh
expect_case FG-000A-ST-NOTERM   missing-terminal   1 missing_terminal corrupt_missing_terminal.sh
expect_case FG-000A-ST-EXITMM   exit-mismatch      1 exit_mismatch    corrupt_exit_mismatch.sh
expect_case FG-000A-ST-NOLOG    missing-log        1 missing_log      corrupt_missing_log.sh

# Timeout: a 3s budget against a 30s stall.
expect_case FG-000A-ST-TIMEOUT  wall-timeout       1 timeout          neg_timeout.sh 3

# ---------------------------------------------------------------------------
# the two truncation negatives must be distinguishable, not merely both "bad"
# ---------------------------------------------------------------------------
run_case detail-noneline 60 1 corrupt_no_newline.sh
fge_assert_contains FG-000A-ST-NONEWL-DETAIL "$CASE_DETAIL" 'does not end with a newline' \
  'a cut-off stream is reported as such'
run_case detail-truncseq 60 1 corrupt_truncated_seq.sh
fge_assert_contains FG-000A-ST-TRUNCSEQ-DETAIL "$CASE_DETAIL" 'highest seq is' \
  'a lost record is reported as a sequence gap, not a generic parse error'

# ---------------------------------------------------------------------------
# every assertion helper's failing branch fires exactly once
# ---------------------------------------------------------------------------
run_case assert-negatives 60 1 neg_assert_negatives.sh
expected_failed='FG-000A-NEG-EQ FG-000A-NEG-NE FG-000A-NEG-EXIT FG-000A-NEG-CONT FG-000A-NEG-NCONT FG-000A-NEG-MATCH FG-000A-NEG-FILE FG-000A-NEG-NFILE FG-000A-NEG-DIR FG-000A-NEG-DIG FG-000A-NEG-DIGM FG-000A-NEG-NDJ FG-000A-NEG-NDJM FG-000A-NEG-NDJE FG-000A-NEG-CMD FG-000A-NEG-FAIL'
fge_assert_eq FG-000A-ST-NEGSET "$expected_failed" "${CASE_FAILED_IDS[*]}" \
  'the failing branch of every assertion helper fires exactly once, in order'
fge_assert_eq FG-000A-ST-NEGCOUNT 16 "${#CASE_FAILED_IDS[@]}" \
  'sixteen assertion negatives are accounted for'

# ---------------------------------------------------------------------------
# a retry that passes never launders the first attempt
# ---------------------------------------------------------------------------
run_case flaky-retry 60 2 flaky_by_attempt.sh
fge_assert_eq FG-000A-ST-FLAKY-RC 1 "$CASE_RC" \
  'a suite whose first attempt failed is non-pass even though a retry passed'
fge_assert_eq FG-000A-ST-FLAKY-DISP flaky "$CASE_DISPOSITION" \
  'the flaky disposition is recorded rather than a green'
fge_assert_file FG-000A-ST-FLAKY-PRESERVED \
  "$CASE_OUT/run/scripts/selftests-fixtures-flaky_by_attempt/attempt-1/e2e.ndjson" \
  'the first attempt log is preserved alongside the retry'
fge_assert_file FG-000A-ST-FLAKY-ATTEMPT2 \
  "$CASE_OUT/run/scripts/selftests-fixtures-flaky_by_attempt/attempt-2/e2e.ndjson" \
  'the second attempt log is kept too'

# The same fixture with a single attempt is a plain failure, not "flaky".
run_case flaky-single 60 1 flaky_by_attempt.sh
fge_assert_eq FG-000A-ST-FLAKY-SINGLE failed "$CASE_DISPOSITION" \
  'without retries the same fixture is simply a failure'

# ---------------------------------------------------------------------------
# one acceptance ID has exactly one owning script
# ---------------------------------------------------------------------------
run_case cross-duplicate 60 1 pos_control.sh neg_cross_dup.sh
fge_assert_eq FG-000A-ST-CROSSDUP-RC 1 "$CASE_RC" \
  'two scripts claiming one acceptance ID fail the suite'
fge_assert_eq FG-000A-ST-CROSSDUP-ID 'FG-000A-CTL-001' "${CASE_CROSS_DUP[*]}" \
  'the contested acceptance ID is named exactly'

# ---------------------------------------------------------------------------
# discovery, and the refusal to pass vacuously
# ---------------------------------------------------------------------------
fge_phase action
empty_dir="$(fge_tempdir empty-suite)"
suite_dir="$(fge_tempdir discovery-suite)"
mkdir -p "$suite_dir/area"
cp "$FIXTURES/pos_control.sh" "$suite_dir/area/discovered_one.sh"
chmod +x "$suite_dir/area/discovered_one.sh"
printf 'not a script\n' >"$suite_dir/area/notes.txt"

empty_rc=0
FGE_LIB="$HERE/lib.sh" "$RUN_ALL" --dir "$empty_dir" --out "$CASES/empty/run" \
  >"$CASES/empty.stdout" 2>"$CASES/empty.stderr" || empty_rc=$?

list_out=$(FGE_LIB="$HERE/lib.sh" "$RUN_ALL" --dir "$suite_dir" --list 2>/dev/null || printf '')

disc_rc=0
FGE_LIB="$HERE/lib.sh" "$RUN_ALL" --dir "$suite_dir" --out "$CASES/discovery/run" \
  --timeout 60 >"$CASES/discovery.stdout" 2>"$CASES/discovery.stderr" || disc_rc=$?

fge_phase assert
fge_assert_eq FG-000A-ST-EMPTY-RC 1 "$empty_rc" \
  'a suite that selected zero scripts fails structurally instead of passing vacuously'
fge_assert_contains FG-000A-ST-LIST "$list_out" 'discovered_one' \
  '--list reports the discovered script'
fge_assert_not_contains FG-000A-ST-LIST-NONSH "$list_out" 'notes.txt' \
  'discovery ignores non-.sh files'
fge_assert_eq FG-000A-ST-DISCOVER-RC 0 "$disc_rc" \
  'a discovered healthy script passes through the discovery path'

# ---------------------------------------------------------------------------
# evidence retention
# ---------------------------------------------------------------------------
fge_preserve "$CASES" 'self-test case outputs, receipts and run_all stderr'
