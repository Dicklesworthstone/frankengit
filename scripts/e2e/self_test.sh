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
# The fixture's OWN terminal record, read straight from its NDJSON log.
#
# run_all re-derives most non-pass conditions independently of lib.sh, which is
# deliberate defence in depth -- but it means a self-test that only inspects
# run_all's verdict cannot see lib.sh's verdict go wrong. Mutation testing
# confirmed exactly that: weakening lib.sh's skip, zero-assertion and cleanup
# rules left the suite green because run_all still caught each one. These
# assertions pin the library's own judgement so both layers are load-bearing.
# ---------------------------------------------------------------------------
FIX_STATUS=''
FIX_EXIT=''
FIX_CLEANUP=''
FIX_ZERO=''
FIX_CONTAINMENT=''
FIX_SKIPPED=''
FIX_UNSUPPORTED=''
FIX_OBLIG=''
FIX_DUPS=''
FIX_LOG=''

# fixture_terminal CASE_OUT SCRIPT_ID [ATTEMPT]
fixture_terminal() {
  local case_out=$1 script_id=$2 attempt=${3:-1}
  FIX_LOG="$case_out/run/scripts/$script_id/attempt-$attempt/e2e.ndjson"
  FIX_STATUS=''
  FIX_EXIT=''
  FIX_CLEANUP=''
  FIX_ZERO=''
  FIX_CONTAINMENT=''
  FIX_SKIPPED=''
  FIX_UNSUPPORTED=''
  FIX_OBLIG=''
  FIX_DUPS=''
  [ -f "$FIX_LOG" ] || return 1
  local line
  line=$(grep '"kind":"terminal"' "$FIX_LOG" 2>/dev/null | tail -1)
  [ -n "$line" ] || return 1
  fge_json_top "$line" || return 1
  local term=${FGE_JSON[terminal]-}
  [ -n "$term" ] || return 1
  fge_json_top "$term" || return 1
  FIX_STATUS=$(fge_json_unquote "${FGE_JSON[status]-}")
  FIX_EXIT=${FGE_JSON[exit_code]-}
  FIX_CLEANUP=$(fge_json_unquote "${FGE_JSON[cleanup_state]-}")
  FIX_ZERO=${FGE_JSON[zero_assertions]-}
  FIX_CONTAINMENT=$(fge_json_unquote "${FGE_JSON[containment]-}")
  FIX_SKIPPED=${FGE_JSON[skipped]-}
  FIX_UNSUPPORTED=${FGE_JSON[unsupported]-}
  FIX_OBLIG=${FGE_JSON[obligations_outstanding]-}
  FIX_DUPS=${FGE_JSON[duplicate_ids]-}
  return 0
}

# assert_fixture_fails ID_PREFIX SCRIPT_ID DESC
# The library itself must call the run a failure and exit nonzero.
assert_fixture_fails() {
  local idp=$1 sid=$2 desc=$3
  if ! fixture_terminal "$CASE_OUT" "$sid"; then
    fge_fail "${idp}-LIBTERM" "could not read the terminal record for $sid"
    return 0
  fi
  fge_assert_eq "${idp}-LIBSTATUS" fail "$FIX_STATUS" \
    "lib.sh itself marks $desc a failure"
  fge_assert_ne "${idp}-LIBEXIT" 0 "$FIX_EXIT" \
    "lib.sh itself exits nonzero for $desc"
  return 0
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
assert_fixture_fails FG-000A-ST-CMDFAIL selftests-fixtures-neg_command_failure 'a failed command'

expect_case FG-000A-ST-MISMATCH assert-mismatch    1 failed           neg_assert_mismatch.sh
assert_fixture_fails FG-000A-ST-MISMATCH selftests-fixtures-neg_assert_mismatch 'a mismatched assertion'

expect_case FG-000A-ST-ZERO     zero-assertions    1 zero_assertions  neg_zero_assertions.sh
assert_fixture_fails FG-000A-ST-ZERO selftests-fixtures-neg_zero_assertions 'a run that proved nothing'
fge_assert_eq FG-000A-ST-ZERO-LIBFLAG true "$FIX_ZERO" \
  'lib.sh raises zero_assertions in its own terminal record'

expect_case FG-000A-ST-DUP      duplicate-id       1 duplicate_ids    neg_duplicate_id.sh
assert_fixture_fails FG-000A-ST-DUP selftests-fixtures-neg_duplicate_id 'a duplicated acceptance id'
fge_assert_eq FG-000A-ST-DUP-LIBIDS '["FG-000A-DUP-001"]' "$FIX_DUPS" \
  'lib.sh names the duplicated id in its own terminal record'

expect_case FG-000A-ST-CLEANUP  cleanup-failure    1 cleanup_failed   neg_cleanup_failure.sh
assert_fixture_fails FG-000A-ST-CLEANUP selftests-fixtures-neg_cleanup_failure 'a failing cleanup'
fge_assert_eq FG-000A-ST-CLEANUP-LIBSTATE failed "$FIX_CLEANUP" \
  'lib.sh records cleanup_state=failed'

expect_case FG-000A-ST-SKIP     skipped-assertion  1 skipped          neg_skip.sh
assert_fixture_fails FG-000A-ST-SKIP selftests-fixtures-neg_skip 'a skipped assertion'
fge_assert_eq FG-000A-ST-SKIP-LIBCOUNT 1 "$FIX_SKIPPED" \
  'lib.sh counts the skipped assertion'

expect_case FG-000A-ST-UNSUP    unsupported-result 1 unsupported      neg_unsupported.sh
assert_fixture_fails FG-000A-ST-UNSUP selftests-fixtures-neg_unsupported 'an unsupported result'
fge_assert_eq FG-000A-ST-UNSUP-LIBCOUNT 1 "$FIX_UNSUPPORTED" \
  'lib.sh counts the unsupported assertion'

expect_case FG-000A-ST-OBLIG    obligation-leak    1 containment      neg_obligation_leak.sh
assert_fixture_fails FG-000A-ST-OBLIG selftests-fixtures-neg_obligation_leak 'a leaked obligation'
fge_assert_eq FG-000A-ST-OBLIG-LIBCONT failed "$FIX_CONTAINMENT" \
  'lib.sh reports containment failure for an unresolved obligation'
fge_assert_eq FG-000A-ST-OBLIG-LIBCOUNT 1 "$FIX_OBLIG" \
  'lib.sh counts the outstanding obligation'

expect_case FG-000A-ST-ORPHAN   orphan-child       1 containment      neg_orphan_child.sh
assert_fixture_fails FG-000A-ST-ORPHAN selftests-fixtures-neg_orphan_child 'an orphaned child'
fge_assert_eq FG-000A-ST-ORPHAN-LIBCONT failed "$FIX_CONTAINMENT" \
  'lib.sh reports containment failure for a child that ignored SIGTERM'

expect_case FG-000A-ST-COLLIDE  artifact-collision 1 failed           neg_artifact_collision.sh
assert_fixture_fails FG-000A-ST-COLLIDE selftests-fixtures-neg_artifact_collision 'an artifact name collision'

# The permitted control's own terminal record is the counterpart of every
# assert_fixture_fails above: clean on exactly the fields they see dirty.
run_case control-terminal 60 1 pos_control.sh
if fixture_terminal "$CASE_OUT" selftests-fixtures-pos_control; then
  fge_assert_eq FG-000A-ST-CTL-LIBSTATUS pass "$FIX_STATUS" 'the control run is a pass'
  fge_assert_eq FG-000A-ST-CTL-LIBEXIT   0    "$FIX_EXIT"   'the control run exits 0'
  fge_assert_eq FG-000A-ST-CTL-LIBZERO   false "$FIX_ZERO"  'the control run proved something'
  fge_assert_eq FG-000A-ST-CTL-LIBCONT   ok   "$FIX_CONTAINMENT" 'the control run contains its children'
  fge_assert_eq FG-000A-ST-CTL-LIBDUPS   '[]' "$FIX_DUPS"   'the control run has no duplicate ids'
  fge_assert_eq FG-000A-ST-CTL-LIBSKIP   0    "$FIX_SKIPPED" 'the control run skips nothing'
else
  fge_fail FG-000A-ST-CTL-LIBTERM 'could not read the control terminal record'
fi

# Log-shape negatives.
expect_case FG-000A-ST-MALFORM  malformed-ndjson   1 malformed_log    corrupt_malformed.sh
expect_case FG-000A-ST-TRUNCSEQ truncated-record   1 truncated_log    corrupt_truncated_seq.sh
expect_case FG-000A-ST-NONEWL   truncated-stream   1 truncated_log    corrupt_no_newline.sh
expect_case FG-000A-ST-NOTERM   missing-terminal   1 missing_terminal corrupt_missing_terminal.sh
expect_case FG-000A-ST-EXITMM   exit-mismatch      1 exit_mismatch    corrupt_exit_mismatch.sh
expect_case FG-000A-ST-NOLOG    missing-log        1 missing_log      corrupt_missing_log.sh
expect_case FG-000A-ST-NOKEY    missing-base-key   1 malformed_log    corrupt_missing_key.sh
fge_assert_contains FG-000A-ST-NOKEY-DETAIL "$CASE_DETAIL" "missing required key 'replay'" \
  'a record that parses but lost a required base key is named precisely'

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
expected_failed='FG-000A-NEG-EQ FG-000A-NEG-NE FG-000A-NEG-EXIT FG-000A-NEG-CONT FG-000A-NEG-NCONT FG-000A-NEG-NCONTE FG-000A-NEG-MATCH FG-000A-NEG-FILE FG-000A-NEG-NFILE FG-000A-NEG-DIR FG-000A-NEG-DIG FG-000A-NEG-DIGM FG-000A-NEG-NDJ FG-000A-NEG-NDJM FG-000A-NEG-NDJE FG-000A-NEG-CMD FG-000A-NEG-FAIL'
fge_assert_eq FG-000A-ST-NEGSET "$expected_failed" "${CASE_FAILED_IDS[*]}" \
  'the failing branch of every assertion helper fires exactly once, in order'
fge_assert_eq FG-000A-ST-NEGCOUNT 17 "${#CASE_FAILED_IDS[@]}" \
  'seventeen assertion negatives are accounted for'

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
# a scoped profile names every outside area in its receipt without turning a
# legitimate area-scoped profile into an all-corpus gate
# ---------------------------------------------------------------------------
fge_phase action
profile_manifest="$HERE/manifests/profile-coverage-probe.tsv"
profile_declared_dir="$HERE/suites/profile_coverage_declared"
profile_declared_script="$profile_declared_dir/declared.sh"
profile_probe_dir="$HERE/suites/profile_coverage_probe"
profile_probe_script="$profile_probe_dir/undeclared.sh"
profile_root=$(fge_tempdir profile-coverage)
profile_probe_ready=false
if [ -e "$profile_manifest" ] || [ -e "$profile_declared_dir" ] || [ -e "$profile_probe_dir" ]; then
  fge_fail FG-000A-ST-PROFILE-PRECONDITION \
    'profile-coverage probe paths already exist; refusing to overwrite them'
else
  # Cleanup is registered before either real-tree probe path exists. The test
  # must exercise repo-relative discovery -- a copied runner derives a different
  # ID namespace and can make an empty profile result look like a valid pass.
  fge_cleanup_register rm -f -- "$profile_manifest"
  fge_cleanup_register rmdir -- "$profile_probe_dir"
  fge_cleanup_register rm -f -- "$profile_probe_script"
  fge_cleanup_register rmdir -- "$profile_declared_dir"
  fge_cleanup_register rm -f -- "$profile_declared_script"
  mkdir -p "$profile_declared_dir" "$profile_probe_dir"
  cp "$FIXTURES/pos_control.sh" "$profile_declared_script"
  cp "$FIXTURES/pos_control.sh" "$profile_probe_script"
  chmod +x "$profile_declared_script" "$profile_probe_script"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    suites-profile_coverage_declared-declared frankengit-fg000a-e2e-harness-4ci g0 \
    scripts/e2e/suites/profile_coverage_declared/declared.sh any required mechanism pass \
    >"$profile_manifest"
  profile_probe_ready=true
fi

profile_rc=1
profile_terminal=''
profile_status=''
declare -a profile_uncovered_areas=() profile_unregistered=()
if [ "$profile_probe_ready" = true ]; then
  profile_rc=0
  "$RUN_ALL" --profile profile-coverage-probe \
    --out "$profile_root/run" --timeout 60 \
    >"$profile_root/stdout.log" 2>"$profile_root/stderr.log" || profile_rc=$?
  profile_terminal=$(grep -m1 '"kind":"suite_terminal"' \
    "$profile_root/run/receipt.ndjson" 2>/dev/null || printf '')
  if [ -n "$profile_terminal" ] && fge_json_top "$profile_terminal"; then
    profile_status=$(fge_json_unquote "${FGE_JSON[status]-\"\"}")
    if fge_json_array_strings "${FGE_JSON[manifest_uncovered_areas]-[]}"; then
      profile_uncovered_areas=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}")
    fi
    if fge_json_array_strings "${FGE_JSON[manifest_unregistered]-[]}"; then
      profile_unregistered=("${FGE_JSON_ARRAY[@]+"${FGE_JSON_ARRAY[@]}"}")
    fi
  fi
fi

fge_phase assert
fge_assert_eq FG-000A-ST-PROFILE-SCOPED-RC 0 "$profile_rc" \
  'an area-scoped profile still runs and passes its declared surface'
fge_assert_eq FG-000A-ST-PROFILE-SCOPED-STATUS pass "$profile_status" \
  'the controlled scoped profile retains its passing terminal status'
fge_assert_eq FG-000A-ST-PROFILE-SCOPED-UNREGISTERED 0 "${#profile_unregistered[@]}" \
  'a suite in an unowned area is not misreported as unregistered in the owned area'
fge_assert_contains FG-000A-ST-PROFILE-UNCOVERED-NAME \
  "${profile_uncovered_areas[*]}" suites-profile_coverage_probe \
  'the receipt names the planted undeclared area rather than hiding it by scope'

# ---------------------------------------------------------------------------
# evidence retention
# ---------------------------------------------------------------------------
fge_preserve "$CASES" 'self-test case outputs, receipts and run_all stderr'
