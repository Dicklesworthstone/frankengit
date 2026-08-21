#!/usr/bin/env bash
# e2e: proves the shared harness library's own mechanics on the permitted path
# (bead frankengit-fg000a-e2e-harness-4ci). Every planted-negative counterpart
# lives in scripts/e2e/selftests/ and is driven by scripts/e2e/self_test.sh.
#
# Scope claim: this proves harness mechanics ONLY. It is not subsystem
# evidence, and running it says nothing about any FrankenGit capability.
set -euo pipefail
. "${FGE_LIB:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh}"

fge_init

# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------
fge_phase setup
fge_context suite harness-mechanics
fge_step begin 'harness mechanics, permitted path'

work=$(fge_tempdir repo)
# A path with a space and non-ASCII bytes, because artifact and work paths are
# attacker- and author-controlled in real suites.
odd="$work/dir with space/ünïcode-∆"
mkdir -p "$odd"
printf 'hello\n' >"$odd/file one.txt"

# ---------------------------------------------------------------------------
# command execution
# ---------------------------------------------------------------------------
fge_phase action

fge_run true-command true || true
rc_true=$FGE_LAST_EXIT

fge_run false-command false || true
rc_false=$FGE_LAST_EXIT

fge_run_ok ok-command true

fge_capture capture-stdout printf 'captured %s\n' 'value'
cap_out=$FGE_LAST_STDOUT
cap_file=$FGE_LAST_STDOUT_FILE

fge_capture capture-stderr-cmd bash -c 'printf "to-stderr\n" >&2; exit 3' || true
cap_err=$FGE_LAST_STDERR
cap_err_exit=$FGE_LAST_EXIT

# Completes well inside the budget: the permitted counterpart of the planted
# timeout fixture.
fge_run_timeout 30 within-budget true
rc_budget=$FGE_LAST_EXIT

# Succeeds on the first attempt, so first_attempt_status stays "pass".
fge_retry 3 retry-first-try true
rc_retry=$FGE_LAST_EXIT

fge_spawn background-sleep sleep 30
spawned_pid=$FGE_LAST_PID
spawn_alive=no
kill -0 "$spawned_pid" 2>/dev/null && spawn_alive=yes
fge_reap background-sleep
spawn_reaped=no
kill -0 "$spawned_pid" 2>/dev/null || spawn_reaped=yes

# ---------------------------------------------------------------------------
# determinism, replay, failpoints
# ---------------------------------------------------------------------------
seed_a=$(fge_seed)
r1=$(fge_rand 1000)
r2=$(fge_rand 1000)
hex1=$(fge_rand_hex 8)

# Re-seeding to the same seed must reproduce the same sequence exactly.
fge__seed_state
r1b=$(fge_rand 1000)
r2b=$(fge_rand 1000)
hex1b=$(fge_rand_hex 8)

replay=$(fge_replay_command)
sched=$(fge_schedule)

# Not armed unless FGE_FAILPOINT names it.
fp_unarmed=notfired
fge_failpoint definitely-not-armed && fp_unarmed=fired

# ---------------------------------------------------------------------------
# secrets and redaction
# ---------------------------------------------------------------------------
secret_value='sup3rsecretvalue'
fge_register_secret "$secret_value" demo
red_secret=$(fge_redact "prefix $secret_value suffix")

# A value too short to redact safely is refused rather than silently accepted.
short_rc=0
fge_register_secret 'ab' tiny 2>/dev/null || short_rc=$?

red_kv=$(fge_redact 'GIT_TOKEN=abcdef123456 PATH=/usr/bin')

# Same argv digests identically; different argv does not.
d1=$(fge_cmd_digest git status --short)
d2=$(fge_cmd_digest git status --short)
d3=$(fge_cmd_digest git status --long)

# ---------------------------------------------------------------------------
# digests, artifacts, resources, obligations, position
# ---------------------------------------------------------------------------
empty_digest=$(fge_digest_string '')
known_digest=$(fge_digest_string 'abc')
file_digest=$(fge_digest_file "$odd/file one.txt")
hello_digest=$(fge_digest_string 'hello
')

art=$(fge_artifact_path 'evidence/sample.txt')
printf 'sample evidence\n' >"$art"
fge_artifact 'evidence/sample.txt' text
# Re-registering the SAME name with the SAME bytes is idempotent, not a
# collision; the collision case is planted in the self-test fixtures.
fge_artifact 'evidence/sample.txt' text

fge_preserve "$odd" 'unicode work dir retained for triage'

fge_resource_mark

fge_obligation_open lease-1 lease
fge_obligation_close lease-1

fge_position 'head-abc123' 'gen-7' 'policy-v1'
fge_field domain_specific 'typed field on this record only'
fge_step positioned 'record carries authority position and one domain field'

# ---------------------------------------------------------------------------
# JSON / NDJSON helpers
# ---------------------------------------------------------------------------
json_good=0
fge_json_validate_line '{"a":[1,2,{"b":"c"}],"d":null}' || json_good=1
json_bad=0
fge_json_validate_line '{"a":1,}' || json_bad=1
json_ctrl=0
fge_json_validate_line "$(printf '{"a":"x\001y"}')" || json_ctrl=1

fge_json_top '{"k":"v","n":{"deep":[1,2]}}'
top_k=$(fge_json_unquote "${FGE_JSON[k]}")
top_n=${FGE_JSON[n]}

fge_json_array_strings '["one","tw\"o","th,ree"]'
arr_count=${#FGE_JSON_ARRAY[@]}
arr_1=${FGE_JSON_ARRAY[1]}
arr_2=${FGE_JSON_ARRAY[2]}

esc=$(fge_json_escape "$(printf 'tab\there\nnl"q\\b')")

# Round trip: the harness's own log must satisfy the harness's own validator.
log_lines=0
while IFS= read -r _l; do log_lines=$((log_lines + 1)); done <"$FGE_LOG"

# ---------------------------------------------------------------------------
# cleanup registration (succeeding path)
# ---------------------------------------------------------------------------
cleanup_marker="$work/cleanup-ran"
fge_cleanup_register touch "$cleanup_marker"

# ---------------------------------------------------------------------------
# assertions
# ---------------------------------------------------------------------------
fge_phase assert

fge_assert_eq  FG-000A-MECH-001 0 "$rc_true"            'fge_run reports exit 0'
fge_assert_eq  FG-000A-MECH-002 1 "$rc_false"           'fge_run reports a nonzero exit without aborting'
fge_assert_exit FG-000A-MECH-003 0 "$rc_budget"         'fge_run_timeout inside budget is a pass'
fge_assert_eq  FG-000A-MECH-004 0 "$rc_retry"           'fge_retry succeeds on the first attempt'

fge_assert_eq  FG-000A-MECH-005 'captured value' "$cap_out"    'fge_capture exposes stdout'
fge_assert_eq  FG-000A-MECH-006 'to-stderr' "$cap_err"          'fge_capture exposes stderr'
fge_assert_eq  FG-000A-MECH-007 3 "$cap_err_exit"               'fge_capture preserves the exit code'
fge_assert_file FG-000A-MECH-008 "$cap_file"                    'fge_capture keeps stdout as an artifact'

fge_assert_eq  FG-000A-MECH-009 yes "$spawn_alive"      'fge_spawn starts a live child'
fge_assert_eq  FG-000A-MECH-010 yes "$spawn_reaped"     'fge_reap terminates it'

fge_assert_ne  FG-000A-MECH-011 '' "$seed_a"            'a seed is always present'
fge_assert_eq  FG-000A-MECH-012 "$r1" "$r1b"            'fge_rand is deterministic under a fixed seed (1/3)'
fge_assert_eq  FG-000A-MECH-013 "$r2" "$r2b"            'fge_rand is deterministic under a fixed seed (2/3)'
fge_assert_eq  FG-000A-MECH-014 "$hex1" "$hex1b"        'fge_rand_hex is deterministic under a fixed seed (3/3)'
fge_assert_match FG-000A-MECH-015 "$hex1" '^[0-9a-f]{16}$' 'fge_rand_hex returns 2 hex digits per byte'
fge_assert_contains FG-000A-MECH-016 "$replay" 'FGE_SEED=' 'the replay command pins the seed'
fge_assert_contains FG-000A-MECH-017 "$replay" 'FGE_FAILPOINT=' 'the replay command pins the failpoint'
fge_assert_eq  FG-000A-MECH-018 default "$sched"        'the default schedule label is reported'
fge_assert_eq  FG-000A-MECH-019 notfired "$fp_unarmed"  'an unarmed failpoint does not fire'

fge_assert_not_contains FG-000A-MECH-020 "$red_secret" "$secret_value" 'a registered secret never reaches evidence text'
fge_assert_contains FG-000A-MECH-021 "$red_secret" '<redacted:demo:' 'redaction leaves a labelled, digest-tagged marker'
fge_assert_contains FG-000A-MECH-022 "$red_secret" 'prefix'           'redaction leaves the surrounding text intact'
fge_assert_eq  FG-000A-MECH-023 2 "$short_rc"           'a secret shorter than 4 bytes is refused, not silently accepted'
fge_assert_not_contains FG-000A-MECH-024 "$red_kv" 'abcdef123456' 'a secret-shaped KEY=VALUE argument is masked'
fge_assert_contains FG-000A-MECH-025 "$red_kv" 'PATH=/usr/bin'   'a non-secret KEY=VALUE argument is left readable'

fge_assert_eq  FG-000A-MECH-026 "$d1" "$d2"             'the same argv digests identically'
fge_assert_ne  FG-000A-MECH-027 "$d1" "$d3"             'a different argv digests differently'

fge_assert_eq  FG-000A-MECH-028 \
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' \
  "$empty_digest" 'sha-256 of the empty string matches the published vector'
fge_assert_eq  FG-000A-MECH-029 \
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' \
  "$known_digest" 'sha-256 of "abc" matches the published vector'
fge_assert_eq  FG-000A-MECH-030 "$hello_digest" "$file_digest" \
  'fge_digest_file agrees with fge_digest_string through a path with a space and non-ASCII bytes'

fge_assert_file FG-000A-MECH-031 "$art"                 'fge_artifact_path creates a usable path'
fge_assert_dir  FG-000A-MECH-032 "$odd"                 'a unicode work directory survives'
fge_assert_digest FG-000A-MECH-033 "$hello_digest" "$odd/file one.txt" 'fge_assert_digest verifies content'
fge_assert_no_file FG-000A-MECH-034 "$work/definitely-absent" 'fge_assert_no_file detects absence'

fge_assert_eq  FG-000A-MECH-035 0 "$json_good"          'the validator accepts well-formed JSON'
fge_assert_eq  FG-000A-MECH-036 1 "$json_bad"           'the validator rejects a trailing comma'
fge_assert_eq  FG-000A-MECH-037 1 "$json_ctrl"          'the validator rejects a raw control byte'
fge_assert_eq  FG-000A-MECH-038 v "$top_k"              'fge_json_top extracts a scalar'
fge_assert_eq  FG-000A-MECH-039 '{"deep":[1,2]}' "$top_n" 'fge_json_top returns a nested value as raw JSON'
fge_assert_eq  FG-000A-MECH-040 3 "$arr_count"          'fge_json_array_strings counts elements'
fge_assert_eq  FG-000A-MECH-041 'tw"o' "$arr_1"         'fge_json_array_strings decodes an escaped quote'
fge_assert_eq  FG-000A-MECH-042 'th,ree' "$arr_2"       'fge_json_array_strings does not split on a comma inside a string'
fge_assert_eq  FG-000A-MECH-043 'tab\there\nnl\"q\\b' "$esc" 'fge_json_escape escapes control bytes, quotes and backslashes'

fge_assert_ndjson FG-000A-MECH-044 "$FGE_LOG"           'the harness log validates against the harness validator'
fge_assert_cmd  FG-000A-MECH-045 'the log has grown past the first record' test "$log_lines" -gt 5

fge_pass FG-000A-MECH-046 'fge_pass records an explicit pass'
