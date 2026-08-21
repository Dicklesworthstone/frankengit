# shellcheck shell=bash
# =============================================================================
# FrankenGit shared end-to-end harness library  --  scripts/e2e/lib.sh
# Owner bead: frankengit-fg000a-e2e-harness-4ci
#
# THIS HEADER IS THE CANONICAL USAGE REFERENCE FOR THE HARNESS.
# There is no separate process document; if behaviour and header disagree, the
# header is the bug report and the behaviour is the defect.
#
# -----------------------------------------------------------------------------
# 0. WHAT THIS IS AND IS NOT
# -----------------------------------------------------------------------------
# This library supplies E2E *mechanics* only: step execution, assertions with
# stable acceptance IDs, deterministic seeding/replay, secret-safe command
# display, digest/resource/obligation capture, cleanup, failure-state
# preservation, and a single NDJSON evidence stream per script run.
#
# It cannot make a dormant lane green, it is not subsystem evidence, and a
# passing harness self-test is never release coverage. `scripts/verify.sh`
# full/release activation and the exact expected-suite manifest are owned by
# FG-091, not by this file (see section 9, "Seam for FG-091").
#
# -----------------------------------------------------------------------------
# 1. TOOLING CONTRACT (deliberate, see registries/dependency_policy.tsv)
# -----------------------------------------------------------------------------
# Required: bash >= 4.4 (associative arrays, `inherit_errexit`), POSIX
# coreutils, and ONE sha-256 helper out of `sha256sum` | `shasum -a 256` |
# `openssl dgst -sha256`.
#
# Deliberately NOT used, and no registry row is therefore requested:
#   jq, python, perl, awk, sed-scripting for JSON.
# The NDJSON scanner in section `fge_json_*` is written in pure bash precisely
# so that the evidence-validating path adds no tool to the closed dependency
# universe. If a future need forces a tool, it takes a
# `registries/dependency_policy.tsv` tooling row (cf. DEP-011 `nektos-act`)
# under an Agent Mail reservation -- never a silent `command -v`.
#
# `timeout(1)` is used when present but is NOT required: a pure-bash watchdog
# is the fallback and the record states which one ran (`env.timeout_impl`).
#
# -----------------------------------------------------------------------------
# 2. MINIMAL SCRIPT SHAPE
# -----------------------------------------------------------------------------
#   #!/usr/bin/env bash
#   # e2e: <one line saying what capability this proves>
#   set -euo pipefail
#   . "$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/lib.sh"   # path to lib.sh
#
#   fge_init                       # or: fge_init my-script-id
#
#   fge_phase setup
#   work="$(fge_tempdir repo)"     # preserved verbatim if the run fails
#
#   fge_phase action
#   fge_run build-thing cargo check -p fgit-types     # records exit + duration
#
#   fge_phase assert
#   fge_assert_exit  FG-000A-DEMO-001 0
#   fge_assert_eq    FG-000A-DEMO-002 "expected" "$actual" "human description"
#
#   # No explicit teardown call is needed: the EXIT trap runs registered
#   # cleanups, emits the terminal record, and sets the process exit status.
#
# Sourcing lib.sh turns on `set -euo pipefail` and `shopt -s inherit_errexit`
# for you. Do not turn them back off.
#
# -----------------------------------------------------------------------------
# 3. PUBLIC FUNCTION SURFACE (frozen for wave 1 -- names will not change)
# -----------------------------------------------------------------------------
# Lifecycle
#   fge_init [SCRIPT_ID]                 start a run; must be called first
#   fge_phase PHASE                      setup|action|assert|failpoint|cleanup|teardown
#   fge_step  STEP MESSAGE               a bare step record, no command
#   fge_note  STEP MESSAGE               free-form note record
#   fge_die   MESSAGE                    typed fatal error; terminal record still emitted
#
# Commands (all set FGE_LAST_EXIT / FGE_LAST_DURATION_MS / FGE_LAST_STEP)
#
#   >>> IF YOU INTEND TO ASSERT ON THE EXIT CODE, WRITE `|| true`. <<<
#
#   fge_run and fge_capture RETURN the command's exit status, and every suite
#   runs under `set -euo pipefail`. So a bare call whose command fails kills the
#   script ON THAT LINE -- before FGE_LAST_EXIT is read and before the assertion
#   meant to report the failure can run:
#
#       fge_run build cargo test ...        # <-- dies here on failure
#       rc=$FGE_LAST_EXIT                   # never reached
#       fge_assert_eq FG-X-001 0 "$rc" ...  # never reached
#
#   The run is still caught as failing, so nothing green slips through, but it
#   reports `status=fail failed=0` with the remaining assertions never executed:
#   the operator learns the suite died, not which check broke, and one early
#   failure masks every later assertion. Write it as:
#
#       fge_run build cargo test ... || true
#       rc=$FGE_LAST_EXIT
#       fge_assert_eq FG-X-001 0 "$rc" ...
#
#   A bare call is correct when the failure SHOULD abort -- that is what
#   fge_run_ok is for, and it says so at the call site. The trap is only the
#   combination: bare call, capture the exit, assert on it.
#
#   fge_run          STEP CMD [ARG...]             run, time, record; returns cmd exit
#                                                  (see the warning above)
#   fge_run_ok       STEP CMD [ARG...]             as fge_run, fge_die on nonzero
#   fge_capture      STEP CMD [ARG...]             as fge_run + capture stdout/stderr
#                                                  to artifacts; sets FGE_LAST_STDOUT,
#                                                  FGE_LAST_STDERR (redacted, truncated)
#                                                  and FGE_LAST_STDOUT_FILE/_STDERR_FILE
#   fge_run_timeout  SECS STEP CMD [ARG...]        SIGTERM then SIGKILL; status "timeout"
#   fge_retry        ATTEMPTS STEP CMD [ARG...]    records EVERY attempt; the first
#                                                  attempt's outcome is preserved in the
#                                                  terminal record
#   fge_spawn        NAME CMD [ARG...]             background child, tracked for
#                                                  containment; sets FGE_LAST_PID
#   fge_reap         NAME [SIGNAL]                 stop a spawned child and record it
#
# Assertions -- every one takes a stable acceptance ID as its first argument,
# NEVER aborts the script, always returns 0, and sets FGE_LAST_ASSERT_OK to
# 0 (pass) or 1 (fail). Rationale: a script must run its whole assertion set so
# the terminal record can carry exact discovered/passed/failed ID sets; a
# fail-fast assert would silently shrink the denominator.
#   fge_assert_eq            ID EXPECTED ACTUAL [DESC]
#   fge_assert_ne            ID NOT_EXPECTED ACTUAL [DESC]
#   fge_assert_exit          ID EXPECTED_EXIT [ACTUAL_EXIT] [DESC]   (default: FGE_LAST_EXIT)
#   fge_assert_contains      ID HAYSTACK NEEDLE [DESC]
#   fge_assert_not_contains  ID HAYSTACK NEEDLE [DESC]
#   fge_assert_match         ID STRING ERE [DESC]
#   fge_assert_file          ID PATH [DESC]        regular file exists
#   fge_assert_no_file       ID PATH [DESC]
#   fge_assert_dir           ID PATH [DESC]
#   fge_assert_digest        ID EXPECTED_HEX PATH [DESC]
#   fge_assert_ndjson        ID PATH [DESC]        every line a valid JSON object
#   fge_assert_cmd           ID DESC CMD [ARG...]  predicate command exits 0
#   fge_pass                 ID [DESC]
#   fge_fail                 ID REASON
#   fge_skip                 ID REASON             terminal non-pass
#   fge_unsupported          ID REASON             typed unsupported; terminal non-pass
#
# Determinism, replay, fault injection
#   fge_seed                             print the active seed (deterministic by default)
#   fge_rand [MAX]                       deterministic PRNG int in [0,MAX) (default 2^31)
#   fge_rand_hex [BYTES]                 deterministic hex string
#   fge_failpoint NAME                   true when FGE_FAILPOINT matches; records a
#                                        failpoint record when it fires
#   fge_schedule                         print the active schedule label
#   fge_replay_command                   print the exact command that reproduces this run
#
# Secrets
#   fge_register_secret VALUE [LABEL]    redact VALUE everywhere the harness prints
#                                        (command display, captured output, records).
#                                        Values shorter than 4 bytes are REFUSED
#                                        (typed error) because they would redact
#                                        unrelated text.
#   fge_redact TEXT                      print TEXT with registered secrets and
#                                        secret-shaped KEY=VALUE arguments masked
#   fge_cmd_digest CMD [ARG...]          sha-256 over the NUL-joined *unredacted* argv,
#                                        so two runs are comparable without disclosure
#
# Artifacts, digests, resources, obligations, position
#   fge_artifact_path NAME               absolute path inside the run's artifact dir
#   fge_artifact NAME_OR_PATH [KIND]     hash + record an artifact (collision-checked:
#                                        re-registering a NAME with different content
#                                        is a typed failure, not an overwrite)
#   fge_digest_file PATH                 sha-256 hex of a file
#   fge_digest_string TEXT               sha-256 hex of a string
#   fge_tempdir [NAME]                   work dir; removed on success, PRESERVED on failure
#   fge_preserve PATH REASON             keep PATH and name it in the terminal record
#   fge_resource_mark LABEL              take a resource sample; deltas vs the previous
#                                        mark are recorded (rss_kb, open fds, child procs)
#   fge_obligation_open ID KIND          open a typed obligation
#   fge_obligation_close ID              close it; outstanding obligations at terminal
#                                        are a containment failure, never a warning
#   fge_position AUTHORITY GENERATION POLICY   sticky authority/generation/policy position
#   fge_context KEY VALUE                sticky domain field on every later record
#   fge_field   KEY VALUE                domain field on the NEXT record only
#
# Cleanup
#   fge_cleanup_register CMD [ARG...]    LIFO; each runs as a cleanup-phase step. A
#                                        failing cleanup fails the run
#                                        (terminal.cleanup_state = "failed").
#
# JSON / NDJSON (used by run_all.sh; available to scripts)
#   fge_json_validate_line LINE          0 iff LINE is one complete JSON *object*
#   fge_json_top LINE                    parse top level into FGE_JSON[<key>] = raw JSON
#   fge_json_unquote RAW                 JSON string literal -> bytes
#   fge_json_array_strings RAW           JSON array of strings -> FGE_JSON_ARRAY[]
#   fge_json_escape TEXT                 bytes -> JSON string body (no surrounding quotes)
#
# -----------------------------------------------------------------------------
# 4. ENVIRONMENT INPUTS (all optional; every one is echoed into the record)
# -----------------------------------------------------------------------------
#   FGE_SEED           deterministic seed. Default: sha256(script_id) prefix, i.e.
#                      STABLE ACROSS RUNS. The harness never seeds from the clock
#                      or $RANDOM; an unreproducible default would make every
#                      replay command a lie.
#   FGE_SCHEDULE       free-form schedule label recorded in determinism.schedule
#   FGE_FAILPOINT      name of the failpoint to arm (see fge_failpoint)
#   FGE_ATTEMPT        attempt number, set by run_all.sh on retries (default 1)
#   FGE_ARTIFACT_ROOT  default: <repo>/target/e2e-artifacts
#   FGE_RUN_DIR        exact artifact dir for this run (overrides the derived one)
#   FGE_PROFILE        cargo profile label recorded in env.profile (default "debug")
#   FGE_FEATURES       feature list recorded in env.features
#   FGE_TARGET         target triple recorded in env.target
#   FGE_KEEP_LOCALE=1  do not normalise LC_ALL=C for the run
#   FGE_KEEP_TEMP=1    never delete fge_tempdir directories, even on success
#   FGE_MAX_CAPTURE    bytes of stdout/stderr inlined into a record (default 4096;
#                      the FULL stream is always kept as an artifact regardless)
#
# -----------------------------------------------------------------------------
# 5. THE NDJSON EVIDENCE STREAM
# -----------------------------------------------------------------------------
# Every step, assertion, failpoint, artifact registration, cleanup action and
# the terminal summary emit exactly ONE record. Each record is written twice:
#   * to stderr, raw, one line, never suppressed; and
#   * appended to  <run_dir>/e2e.ndjson .
# stdout is left entirely to the script under test.
#
# BASE RECORD -- every key below is ALWAYS present; `null` means not applicable.
# Uniform presence is what lets the validator be strict instead of heuristic.
#
# {
#   "schema":"frankengit.e2e.v1",       // fixed
#   "schema_version":1,
#   "kind":"run_begin|step|assert|failpoint|artifact|cleanup|note|terminal",
#   "ts":"2026-08-21T02:31:50.123456Z", // UTC, microsecond when available
#   "epoch_ns":1787279510123456000,     // integer nanoseconds since the epoch
#   "elapsed_ms":42,                    // since fge_init, the logical clock
#   "seq":3,                            // logical sequence, 1..N, unique, no gaps
#   "run_id":"20260821T023150Z-12345-a1b2c3d4",
#   "attempt":1,
#   "script":"scripts/e2e/suites/foo/bar.sh",   // repo-relative when possible
#   "script_id":"suites-foo-bar",
#   "acceptance_id":"FG-000A-DEMO-002",         // non-null exactly on kind="assert"
#   "phase":"setup|action|assert|failpoint|cleanup|teardown",
#   "step":"seed-repo",
#   "env":{"harness":"frankengit-e2e","harness_version":1,
#          "revision":"<git sha or unknown>","revision_dirty":true|false|null,
#          "toolchain":"<rust-toolchain.toml channel>","target":"...",
#          "features":"","profile":"debug","os":"Linux","kernel":"...",
#          "bash":"5.2.37","digest_tool":"sha256sum","timeout_impl":"coreutils",
#          "time_resolution":"us","tz":"UTC","locale":"C"},
#   "determinism":{"seed":"...","schedule":"...","failpoint":"...",
#                  "failpoint_active":false},
#   "cmd":{"display":"cargo check -p fgit-types","digest":"sha256:...",
#          "argc":3,"redacted":false} | null,
#   "result":{"status":"pass|fail|skip|unsupported|error|timeout|info",
#             "exit_code":0|null,"duration_ms":12|null,
#             "expected":<string|null>,"actual":<string|null>,"detail":<string|null>},
#   "position":{"authority_head":null,"generation":null,"policy":null},
#   "resources":{"rss_kb":null,"rss_kb_delta":null,"fds":null,"fds_delta":null,
#                "procs":null,"procs_delta":null},
#   "obligations":{"opened":0,"closed":0,"outstanding":0},
#   "artifacts":[{"name":"stdout","path":"...","digest":"sha256:...","bytes":12}],
#   "fields":{},                         // domain beads put THEIR typed fields here
#   "replay":"FGE_SEED=... scripts/e2e/suites/foo/bar.sh"
# }
#
# TERMINAL RECORD -- kind="terminal", always the LAST line of the log, adds:
#
#   "terminal":{
#     "status":"pass|fail",
#     "exit_code":0,
#     "wall_ms":1234,
#     "assertions_discovered":7,
#     "assertion_ids":[...],            // first-emission order
#     "passed":6,"failed":1,"skipped":0,"unsupported":0,"errors":0,"timeouts":0,
#     "passed_ids":[...],"failed_ids":[...],"skipped_ids":[...],
#     "unsupported_ids":[...],"error_ids":[...],
#     "duplicate_ids":[...],            // an ID emitted more than once
#     "first_attempt_status":"fail",    // preserved across fge_retry
#     "cleanup_state":"ok|failed|skipped","cleanup_failures":[...],
#     "containment":"ok|failed","orphans":[...],
#     "obligations_outstanding":0,
#     "preserved":[{"path":"...","reason":"..."}],
#     "artifact_dir":"...","log_path":"...",
#     "zero_assertions":false,
#     "record_count":12
#   }
#
# TERMINAL NON-PASS RULES, enforced here and re-checked by run_all.sh:
#   * any failed / error / timeout assertion       -> fail
#   * any skipped or unsupported assertion         -> fail  (a skipped required cell
#                                                    is a terminal non-pass state,
#                                                    never a quiet success)
#   * zero discovered assertions                   -> fail  (a script that exits 0
#                                                    while proving nothing is the
#                                                    single most dangerous false green)
#   * duplicate acceptance ID                      -> fail
#   * failing cleanup                              -> fail
#   * outstanding obligation or orphan process     -> fail (containment)
#
# -----------------------------------------------------------------------------
# 6. DETERMINISM AND REPLAY
# -----------------------------------------------------------------------------
# The default seed is derived from the script id, so a bare re-run reproduces
# the same schedule. `fge_replay_command` prints the seed, schedule, failpoint
# and attempt explicitly, so the printed command reproduces the run even if the
# defaults later change. Time, PID and the run id are the only intentionally
# varying inputs and none of them feeds fge_rand.
#
# -----------------------------------------------------------------------------
# 7. FAILURE PRESERVATION
# -----------------------------------------------------------------------------
# On a failing run the harness keeps: the full NDJSON log, every captured
# stdout/stderr stream, every `fge_tempdir` work directory, everything named by
# `fge_preserve`, and the replay command -- all under one run directory whose
# path is printed on stderr as the last line. Nothing is deleted on the failure
# path, including when the failure is a cleanup failure.
#
# -----------------------------------------------------------------------------
# 8. CONCURRENCY
# -----------------------------------------------------------------------------
# Sequence numbers and assertion bookkeeping live in files under the run dir,
# not in shell variables, so records emitted from background subshells are
# still unique, gapless and counted.
#
# Sequence allocation is LOCK-FREE. A writer claims number n by creating
# `.state/seq.d/<n>` with O_EXCL; the kernel guarantees exactly one winner per
# n and a loser retries n+1. There is deliberately no mutex: the mkdir-mutex
# version this replaced needed a stale-lock breaker, and "read the holder pid,
# check it is dead, remove the lock" is an ABA race that can delete a lock a
# third writer has legitimately taken, handing two writers the same number.
# That reproduced in two runs out of three under 24 concurrent writers.
#
# Record bytes are appended outside any critical section through a dedicated
# O_APPEND descriptor in a single write, so records may land out of order.
# What holds is that the seq values of a complete log form exactly {1..N} --
# which is why the validator checks the SET rather than the file order, and why
# a lost record shows up as a gap rather than as silence.
#
# -----------------------------------------------------------------------------
# 9. SEAM FOR FG-091 (exact expected-suite manifest)
# -----------------------------------------------------------------------------
# run_all.sh emits, per run, a machine-readable receipt containing the exact
# discovered / selected / started / passed / failed / skipped / unsupported /
# timed-out / malformed-log / missing-terminal / zero-assertion /
# duplicate-id ID sets. FG-091 layers required-set equality against a
# checked-in manifest on top of that receipt. This library deliberately
# contains NO manifest, NO allowlist generated from discovery, and NO minimum
# script count: each of those is a documented false-green mechanism.
# =============================================================================


# --- strict mode ------------------------------------------------------------
set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

if [ -z "${BASH_VERSINFO:-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
  { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 4 ]; }; then
  printf 'fge: unsupported: bash >= 4.4 is required, found %s\n' "${BASH_VERSION:-unknown}" >&2
  exit 4
fi

FGE_HARNESS_VERSION=1
FGE_SCHEMA='frankengit.e2e.v1'
FGE_SCHEMA_VERSION=1

# --- internal state ---------------------------------------------------------
FGE_INITIALIZED=0
FGE_RUN_ID=''
FGE_SCRIPT=''
FGE_SCRIPT_ID=''
FGE_PHASE='setup'
FGE_START_NS=0
FGE_LOG=''
FGE_LOG_FD=''
FGE_STATE_DIR=''
FGE_ARTIFACT_DIR=''
FGE_REPO_ROOT=''
FGE_DIGEST_TOOL=''
FGE_TIME_RES='s'
FGE_TIMEOUT_IMPL='bash'
FGE_ENV_JSON='{}'
FGE_REPLAY_CMD=''
FGE_FAILED=0
FGE_FIRST_ATTEMPT_STATUS=''
FGE_CLEANUP_STATE='skipped'
FGE_IN_TERMINAL=0
FGE_LAST_EXIT=0
FGE_LAST_DURATION_MS=0
FGE_LAST_STEP=''
FGE_LAST_PID=''
FGE_LAST_STDOUT=''
FGE_LAST_STDERR=''
FGE_LAST_STDOUT_FILE=''
FGE_LAST_STDERR_FILE=''
FGE_LAST_ASSERT_OK=0
FGE_POS_AUTHORITY='null'
FGE_POS_GENERATION='null'
FGE_POS_POLICY='null'
FGE_RES_RSS=''
FGE_RES_FDS=''
FGE_RES_PROCS=''
FGE_RES_RSS_DELTA=''
FGE_RES_FDS_DELTA=''
FGE_RES_PROCS_DELTA=''
FGE_RAND_STATE=1
FGE_PENDING_ARTIFACTS='[]'
FGE__E=''
FGE__R=''
FGE__J=''

declare -a FGE_SECRETS=()
declare -a FGE_SECRET_LABELS=()
declare -a FGE_CLEANUP_CMDS=()
declare -a FGE_CLEANUP_FAILED_LIST=()
declare -a FGE_TEMPDIRS=()
declare -a FGE_SPAWN_NAMES=()
declare -a FGE_SPAWN_PIDS=()
declare -a FGE_ORPHANS=()
declare -a FGE_PRESERVED_PATHS=()
declare -a FGE_PRESERVED_REASONS=()
declare -A FGE_CONTEXT_FIELDS=()
declare -A FGE_NEXT_FIELDS=()
declare -A FGE_ARTIFACT_DIGESTS=()
declare -A FGE_OBLIGATIONS=()
declare -A FGE__DIGEST_CACHE=()
declare -A FGE_JSON=()
declare -a FGE_JSON_ARRAY=()

# =============================================================================
# JSON encoding
#
# Every helper below writes into a global instead of printing, and callers
# append to the FGE__J accumulator. That is not micro-optimisation for its own
# sake: a command substitution per field costs a fork, and at ~25 fields per
# record the harness was spending more time forking than the steps it measures,
# which distorts the very durations it exists to report.
# =============================================================================

# fge__esc TEXT -> FGE__E
fge__esc() {
  local s=${1-}
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}
  s=${s//$'\r'/\\r}
  s=${s//$'\t'/\\t}
  s=${s//$'\b'/\\b}
  s=${s//$'\f'/\\f}
  if [[ $s == *[$'\001'-$'\037']* ]]; then
    local n oct ch esc
    for n in 1 2 3 4 5 6 7 11 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31; do
      printf -v oct '%03o' "$n"
      printf -v ch "\\$oct"
      [[ $s == *"$ch"* ]] || continue
      printf -v esc '\\u%04x' "$n"
      s=${s//"$ch"/"$esc"}
    done
  fi
  FGE__E=$s
}

# fge_json_escape TEXT -> JSON string body on stdout (no surrounding quotes).
# Bytes >= 0x20 other than '"' and '\' pass through unchanged, so valid UTF-8
# input stays valid UTF-8 output without the harness needing to decode it.
fge_json_escape() {
  fge__esc "${1-}"
  printf '%s' "$FGE__E"
}

# fge__jstr KEY VALUE   -> appends "key":"redacted-escaped-value"
fge__jstr() {
  fge__redact_v "${2-}"
  fge__esc "$FGE__R"
  local v=$FGE__E
  fge__esc "$1"
  FGE__J+="\"$FGE__E\":\"$v\""
}

# fge__jstrn KEY VALUE  -> as fge__jstr, but an empty VALUE becomes null
fge__jstrn() {
  if [ -z "${2-}" ]; then
    fge__esc "$1"
    FGE__J+="\"$FGE__E\":null"
  else
    fge__jstr "$1" "$2"
  fi
}

# fge__jraw KEY RAW_JSON -> appends "key":RAW_JSON
fge__jraw() {
  fge__esc "$1"
  FGE__J+="\"$FGE__E\":${2}"
}

# fge__jnum KEY NUMBER -> appends "key":NUMBER, or "key":null when not an integer
fge__jnum() {
  fge__esc "$1"
  local v=${2-}
  if [[ $v =~ ^-?[0-9]+$ ]]; then
    FGE__J+="\"$FGE__E\":$v"
  else
    FGE__J+="\"$FGE__E\":null"
  fi
}

# fge__jarr_str_into ELEMENT... -> appends a JSON array of strings
fge__jarr_str_into() {
  local e first=1
  FGE__J+='['
  for e in "$@"; do
    [ "$first" -eq 1 ] || FGE__J+=','
    first=0
    fge__redact_v "$e"
    fge__esc "$FGE__R"
    FGE__J+="\"$FGE__E\""
  done
  FGE__J+=']'
}

# fge__jassoc_into NAME -> appends a JSON object built from an associative array,
# with keys emitted in a stable sorted order so two runs produce byte-identical
# records for identical content (map iteration order is never observable here).
fge__jassoc_into() {
  local -n _src=$1
  local first=1 k
  local -a keys=()
  for k in "${!_src[@]}"; do keys+=("$k"); done
  if [ "${#keys[@]}" -gt 1 ]; then
    local -a sorted=()
    local IFS=$'\n'
    read -r -d '' -a sorted < <(printf '%s\n' "${keys[@]}" | LC_ALL=C sort && printf '\0') || true
    keys=("${sorted[@]}")
  fi
  FGE__J+='{'
  for k in "${keys[@]+"${keys[@]}"}"; do
    [ "$first" -eq 1 ] || FGE__J+=','
    first=0
    fge__jstr "$k" "${_src[$k]}"
  done
  FGE__J+='}'
}

# =============================================================================
# JSON scanning (pure bash, byte oriented, no external tool)
#
# Two phases, because a character-at-a-time scan of a 2 KB evidence record in
# bash costs more than the step it describes:
#
#   Phase A  every string literal is lifted out in bulk with parameter
#            expansion, validated with one regex, and replaced in the text by a
#            single SOH byte (0x01). SOH is reserved: a raw byte in 0x00-0x1F
#            is illegal JSON both inside a string and outside one, so any line
#            containing one is rejected before phase A runs and the placeholder
#            can never collide with real input.
#   Phase B  what remains -- the skeleton -- is only braces, brackets, commas,
#            colons, numbers, literals, whitespace and placeholders, and is an
#            order of magnitude shorter than the record. That is what the
#            character scanner walks.
#
# The result is a complete JSON validator, not a shape check: a line the
# harness did not write is judged by the grammar, which is what makes the
# planted malformed-NDJSON case a real negative.
# =============================================================================

FGE__SKEL=''
declare -a FGE__STRINGS=()
# A JSON string body: any byte except '"' and '\', or a valid escape.
FGE__STR_ERE='^([^"\\]|\\(["\\/bfnrt]|u[0-9a-fA-F]{4}))*$'

# fge__split_strings LINE -> FGE__SKEL + FGE__STRINGS[] ; 1 if a literal is bad
fge__split_strings() {
  local s=${1-}
  FGE__SKEL=''
  FGE__STRINGS=()
  # Raw control bytes are illegal JSON anywhere, and 0x01 is the placeholder.
  case $s in
    *[$'\001'-$'\010'$'\013'$'\014'$'\016'-$'\037']*) return 1 ;;
  esac
  local out='' pre seg body t nb
  while [[ $s == *'"'* ]]; do
    pre=${s%%'"'*}
    out+=$pre
    s=${s#"$pre"}
    s=${s:1}
    body=''
    while :; do
      seg=${s%%'"'*}
      [ "$seg" = "$s" ] && return 1
      t=$seg
      nb=0
      while [[ $t == *'\' ]]; do
        t=${t%'\'}
        nb=$((nb + 1))
      done
      body+=$seg
      s=${s#"$seg"}
      s=${s:1}
      if [ $((nb % 2)) -eq 0 ]; then break; fi
      body+='"'
    done
    [[ $body =~ $FGE__STR_ERE ]] || return 1
    # Tab, LF and CR are legal JSON whitespace BETWEEN tokens, so the up-front
    # control-byte filter has to let them through -- but RFC 8259 still forbids
    # them unescaped INSIDE a string. Re-check them here, per body. The grammar
    # corpus caught a raw tab being accepted without this.
    case $body in
      *[$'\011'$'\012'$'\015']*) return 1 ;;
    esac
    FGE__STRINGS+=("$body")
    out+=$'\001'
  done
  FGE__SKEL="$out$s"
  return 0
}

# --- skeleton scanner -------------------------------------------------------
FGE__SP=0
FGE__SL=0
FGE__SN=0

fge__sk_ws() {
  local c
  while [ "$FGE__SP" -lt "$FGE__SL" ]; do
    c=${FGE__SKEL:FGE__SP:1}
    case $c in
      ' ' | $'\t' | $'\n' | $'\r') FGE__SP=$((FGE__SP + 1)) ;;
      *) return 0 ;;
    esac
  done
  return 0
}

fge__sk_number() {
  local start=$FGE__SP c
  [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
  if [ "${FGE__SKEL:FGE__SP:1}" = '-' ]; then FGE__SP=$((FGE__SP + 1)); fi
  [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
  c=${FGE__SKEL:FGE__SP:1}
  if [ "$c" = '0' ]; then
    FGE__SP=$((FGE__SP + 1))
  elif [[ $c == [1-9] ]]; then
    while [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [0-9] ]]; do
      FGE__SP=$((FGE__SP + 1))
    done
  else
    return 1
  fi
  if [ "$FGE__SP" -lt "$FGE__SL" ] && [ "${FGE__SKEL:FGE__SP:1}" = '.' ]; then
    FGE__SP=$((FGE__SP + 1))
    { [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [0-9] ]]; } || return 1
    while [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [0-9] ]]; do
      FGE__SP=$((FGE__SP + 1))
    done
  fi
  if [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [eE] ]]; then
    FGE__SP=$((FGE__SP + 1))
    if [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [+-] ]]; then
      FGE__SP=$((FGE__SP + 1))
    fi
    { [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [0-9] ]]; } || return 1
    while [ "$FGE__SP" -lt "$FGE__SL" ] && [[ ${FGE__SKEL:FGE__SP:1} == [0-9] ]]; do
      FGE__SP=$((FGE__SP + 1))
    done
  fi
  [ "$FGE__SP" -gt "$start" ] || return 1
  return 0
}

fge__sk_literal() {
  local want=$1 n=${#1}
  [ "${FGE__SKEL:FGE__SP:n}" = "$want" ] || return 1
  FGE__SP=$((FGE__SP + n))
  return 0
}

fge__sk_value() {
  fge__sk_ws
  [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
  case ${FGE__SKEL:FGE__SP:1} in
    $'\001')
      FGE__SP=$((FGE__SP + 1))
      FGE__SN=$((FGE__SN + 1))
      return 0
      ;;
    '{') fge__sk_object ;;
    '[') fge__sk_array ;;
    t) fge__sk_literal true ;;
    f) fge__sk_literal false ;;
    n) fge__sk_literal null ;;
    *) fge__sk_number ;;
  esac
}

fge__sk_object() {
  [ "${FGE__SKEL:FGE__SP:1}" = '{' ] || return 1
  FGE__SP=$((FGE__SP + 1))
  fge__sk_ws
  [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
  if [ "${FGE__SKEL:FGE__SP:1}" = '}' ]; then
    FGE__SP=$((FGE__SP + 1))
    return 0
  fi
  while :; do
    fge__sk_ws
    # A member name must be a string, i.e. a placeholder in the skeleton.
    [ "${FGE__SKEL:FGE__SP:1}" = $'\001' ] || return 1
    FGE__SP=$((FGE__SP + 1))
    FGE__SN=$((FGE__SN + 1))
    fge__sk_ws
    [ "${FGE__SKEL:FGE__SP:1}" = ':' ] || return 1
    FGE__SP=$((FGE__SP + 1))
    fge__sk_value || return 1
    fge__sk_ws
    [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
    case ${FGE__SKEL:FGE__SP:1} in
      ',') FGE__SP=$((FGE__SP + 1)) ;;
      '}')
        FGE__SP=$((FGE__SP + 1))
        return 0
        ;;
      *) return 1 ;;
    esac
  done
}

fge__sk_array() {
  [ "${FGE__SKEL:FGE__SP:1}" = '[' ] || return 1
  FGE__SP=$((FGE__SP + 1))
  fge__sk_ws
  [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
  if [ "${FGE__SKEL:FGE__SP:1}" = ']' ]; then
    FGE__SP=$((FGE__SP + 1))
    return 0
  fi
  while :; do
    fge__sk_value || return 1
    fge__sk_ws
    [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
    case ${FGE__SKEL:FGE__SP:1} in
      ',') FGE__SP=$((FGE__SP + 1)) ;;
      ']')
        FGE__SP=$((FGE__SP + 1))
        return 0
        ;;
      *) return 1 ;;
    esac
  done
}

# fge__unskel START END STRING_INDEX -> the original JSON text of that slice,
# with placeholders expanded back into quoted string literals.
fge__unskel() {
  local start=$1 end=$2 idx=$3 i c out=''
  for ((i = start; i < end; i++)); do
    c=${FGE__SKEL:i:1}
    if [ "$c" = $'\001' ]; then
      out+="\"${FGE__STRINGS[$idx]}\""
      idx=$((idx + 1))
    else
      out+=$c
    fi
  done
  printf '%s' "$out"
}

# fge_json_validate_line LINE -> 0 iff LINE is exactly one complete JSON object.
fge_json_validate_line() {
  fge__split_strings "${1-}" || return 1
  FGE__SL=${#FGE__SKEL}
  FGE__SP=0
  FGE__SN=0
  fge__sk_ws
  [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
  [ "${FGE__SKEL:FGE__SP:1}" = '{' ] || return 1
  fge__sk_object || return 1
  fge__sk_ws
  [ "$FGE__SP" -eq "$FGE__SL" ] || return 1
  return 0
}

# fge_json_top LINE -> populates FGE_JSON[key]=<raw json value>. Returns 1 on
# malformed input or on a duplicate key: a duplicate key in evidence is a
# defect to report, not two values to silently merge.
fge_json_top() {
  FGE_JSON=()
  fge__split_strings "${1-}" || return 1
  FGE__SL=${#FGE__SKEL}
  FGE__SP=0
  FGE__SN=0
  fge__sk_ws
  { [ "$FGE__SP" -lt "$FGE__SL" ] && [ "${FGE__SKEL:FGE__SP:1}" = '{' ]; } || return 1
  FGE__SP=$((FGE__SP + 1))
  fge__sk_ws
  if [ "$FGE__SP" -lt "$FGE__SL" ] && [ "${FGE__SKEL:FGE__SP:1}" = '}' ]; then
    FGE__SP=$((FGE__SP + 1))
    fge__sk_ws
    [ "$FGE__SP" -eq "$FGE__SL" ] || return 1
    return 0
  fi
  local key vstart vend nstart
  while :; do
    fge__sk_ws
    [ "${FGE__SKEL:FGE__SP:1}" = $'\001' ] || return 1
    key=$(fge_json_unquote "\"${FGE__STRINGS[$FGE__SN]}\"") || return 1
    FGE__SP=$((FGE__SP + 1))
    FGE__SN=$((FGE__SN + 1))
    [ -z "${FGE_JSON[$key]+x}" ] || return 1
    fge__sk_ws
    [ "${FGE__SKEL:FGE__SP:1}" = ':' ] || return 1
    FGE__SP=$((FGE__SP + 1))
    fge__sk_ws
    vstart=$FGE__SP
    nstart=$FGE__SN
    fge__sk_value || return 1
    vend=$FGE__SP
    FGE_JSON[$key]=$(fge__unskel "$vstart" "$vend" "$nstart")
    fge__sk_ws
    [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
    case ${FGE__SKEL:FGE__SP:1} in
      ',') FGE__SP=$((FGE__SP + 1)) ;;
      '}')
        FGE__SP=$((FGE__SP + 1))
        fge__sk_ws
        [ "$FGE__SP" -eq "$FGE__SL" ] || return 1
        return 0
        ;;
      *) return 1 ;;
    esac
  done
}

# fge_json_unquote RAW -> decoded bytes of a JSON string literal.
# \uXXXX below 0x80 is decoded exactly; at or above 0x80 the literal escape is
# preserved rather than guessed at, because a wrong transcoding of evidence is
# worse than an undecoded one.
fge_json_unquote() {
  local raw=${1-}
  case $raw in
    '"'*'"') ;;
    *)
      printf '%s' "$raw"
      return 0
      ;;
  esac
  raw=${raw:1:${#raw}-2}
  if [[ $raw != *'\'* ]]; then
    printf '%s' "$raw"
    return 0
  fi
  local out='' i=0 n=${#raw} c d hex code
  while [ "$i" -lt "$n" ]; do
    c=${raw:i:1}
    if [ "$c" != '\' ]; then
      out+=$c
      i=$((i + 1))
      continue
    fi
    i=$((i + 1))
    d=${raw:i:1}
    i=$((i + 1))
    case $d in
      n) out+=$'\n' ;;
      r) out+=$'\r' ;;
      t) out+=$'\t' ;;
      b) out+=$'\b' ;;
      f) out+=$'\f' ;;
      '"') out+='"' ;;
      '\') out+='\' ;;
      '/') out+='/' ;;
      u)
        hex=${raw:i:4}
        i=$((i + 4))
        code=$((16#$hex))
        if [ "$code" -lt 128 ] && [ "$code" -gt 0 ]; then
          printf -v c "\\$(printf '%03o' "$code")"
          out+=$c
        else
          out+="\\u$hex"
        fi
        ;;
      *) return 1 ;;
    esac
  done
  printf '%s' "$out"
}

# fge_json_array_strings RAW -> FGE_JSON_ARRAY=(elem...)
# Returns 1 unless RAW is an array whose every element is a string.
fge_json_array_strings() {
  FGE_JSON_ARRAY=()
  local raw=${1-}
  fge__split_strings "$raw" || return 1
  FGE__SL=${#FGE__SKEL}
  FGE__SP=0
  FGE__SN=0
  fge__sk_ws
  { [ "$FGE__SP" -lt "$FGE__SL" ] && [ "${FGE__SKEL:FGE__SP:1}" = '[' ]; } || return 1
  FGE__SP=$((FGE__SP + 1))
  fge__sk_ws
  if [ "$FGE__SP" -lt "$FGE__SL" ] && [ "${FGE__SKEL:FGE__SP:1}" = ']' ]; then
    FGE__SP=$((FGE__SP + 1))
    fge__sk_ws
    [ "$FGE__SP" -eq "$FGE__SL" ] || return 1
    return 0
  fi
  while :; do
    fge__sk_ws
    [ "${FGE__SKEL:FGE__SP:1}" = $'\001' ] || return 1
    FGE_JSON_ARRAY+=("$(fge_json_unquote "\"${FGE__STRINGS[$FGE__SN]}\"")")
    FGE__SP=$((FGE__SP + 1))
    FGE__SN=$((FGE__SN + 1))
    fge__sk_ws
    [ "$FGE__SP" -lt "$FGE__SL" ] || return 1
    case ${FGE__SKEL:FGE__SP:1} in
      ',') FGE__SP=$((FGE__SP + 1)) ;;
      ']')
        FGE__SP=$((FGE__SP + 1))
        fge__sk_ws
        [ "$FGE__SP" -eq "$FGE__SL" ] || return 1
        return 0
        ;;
      *) return 1 ;;
    esac
  done
}
# =============================================================================
# Digests
# =============================================================================

fge__detect_digest_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    FGE_DIGEST_TOOL=sha256sum
  elif command -v shasum >/dev/null 2>&1; then
    FGE_DIGEST_TOOL=shasum
  elif command -v openssl >/dev/null 2>&1; then
    FGE_DIGEST_TOOL=openssl
  else
    return 1
  fi
  return 0
}

# Input arrives on stdin so file names never have to survive a quoting round
# trip; paths with spaces, newlines or Unicode are therefore not special.
fge__digest_stdin() {
  case $FGE_DIGEST_TOOL in
    sha256sum) sha256sum | cut -d' ' -f1 ;;
    shasum) shasum -a 256 | cut -d' ' -f1 ;;
    openssl) openssl dgst -sha256 | tr -d ' ' | sed 's/.*=//' ;;
    *) return 1 ;;
  esac
}

fge_digest_file() {
  local f=${1-}
  [ -r "$f" ] || return 1
  fge__digest_stdin <"$f"
}

fge_digest_string() { printf '%s' "${1-}" | fge__digest_stdin; }

fge_cmd_digest() {
  local a out=''
  for a in "$@"; do out+="$a"$'\037'; done
  printf '%s' "$out" | fge__digest_stdin
}

# Cached because redaction hashes the same secret-shaped value on every record.
fge__digest_cached() {
  local v=${1-}
  if [ -z "${FGE__DIGEST_CACHE[$v]+x}" ]; then
    FGE__DIGEST_CACHE[$v]=$(fge_digest_string "$v")
  fi
  printf '%s' "${FGE__DIGEST_CACHE[$v]}"
}

# =============================================================================
# Time
# =============================================================================

fge__now_ns() {
  local er=${EPOCHREALTIME:-}
  if [ -n "$er" ]; then
    local s=${er%%[.,]*} frac=${er#*[.,]}
    frac=${frac}000000
    frac=${frac:0:6}
    printf '%s%s000' "$s" "$frac"
    return 0
  fi
  local d
  d=$(date +%s%N 2>/dev/null || printf '')
  if [[ $d =~ ^[0-9]+$ ]] && [ "${#d}" -ge 19 ]; then
    printf '%s' "$d"
    return 0
  fi
  d=$(date +%s)
  printf '%s000000000' "$d"
}

# fge__iso_ts NS -> FGE__TS  (UTC, no fork: printf's %(fmt)T with a TZ prefix
# assignment, which bash scopes to the builtin call and does not leak.)
fge__iso_ts() {
  local ns=$1 s frac out
  s=${ns:0:${#ns}-9}
  frac=${ns: -9}
  [ -n "$s" ] || s=0
  TZ=UTC printf -v out '%(%Y-%m-%dT%H:%M:%S)T' "$s"
  case $FGE_TIME_RES in
    us) FGE__TS="$out.${frac:0:6}Z" ;;
    ns) FGE__TS="$out.${frac}Z" ;;
    *) FGE__TS="${out}Z" ;;
  esac
}
FGE__TS=''

# =============================================================================
# Secrets and redaction
# =============================================================================

FGE_SECRET_KEY_ERE='(TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|APIKEY|API_KEY|PRIVATEKEY|PRIVATE_KEY|CREDENTIAL|CREDENTIALS|AUTHORIZATION|BEARER|COOKIE|SESSION_KEY|ACCESS_KEY|SIGNING_KEY)'

# fge_register_secret VALUE [LABEL]
# Refuses values shorter than 4 bytes: masking such a value would corrupt
# unrelated evidence text, which is a worse outcome than not masking it.
fge_register_secret() {
  local value=${1-} label=${2:-secret}
  if [ "${#value}" -lt 4 ]; then
    printf 'fge: refused: secret shorter than 4 bytes cannot be registered (label=%s)\n' \
      "$label" >&2
    return 2
  fi
  local i
  for i in "${!FGE_SECRETS[@]}"; do
    [ "${FGE_SECRETS[$i]}" = "$value" ] && return 0
  done
  local d
  d=$(fge_digest_string "$value")
  FGE_SECRETS+=("$value")
  FGE_SECRET_LABELS+=("<redacted:${label}:${d:0:8}>")
  return 0
}

# fge__redact_v TEXT -> FGE__R
fge__redact_v() {
  local s=${1-} i
  for i in "${!FGE_SECRETS[@]}"; do
    s=${s//"${FGE_SECRETS[$i]}"/"${FGE_SECRET_LABELS[$i]}"}
  done
  if [[ $s == *=* ]]; then
    local -a toks=()
    local tok out='' first=1 k v ku dv
    IFS=' ' read -r -a toks <<<"$s" || true
    for tok in "${toks[@]+"${toks[@]}"}"; do
      if [[ $tok == *=* ]]; then
        k=${tok%%=*}
        v=${tok#*=}
        ku=${k^^}
        ku=${ku//[^A-Z_]/}
        if [ -n "$v" ] && [[ $ku =~ $FGE_SECRET_KEY_ERE ]]; then
          dv=$(fge__digest_cached "$v")
          tok="$k=<redacted:${dv:0:8}>"
        fi
      fi
      if [ "$first" -eq 1 ]; then
        out=$tok
        first=0
      else
        out+=" $tok"
      fi
    done
    [ "${#toks[@]}" -gt 0 ] && s=$out
  fi
  FGE__R=$s
}

# fge_redact TEXT -> redacted TEXT on stdout
fge_redact() {
  fge__redact_v "${1-}"
  printf '%s' "$FGE__R"
}

fge__quote_v() {
  local s=${1-}
  if [[ $s =~ ^[A-Za-z0-9_./:=@%+-]+$ ]] && [ -n "$s" ]; then
    FGE__Q=$s
  else
    FGE__Q="'${s//\'/\'\\\'\'}'"
  fi
}
FGE__Q=''

fge__shell_quote() {
  fge__quote_v "${1-}"
  printf '%s' "$FGE__Q"
}

fge__cmd_display_v() {
  local a out='' first=1
  for a in "$@"; do
    [ "$first" -eq 1 ] || out+=' '
    first=0
    fge__quote_v "$a"
    out+=$FGE__Q
  done
  FGE__D=$out
}
FGE__D=''

# =============================================================================
# Deterministic pseudo-randomness
# =============================================================================

fge_seed() { printf '%s' "${FGE_SEED:-}"; }
fge_schedule() { printf '%s' "${FGE_SCHEDULE:-default}"; }

fge__seed_state() {
  local h
  h=$(fge_digest_string "${FGE_SEED}")
  FGE_RAND_STATE=$((16#${h:0:8}))
  [ "$FGE_RAND_STATE" -ne 0 ] || FGE_RAND_STATE=1
}

# 32-bit xorshift, masked at every step, so the sequence is identical on every
# platform and never depends on signed-overflow behaviour.
fge_rand() {
  local max=${1:-2147483648}
  local x=$FGE_RAND_STATE
  x=$(((x ^ (x << 13)) & 0xFFFFFFFF))
  x=$((x ^ (x >> 17)))
  x=$(((x ^ (x << 5)) & 0xFFFFFFFF))
  FGE_RAND_STATE=$x
  [ "$max" -gt 0 ] || max=1
  printf '%s' "$((x % max))"
}

fge_rand_hex() {
  local bytes=${1:-8} out='' i v
  for ((i = 0; i < bytes; i++)); do
    v=$(fge_rand 256)
    printf -v v '%02x' "$v"
    out+=$v
  done
  printf '%s' "$out"
}

fge_failpoint() {
  local name=${1-}
  if [ "${FGE_FAILPOINT:-}" = "$name" ] && [ -n "$name" ]; then
    fge__emit failpoint "$FGE_PHASE" "$name" info '' '' 'armed failpoint fired' '' '' null
    return 0
  fi
  return 1
}

fge__build_replay() {
  local out=''
  fge__quote_v "${FGE_SEED:-}"
  out="FGE_SEED=$FGE__Q"
  fge__quote_v "${FGE_SCHEDULE:-default}"
  out+=" FGE_SCHEDULE=$FGE__Q"
  fge__quote_v "${FGE_FAILPOINT:-}"
  out+=" FGE_FAILPOINT=$FGE__Q"
  fge__quote_v "${FGE_ATTEMPT:-1}"
  out+=" FGE_ATTEMPT=$FGE__Q"
  fge__quote_v "$FGE_SCRIPT"
  out+=" $FGE__Q"
  FGE_REPLAY_CMD=$out
}

fge_replay_command() { printf '%s' "$FGE_REPLAY_CMD"; }

# =============================================================================
# Sequence allocation and record emission
# =============================================================================

# A short mkdir-based mutex. mkdir is the one portable atomic create-or-fail
# primitive available to a shell. The holder PID is recorded so a lock left
# behind by a killed writer is broken rather than deadlocking the run.
# Sequence allocation is a lock-free test-and-set.
#
# The obvious mkdir-mutex-plus-counter is what this replaced, and it was
# subtly, intermittently wrong. Any such mutex needs a way to break a lock left
# behind by a killed writer, and "read the holder pid, check it is dead, remove
# the directory" is an ABA race: between the read and the removal the holder
# can finish normally and a THIRD writer can take the lock, which the breaker
# then deletes out from under it. Two writers then hold the lock and are handed
# the same sequence number. A 24-writer probe reproduced it in two runs out of
# three, and the harness's own concurrency assertions caught it.
#
# So there is no lock. Each writer claims a number by creating seq.d/<n> with
# O_EXCL (`set -C` plus `>`), which the kernel makes atomic: exactly one writer
# can win each n, and a loser simply tries n+1. Correctness rests on O_EXCL
# alone -- no ownership, no liveness check, nothing to leak, and a writer killed
# mid-allocation leaves at most one claimed number behind, which shows up as
# the sequence gap it genuinely is.
#
# seqhint is a pure accelerator: a stale or missing hint costs extra attempts
# and never affects correctness.
fge__next_seq() {
  local n='' had_noclobber=0
  read -r n <"$FGE_STATE_DIR/seqhint" 2>/dev/null || true
  [[ $n =~ ^[0-9]+$ ]] || n=1
  [ "$n" -ge 1 ] || n=1
  case $- in
    *C*) had_noclobber=1 ;;
  esac
  set -C
  while ! { : >"$FGE_STATE_DIR/seq.d/$n"; } 2>/dev/null; do
    n=$((n + 1))
  done
  [ "$had_noclobber" -eq 1 ] || set +C
  printf '%s\n' "$((n + 1))" >|"$FGE_STATE_DIR/seqhint" 2>/dev/null || true
  FGE__SEQ=$n
}
FGE__SEQ=0

# A sub-second wait with no fork and no GNU-only `sleep 0.01`.
#
# fd 9 is a FIFO opened read-write, so a timed read genuinely blocks for the
# timeout. Pointing it at a regular file, as an earlier revision did, is the
# trap: `read -t` on a regular file returns instantly at EOF, which turned this
# into a busy-spin, exhausted the retry budget in microseconds and let
# concurrent writers force the lock -- handing two of them the same sequence
# number. The harness self-test caught it; the comment is here so it is not
# reintroduced.
fge__tick() {
  if [ "$FGE_TICK_KIND" = fifo ]; then
    read -r -t 0.01 -u 9 _ 2>/dev/null || true
  else
    # POSIX sleep only guarantees integer seconds, so a filesystem without
    # FIFOs pays a whole second per contended retry rather than spinning.
    sleep 1 2>/dev/null || true
  fi
}
FGE_TICK_KIND=none


fge__resources_into() {
  FGE__J+='"resources":{'
  fge__jnum rss_kb "$FGE_RES_RSS"
  FGE__J+=','
  fge__jnum rss_kb_delta "$FGE_RES_RSS_DELTA"
  FGE__J+=','
  fge__jnum fds "$FGE_RES_FDS"
  FGE__J+=','
  fge__jnum fds_delta "$FGE_RES_FDS_DELTA"
  FGE__J+=','
  fge__jnum procs "$FGE_RES_PROCS"
  FGE__J+=','
  fge__jnum procs_delta "$FGE_RES_PROCS_DELTA"
  FGE__J+='}'
}

# fge__emit KIND PHASE STEP STATUS EXIT DURATION_MS DETAIL EXPECTED ACTUAL
#           CMD_JSON [ACCEPTANCE_ID] [EXTRA_JSON]
fge__emit() {
  local kind=$1 phase=$2 step=$3 status=$4 exitc=$5 dur=$6 detail=$7
  local expected=$8 actual=$9 cmdjson=${10:-null}
  local acc=${11:-} extra=${12:-}

  local ns elapsed
  ns=$(fge__now_ns)
  fge__iso_ts "$ns"
  fge__next_seq
  elapsed=$(((ns - FGE_START_NS) / 1000000))

  local ob_open=0 ob_closed=0 ob_out=0 k
  for k in "${!FGE_OBLIGATIONS[@]}"; do
    ob_open=$((ob_open + 1))
    if [ "${FGE_OBLIGATIONS[$k]}" = closed ]; then
      ob_closed=$((ob_closed + 1))
    else
      ob_out=$((ob_out + 1))
    fi
  done

  local fp_active=false
  [ "$kind" = failpoint ] && fp_active=true

  FGE__J='{'
  fge__jstr schema "$FGE_SCHEMA"
  FGE__J+=','
  fge__jnum schema_version "$FGE_SCHEMA_VERSION"
  FGE__J+=','
  fge__jstr kind "$kind"
  FGE__J+=','
  fge__jstr ts "$FGE__TS"
  FGE__J+=','
  fge__jnum epoch_ns "$ns"
  FGE__J+=','
  fge__jnum elapsed_ms "$elapsed"
  FGE__J+=','
  fge__jnum seq "$FGE__SEQ"
  FGE__J+=','
  fge__jstr run_id "$FGE_RUN_ID"
  FGE__J+=','
  fge__jnum attempt "${FGE_ATTEMPT:-1}"
  FGE__J+=','
  fge__jstr script "$FGE_SCRIPT"
  FGE__J+=','
  fge__jstr script_id "$FGE_SCRIPT_ID"
  FGE__J+=','
  fge__jstrn acceptance_id "$acc"
  FGE__J+=','
  fge__jstr phase "$phase"
  FGE__J+=','
  fge__jstr step "$step"
  FGE__J+=','
  fge__jraw env "$FGE_ENV_JSON"
  FGE__J+=',"determinism":{'
  fge__jstr seed "${FGE_SEED:-}"
  FGE__J+=','
  fge__jstr schedule "${FGE_SCHEDULE:-default}"
  FGE__J+=','
  fge__jstrn failpoint "${FGE_FAILPOINT:-}"
  FGE__J+=','
  fge__jraw failpoint_active "$fp_active"
  FGE__J+='},'
  fge__jraw cmd "$cmdjson"
  FGE__J+=',"result":{'
  fge__jstr status "$status"
  FGE__J+=','
  fge__jnum exit_code "$exitc"
  FGE__J+=','
  fge__jnum duration_ms "$dur"
  FGE__J+=','
  fge__jstrn expected "$expected"
  FGE__J+=','
  fge__jstrn actual "$actual"
  FGE__J+=','
  fge__jstrn detail "$detail"
  FGE__J+='},"position":{'
  fge__jraw authority_head "$FGE_POS_AUTHORITY"
  FGE__J+=','
  fge__jraw generation "$FGE_POS_GENERATION"
  FGE__J+=','
  fge__jraw policy "$FGE_POS_POLICY"
  FGE__J+='},'
  fge__resources_into
  FGE__J+=',"obligations":{'
  fge__jnum opened "$ob_open"
  FGE__J+=','
  fge__jnum closed "$ob_closed"
  FGE__J+=','
  fge__jnum outstanding "$ob_out"
  FGE__J+='},'
  fge__jraw artifacts "$FGE_PENDING_ARTIFACTS"
  FGE_PENDING_ARTIFACTS='[]'
  FGE__J+=','
  if [ "${#FGE_CONTEXT_FIELDS[@]}" -eq 0 ] && [ "${#FGE_NEXT_FIELDS[@]}" -eq 0 ]; then
    fge__jraw fields '{}'
  else
    local -A _merged=()
    for k in "${!FGE_CONTEXT_FIELDS[@]}"; do _merged[$k]=${FGE_CONTEXT_FIELDS[$k]}; done
    for k in "${!FGE_NEXT_FIELDS[@]}"; do _merged[$k]=${FGE_NEXT_FIELDS[$k]}; done
    fge__esc fields
    FGE__J+="\"$FGE__E\":"
    fge__jassoc_into _merged
  fi
  FGE_NEXT_FIELDS=()
  FGE__J+=','
  fge__jstr replay "$FGE_REPLAY_CMD"
  [ -n "$extra" ] && FGE__J+=",$extra"
  FGE__J+='}'

  printf '%s\n' "$FGE__J" >&2
  if [ -n "$FGE_LOG_FD" ]; then
    printf '%s\n' "$FGE__J" >&"$FGE_LOG_FD"
  fi
  return 0
}

# =============================================================================
# Init and environment capture
# =============================================================================

fge__repo_root() {
  local d=${1:-$PWD}
  while [ "$d" != / ] && [ -n "$d" ]; do
    if [ -e "$d/AGENTS.md" ] && [ -e "$d/Cargo.toml" ]; then
      printf '%s' "$d"
      return 0
    fi
    d=$(dirname "$d")
  done
  printf '%s' "${1:-$PWD}"
}

# Reads the revision from .git directly. Shelling out to `git` for a *test
# harness identity field* would still be a subprocess invocation of foreign
# Git in a repository whose constitution bans exactly that reflex, and a
# 40-byte read is cheaper anyway.
fge__git_revision() {
  local root=$1 head ref l
  [ -r "$root/.git/HEAD" ] || {
    printf 'unknown'
    return 0
  }
  read -r head <"$root/.git/HEAD" 2>/dev/null || head=''
  case $head in
    'ref: '*)
      ref=${head#ref: }
      if [ -r "$root/.git/$ref" ]; then
        read -r l <"$root/.git/$ref" || l=''
        printf '%s' "$l"
        return 0
      fi
      if [ -r "$root/.git/packed-refs" ]; then
        while IFS= read -r l; do
          case $l in
            '#'* | '^'*) continue ;;
          esac
          if [ "${l#* }" = "$ref" ]; then
            printf '%s' "${l%% *}"
            return 0
          fi
        done <"$root/.git/packed-refs"
      fi
      printf 'unknown'
      ;;
    '') printf 'unknown' ;;
    *) printf '%s' "$head" ;;
  esac
}

fge__toolchain() {
  local f=$1/rust-toolchain.toml l
  [ -r "$f" ] || {
    printf 'unknown'
    return 0
  }
  while IFS= read -r l; do
    case $l in
      channel*=*)
        l=${l#*=}
        l=${l//\"/}
        l=${l//\'/}
        l=${l// /}
        printf '%s' "$l"
        return 0
        ;;
    esac
  done <"$f"
  printf 'unknown'
}

fge__build_env_json() {
  local rev dirty tc os kern arch
  rev=$(fge__git_revision "$FGE_REPO_ROOT")
  rev=${rev//[^0-9a-fA-F]/}
  [ -n "$rev" ] || rev=unknown
  tc=$(fge__toolchain "$FGE_REPO_ROOT")
  os=$(uname -s 2>/dev/null || printf 'unknown')
  kern=$(uname -r 2>/dev/null || printf 'unknown')
  arch=$(uname -m 2>/dev/null || printf 'unknown')
  # NOT measured here, and that is deliberate. Comparing a work tree against
  # HEAD requires git, and FG-000A-PORT-020 forbids any harness script from
  # shelling out to it -- the same invariant that makes `fge__git_revision`
  # parse .git/HEAD by hand. There is no pure-bash way to do it, so the harness
  # reports what it actually knows.
  #
  # The change from the previous behaviour is the whole point of this fix. It
  # defaulted to `false`, which asserted a CLEAN TREE THAT WAS NEVER CHECKED,
  # in every record of every suite. A record naming a revision while the tree
  # carried uncommitted edits claims the evidence came from that commit when it
  # did not -- the exact overstatement the SHA-bound-claims rule exists to
  # prevent. `null` says "not determined", which is true; `false` said "clean",
  # which was not.
  #
  # A caller that CAN measure supplies it. That belongs outside scripts/e2e,
  # since everything inside is swept by PORT-020: an orchestrator sweep, CI, or
  # a developer shell exports FGE_REVISION_DIRTY=true|false before invoking.
  # Anything unrecognised stays indeterminate rather than clean, so a malformed
  # override can never manufacture a cleanliness claim.
  dirty=null
  case ${FGE_REVISION_DIRTY:-} in
    true) dirty=true ;;
    false) dirty=false ;;
    *) ;;
  esac

  local saved=$FGE__J
  FGE__J='{'
  fge__jstr harness 'frankengit-e2e'
  FGE__J+=','
  fge__jnum harness_version "$FGE_HARNESS_VERSION"
  FGE__J+=','
  fge__jstr revision "$rev"
  FGE__J+=','
  fge__jraw revision_dirty "$dirty"
  FGE__J+=','
  fge__jstr toolchain "$tc"
  FGE__J+=','
  # target is only claimed when the caller supplies it: guessing a triple from
  # `uname -m` would put an unverified identity into evidence records.
  fge__jstrn target "${FGE_TARGET:-}"
  FGE__J+=','
  fge__jstr arch "$arch"
  FGE__J+=','
  fge__jstr features "${FGE_FEATURES:-}"
  FGE__J+=','
  fge__jstr profile "${FGE_PROFILE:-debug}"
  FGE__J+=','
  fge__jstr os "$os"
  FGE__J+=','
  fge__jstr kernel "$kern"
  FGE__J+=','
  fge__jstr bash "${BASH_VERSION%%(*}"
  FGE__J+=','
  fge__jstr digest_tool "$FGE_DIGEST_TOOL"
  FGE__J+=','
  fge__jstr timeout_impl "$FGE_TIMEOUT_IMPL"
  FGE__J+=','
  fge__jstr time_resolution "$FGE_TIME_RES"
  FGE__J+=','
  fge__jstr tick "$FGE_TICK_KIND"
  FGE__J+=','
  fge__jstr tz 'UTC'
  FGE__J+=','
  fge__jstr locale "${LC_ALL:-inherited}"
  FGE__J+='}'
  FGE_ENV_JSON=$FGE__J
  FGE__J=$saved
}

# fge_init [SCRIPT_ID]
fge_init() {
  if [ "$FGE_INITIALIZED" -ne 0 ]; then
    printf 'fge: fge_init called twice\n' >&2
    return 2
  fi

  fge__detect_digest_tool || {
    printf 'fge: unsupported: no sha-256 helper found (need sha256sum, shasum or openssl)\n' >&2
    exit 4
  }

  if [ -n "${EPOCHREALTIME:-}" ]; then
    FGE_TIME_RES=us
  elif [[ $(date +%N 2>/dev/null || printf x) =~ ^[0-9]{9}$ ]]; then
    FGE_TIME_RES=ns
  else
    FGE_TIME_RES=s
  fi

  if command -v timeout >/dev/null 2>&1; then
    FGE_TIMEOUT_IMPL=coreutils
  else
    FGE_TIMEOUT_IMPL=bash
  fi

  if [ -z "${FGE_KEEP_LOCALE:-}" ]; then
    LC_ALL=C
    export LC_ALL
  fi

  local src=${BASH_SOURCE[1]:-$0} abs dir base
  dir=$(cd "$(dirname "$src")" 2>/dev/null && pwd) || dir=$PWD
  base=$(basename "$src")
  abs="$dir/$base"
  FGE_REPO_ROOT=$(fge__repo_root "$dir")
  case $abs in
    "$FGE_REPO_ROOT"/*) FGE_SCRIPT=${abs#"$FGE_REPO_ROOT"/} ;;
    *) FGE_SCRIPT=$abs ;;
  esac

  if [ -n "${1-}" ]; then
    FGE_SCRIPT_ID=$1
  else
    local id=$FGE_SCRIPT
    id=${id#scripts/e2e/}
    id=${id%.sh}
    id=${id//\//-}
    id=${id//[^A-Za-z0-9._-]/-}
    FGE_SCRIPT_ID=$id
  fi

  if [ -z "${FGE_SEED:-}" ]; then
    local h
    h=$(fge_digest_string "frankengit-e2e:$FGE_SCRIPT_ID")
    FGE_SEED=${h:0:16}
  fi
  export FGE_SEED
  fge__seed_state

  FGE_ATTEMPT=${FGE_ATTEMPT:-1}
  export FGE_ATTEMPT
  fge__build_replay

  FGE_START_NS=$(fge__now_ns)
  fge__iso_ts "$FGE_START_NS"
  local stamp=$FGE__TS
  stamp=${stamp%%.*}
  stamp=${stamp//[:-]/}
  stamp=${stamp%Z}Z
  FGE_RUN_ID="${stamp}-$$-${FGE_SEED:0:8}"

  if [ -n "${FGE_RUN_DIR:-}" ]; then
    FGE_ARTIFACT_DIR=$FGE_RUN_DIR
  else
    FGE_ARTIFACT_DIR="${FGE_ARTIFACT_ROOT:-$FGE_REPO_ROOT/target/e2e-artifacts}/$FGE_SCRIPT_ID/$FGE_RUN_ID"
  fi
  mkdir -p "$FGE_ARTIFACT_DIR" || {
    printf 'fge: cannot create artifact dir %s\n' "$FGE_ARTIFACT_DIR" >&2
    exit 4
  }
  FGE_STATE_DIR="$FGE_ARTIFACT_DIR/.state"
  mkdir -p "$FGE_STATE_DIR"
  : >"$FGE_STATE_DIR/assertions.tsv"
  mkdir -p "$FGE_STATE_DIR/seq.d"
  printf '1\n' >"$FGE_STATE_DIR/seqhint"
  FGE_LOG="$FGE_ARTIFACT_DIR/e2e.ndjson"
  : >"$FGE_LOG"
  exec {FGE_LOG_FD}>>"$FGE_LOG"

  # fd 9 must be a FIFO for fge__tick to actually wait; see its comment.
  rm -f "$FGE_STATE_DIR/.tick"
  if mkfifo "$FGE_STATE_DIR/.tick" 2>/dev/null && exec 9<>"$FGE_STATE_DIR/.tick"; then
    FGE_TICK_KIND=fifo
  else
    FGE_TICK_KIND=sleep
  fi

  fge__build_env_json
  FGE_INITIALIZED=1

  trap 'fge__on_exit $?' EXIT
  trap 'fge__on_signal INT' INT
  trap 'fge__on_signal TERM' TERM
  trap 'fge__on_signal HUP' HUP

  fge_resource_mark init
  fge__emit run_begin setup init info 0 0 'run started' '' '' null
  return 0
}

fge_phase() {
  case ${1-} in
    setup | action | assert | failpoint | cleanup | teardown) FGE_PHASE=$1 ;;
    *)
      printf 'fge: invalid phase %s\n' "${1-}" >&2
      return 2
      ;;
  esac
  return 0
}

fge_context() {
  FGE_CONTEXT_FIELDS[${1-}]=${2-}
  return 0
}

fge_field() {
  FGE_NEXT_FIELDS[${1-}]=${2-}
  return 0
}

fge_position() {
  local a=${1-} g=${2-} p=${3-}
  if [ -n "$a" ]; then
    fge__esc "$a"
    FGE_POS_AUTHORITY="\"$FGE__E\""
  else FGE_POS_AUTHORITY=null; fi
  if [ -n "$g" ]; then
    fge__esc "$g"
    FGE_POS_GENERATION="\"$FGE__E\""
  else FGE_POS_GENERATION=null; fi
  if [ -n "$p" ]; then
    fge__esc "$p"
    FGE_POS_POLICY="\"$FGE__E\""
  else FGE_POS_POLICY=null; fi
  return 0
}

fge_step() { fge__emit step "$FGE_PHASE" "${1-}" info '' '' "${2-}" '' '' null; }
fge_note() { fge__emit note "$FGE_PHASE" "${1-}" info '' '' "${2-}" '' '' null; }

fge_die() {
  local msg=${1-fatal}
  FGE_FAILED=1
  fge__emit note "$FGE_PHASE" "${FGE_LAST_STEP:-fatal}" error '' '' "$msg" '' '' null
  exit 1
}

# =============================================================================
# Resources and obligations
# =============================================================================

fge__read_rss_kb() {
  local l
  if [ -r /proc/self/status ]; then
    while IFS= read -r l; do
      case $l in
        VmRSS:*)
          l=${l#VmRSS:}
          l=${l%%kB*}
          l=${l// /}
          l=${l//$'\t'/}
          printf '%s' "$l"
          return 0
          ;;
      esac
    done </proc/self/status
  fi
  printf ''
}

fge__count_fds() {
  if [ -d /proc/self/fd ]; then
    local n=0 f
    for f in /proc/self/fd/*; do
      [ -e "$f" ] || continue
      n=$((n + 1))
    done
    printf '%s' "$n"
  else
    printf ''
  fi
}

fge__count_procs() {
  local n=0 p
  for p in "${FGE_SPAWN_PIDS[@]+"${FGE_SPAWN_PIDS[@]}"}"; do
    [ -n "$p" ] || continue
    kill -0 "$p" 2>/dev/null && n=$((n + 1))
  done
  printf '%s' "$n"
}

fge_resource_mark() {
  local rss fds procs
  rss=$(fge__read_rss_kb)
  fds=$(fge__count_fds)
  procs=$(fge__count_procs)
  if [[ $FGE_RES_RSS =~ ^[0-9]+$ ]] && [[ $rss =~ ^[0-9]+$ ]]; then
    FGE_RES_RSS_DELTA=$((rss - FGE_RES_RSS))
  else FGE_RES_RSS_DELTA=''; fi
  if [[ $FGE_RES_FDS =~ ^[0-9]+$ ]] && [[ $fds =~ ^[0-9]+$ ]]; then
    FGE_RES_FDS_DELTA=$((fds - FGE_RES_FDS))
  else FGE_RES_FDS_DELTA=''; fi
  if [[ $FGE_RES_PROCS =~ ^[0-9]+$ ]] && [[ $procs =~ ^[0-9]+$ ]]; then
    FGE_RES_PROCS_DELTA=$((procs - FGE_RES_PROCS))
  else FGE_RES_PROCS_DELTA=''; fi
  FGE_RES_RSS=$rss
  FGE_RES_FDS=$fds
  FGE_RES_PROCS=$procs
  return 0
}

fge_obligation_open() {
  local id=${1-} kind=${2:-obligation}
  [ -n "$id" ] || return 2
  FGE_OBLIGATIONS[$id]=open
  fge_field obligation_kind "$kind"
  fge__emit step "$FGE_PHASE" "obligation-open:$id" info '' '' "opened $kind" '' '' null
  return 0
}

fge_obligation_close() {
  local id=${1-}
  [ -n "$id" ] || return 2
  if [ -z "${FGE_OBLIGATIONS[$id]+x}" ]; then
    FGE_FAILED=1
    fge__emit step "$FGE_PHASE" "obligation-close:$id" error '' '' \
      'close of an obligation that was never opened' '' '' null
    return 1
  fi
  FGE_OBLIGATIONS[$id]=closed
  fge__emit step "$FGE_PHASE" "obligation-close:$id" info '' '' 'closed' '' '' null
  return 0
}

# =============================================================================
# Artifacts and work directories
# =============================================================================

fge_artifact_path() {
  local name=${1-}
  case $name in
    '' | /* | *..*)
      printf 'fge: refused: unsafe artifact name %s\n' "$name" >&2
      return 2
      ;;
  esac
  local p="$FGE_ARTIFACT_DIR/$name"
  mkdir -p "$(dirname "$p")"
  printf '%s' "$p"
}

fge__artifact_entry_into() {
  FGE__J+='[{'
  fge__jstr name "$1"
  FGE__J+=','
  fge__jstr path "$2"
  FGE__J+=','
  fge__jstr digest "sha256:$3"
  FGE__J+=','
  fge__jnum bytes "$4"
  FGE__J+='}]'
}

# fge_artifact NAME_OR_PATH [KIND]
fge_artifact() {
  local nameref=${1-} kind=${2:-file} path name
  if [ -e "$nameref" ]; then
    path=$nameref
    case $path in
      "$FGE_ARTIFACT_DIR"/*) name=${path#"$FGE_ARTIFACT_DIR"/} ;;
      *) name=$(basename "$path") ;;
    esac
  else
    name=$nameref
    path="$FGE_ARTIFACT_DIR/$name"
  fi
  if [ ! -f "$path" ]; then
    FGE_FAILED=1
    fge__emit artifact "$FGE_PHASE" "artifact:$name" error '' '' \
      'artifact does not exist' "$path" '' null
    return 1
  fi
  local digest bytes
  digest=$(fge_digest_file "$path")
  bytes=$(wc -c <"$path")
  bytes=${bytes// /}
  # A second registration of the same NAME with different bytes is a collision,
  # not an update: silently overwriting it would let a later step erase the
  # evidence an earlier assertion was judged against.
  if [ -n "${FGE_ARTIFACT_DIGESTS[$name]+x}" ] &&
    [ "${FGE_ARTIFACT_DIGESTS[$name]}" != "$digest" ]; then
    FGE_FAILED=1
    fge__emit artifact "$FGE_PHASE" "artifact:$name" error '' '' \
      'artifact name collision: same name, different content' \
      "${FGE_ARTIFACT_DIGESTS[$name]}" "$digest" null
    return 1
  fi
  FGE_ARTIFACT_DIGESTS[$name]=$digest
  local saved=$FGE__J
  FGE__J=''
  fge__artifact_entry_into "$name" "$path" "$digest" "$bytes"
  FGE_PENDING_ARTIFACTS=$FGE__J
  FGE__J=$saved
  fge__emit artifact "$FGE_PHASE" "artifact:$name" info '' '' "$kind" '' "sha256:$digest" null
  return 0
}

fge_tempdir() {
  local name=${1:-work} d n=0
  d="$FGE_ARTIFACT_DIR/work/$name"
  while [ -e "$d" ]; do
    n=$((n + 1))
    d="$FGE_ARTIFACT_DIR/work/$name.$n"
  done
  mkdir -p "$d"
  FGE_TEMPDIRS+=("$d")
  printf '%s' "$d"
}

fge_preserve() {
  FGE_PRESERVED_PATHS+=("${1-}")
  FGE_PRESERVED_REASONS+=("${2:-preserved}")
  fge__emit step "$FGE_PHASE" 'preserve' info '' '' "${2:-preserved}" '' "${1-}" null
  return 0
}

fge_cleanup_register() {
  local q='' a
  for a in "$@"; do
    fge__quote_v "$a"
    q+="$FGE__Q "
  done
  FGE_CLEANUP_CMDS+=("$q")
  return 0
}

# =============================================================================
# Command execution
# =============================================================================

fge__cmd_json_v() {
  local digest raw redacted=false
  fge__cmd_display_v "$@"
  raw=$FGE__D
  fge__redact_v "$raw"
  [ "$FGE__R" = "$raw" ] || redacted=true
  digest=$(fge_cmd_digest "$@")
  local saved=$FGE__J
  FGE__J='{'
  fge__jstr display "$raw"
  FGE__J+=','
  fge__jstr digest "sha256:$digest"
  FGE__J+=','
  fge__jnum argc "$#"
  FGE__J+=','
  fge__jraw redacted "$redacted"
  FGE__J+='}'
  FGE__CMDJSON=$FGE__J
  FGE__J=$saved
}
FGE__CMDJSON='null'

fge_run() {
  local step=${1-}
  shift || true
  if [ "$#" -eq 0 ]; then
    printf 'fge: fge_run needs a command\n' >&2
    return 2
  fi
  local t0 t1 rc=0
  fge__cmd_json_v "$@"
  local cmdjson=$FGE__CMDJSON
  FGE_LAST_STEP=$step
  t0=$(fge__now_ns)
  "$@" || rc=$?
  t1=$(fge__now_ns)
  FGE_LAST_EXIT=$rc
  FGE_LAST_DURATION_MS=$(((t1 - t0) / 1000000))
  local status=pass
  [ "$rc" -eq 0 ] || status=fail
  fge__emit step "$FGE_PHASE" "$step" "$status" "$rc" "$FGE_LAST_DURATION_MS" '' '' '' "$cmdjson"
  return "$rc"
}

fge_run_ok() {
  local step=${1-} rc=0
  fge_run "$@" || rc=$?
  [ "$rc" -eq 0 ] || fge_die "step '$step' failed with exit $rc"
  return 0
}

fge_capture() {
  local step=${1-}
  shift || true
  if [ "$#" -eq 0 ]; then
    printf 'fge: fge_capture needs a command\n' >&2
    return 2
  fi
  local outf errf t0 t1 rc=0
  outf=$(fge_artifact_path "capture/${step}.stdout")
  errf=$(fge_artifact_path "capture/${step}.stderr")
  fge__cmd_json_v "$@"
  local cmdjson=$FGE__CMDJSON
  FGE_LAST_STEP=$step
  t0=$(fge__now_ns)
  "$@" >"$outf" 2>"$errf" || rc=$?
  t1=$(fge__now_ns)
  FGE_LAST_EXIT=$rc
  FGE_LAST_DURATION_MS=$(((t1 - t0) / 1000000))
  FGE_LAST_STDOUT_FILE=$outf
  FGE_LAST_STDERR_FILE=$errf
  local cap=${FGE_MAX_CAPTURE:-4096}
  FGE_LAST_STDOUT=$(head -c "$cap" <"$outf")
  FGE_LAST_STDERR=$(head -c "$cap" <"$errf")
  fge__redact_v "$FGE_LAST_STDOUT"
  FGE_LAST_STDOUT=$FGE__R
  fge__redact_v "$FGE_LAST_STDERR"
  FGE_LAST_STDERR=$FGE__R
  local od ed ob eb
  od=$(fge_digest_file "$outf")
  ed=$(fge_digest_file "$errf")
  ob=$(wc -c <"$outf")
  ob=${ob// /}
  eb=$(wc -c <"$errf")
  eb=${eb// /}
  FGE_ARTIFACT_DIGESTS["capture/${step}.stdout"]=$od
  FGE_ARTIFACT_DIGESTS["capture/${step}.stderr"]=$ed
  local saved=$FGE__J
  FGE__J='[{'
  fge__jstr name "capture/${step}.stdout"
  FGE__J+=','
  fge__jstr path "$outf"
  FGE__J+=','
  fge__jstr digest "sha256:$od"
  FGE__J+=','
  fge__jnum bytes "$ob"
  FGE__J+='},{'
  fge__jstr name "capture/${step}.stderr"
  FGE__J+=','
  fge__jstr path "$errf"
  FGE__J+=','
  fge__jstr digest "sha256:$ed"
  FGE__J+=','
  fge__jnum bytes "$eb"
  FGE__J+='}]'
  FGE_PENDING_ARTIFACTS=$FGE__J
  FGE__J=$saved
  local status=pass
  [ "$rc" -eq 0 ] || status=fail
  fge__emit step "$FGE_PHASE" "$step" "$status" "$rc" "$FGE_LAST_DURATION_MS" \
    '' '' "$FGE_LAST_STDOUT" "$cmdjson"
  return "$rc"
}

# fge_run_timeout SECS STEP CMD [ARG...]
fge_run_timeout() {
  local secs=${1-} step=${2-}
  shift 2 || true
  if [ "$#" -eq 0 ]; then
    printf 'fge: fge_run_timeout needs a command\n' >&2
    return 2
  fi
  local t0 t1 rc=0 timed_out=false
  fge__cmd_json_v "$@"
  local cmdjson=$FGE__CMDJSON
  FGE_LAST_STEP=$step
  t0=$(fge__now_ns)
  if [ "$FGE_TIMEOUT_IMPL" = coreutils ]; then
    timeout -k 2 "$secs" "$@" || rc=$?
    if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then timed_out=true; fi
  else
    local sentinel child watchdog
    sentinel=$(fge_artifact_path "timeout/${step}.fired")
    rm -f "$sentinel"
    "$@" &
    child=$!
    (
      left=$((secs * 10))
      while [ "$left" -gt 0 ] && kill -0 "$child" 2>/dev/null; do
        read -r -t 0.1 -u 9 _ 2>/dev/null || true
        left=$((left - 1))
      done
      if kill -0 "$child" 2>/dev/null; then
        : >"$sentinel"
        kill -TERM "$child" 2>/dev/null || true
        read -r -t 2 -u 9 _ 2>/dev/null || true
        kill -KILL "$child" 2>/dev/null || true
      fi
    ) &
    watchdog=$!
    wait "$child" || rc=$?
    kill "$watchdog" 2>/dev/null || true
    wait "$watchdog" 2>/dev/null || true
    [ -e "$sentinel" ] && timed_out=true
  fi
  t1=$(fge__now_ns)
  FGE_LAST_EXIT=$rc
  FGE_LAST_DURATION_MS=$(((t1 - t0) / 1000000))
  local status=pass actual=completed
  if [ "$timed_out" = true ]; then
    status=timeout
    actual=timed_out
    FGE_FAILED=1
    : >"$FGE_STATE_DIR/timeout" 2>/dev/null || true
  elif [ "$rc" -ne 0 ]; then
    status=fail
  fi
  fge_field timeout_seconds "$secs"
  fge__emit step "$FGE_PHASE" "$step" "$status" "$rc" "$FGE_LAST_DURATION_MS" \
    "budget ${secs}s" "completed" "$actual" "$cmdjson"
  return "$rc"
}

# fge_retry ATTEMPTS STEP CMD [ARG...]
# Records EVERY attempt. The first attempt's outcome is preserved in the
# terminal record: a retry that succeeds does not erase the fact that the first
# attempt failed.
fge_retry() {
  local attempts=${1-1} step=${2-}
  shift 2 || true
  local i rc=0 first=''
  for ((i = 1; i <= attempts; i++)); do
    rc=0
    fge_field retry_attempt "$i"
    fge_run "${step}#${i}" "$@" || rc=$?
    if [ -z "$first" ]; then
      if [ "$rc" -eq 0 ]; then first=pass; else first=fail; fi
    fi
    [ "$rc" -eq 0 ] && break
  done
  if [ -z "$FGE_FIRST_ATTEMPT_STATUS" ] || [ "$first" = fail ]; then
    FGE_FIRST_ATTEMPT_STATUS=$first
  fi
  FGE_LAST_EXIT=$rc
  return "$rc"
}

fge_spawn() {
  local name=${1-}
  shift || true
  fge__cmd_json_v "$@"
  local cmdjson=$FGE__CMDJSON
  "$@" &
  local pid=$!
  FGE_LAST_PID=$pid
  FGE_SPAWN_NAMES+=("$name")
  FGE_SPAWN_PIDS+=("$pid")
  fge_field child_pid "$pid"
  fge__emit step "$FGE_PHASE" "spawn:$name" info '' '' 'background child started' '' "$pid" "$cmdjson"
  return 0
}

fge_reap() {
  local name=${1-} sig=${2:-TERM} i pid='' idx=-1 rc=0
  for i in "${!FGE_SPAWN_NAMES[@]}"; do
    if [ "${FGE_SPAWN_NAMES[$i]}" = "$name" ]; then
      pid=${FGE_SPAWN_PIDS[$i]}
      idx=$i
      break
    fi
  done
  if [ -z "$pid" ]; then
    FGE_FAILED=1
    fge__emit step "$FGE_PHASE" "reap:$name" error '' '' 'no such spawned child' '' '' null
    return 1
  fi
  if kill -0 "$pid" 2>/dev/null; then
    kill "-$sig" "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || rc=$?
  [ "$idx" -ge 0 ] && unset 'FGE_SPAWN_PIDS[idx]' 'FGE_SPAWN_NAMES[idx]'
  fge__emit step "$FGE_PHASE" "reap:$name" info "$rc" '' "child reaped with SIG$sig" '' "$pid" null
  return 0
}

# =============================================================================
# Assertions
# =============================================================================

# Every assertion funnels through here. Assertions never abort the script: the
# terminal record is the single place a run's verdict is decided, and a
# fail-fast assert would silently shrink the reported denominator.
fge__record_assertion() {
  local id=$1 status=$2 expected=$3 actual=$4 desc=$5
  if [ -z "$id" ]; then
    FGE_FAILED=1
    FGE_LAST_ASSERT_OK=1
    fge__emit assert assert 'assert' error '' '' \
      'assertion emitted without a stable acceptance ID' '' '' null
    return 0
  fi
  printf '%s\t%s\n' "$id" "$status" >>"$FGE_STATE_DIR/assertions.tsv"
  if [ "$status" = pass ]; then
    FGE_LAST_ASSERT_OK=0
  else
    FGE_LAST_ASSERT_OK=1
    FGE_FAILED=1
  fi
  fge__emit assert assert "${desc:-$id}" "$status" '' '' "$desc" "$expected" "$actual" null "$id"
  return 0
}

fge_pass() {
  fge__record_assertion "${1-}" pass '' '' "${2-}"
  return 0
}

fge_fail() {
  fge__record_assertion "${1-}" fail '' '' "${2-}"
  return 0
}

fge_skip() {
  fge__record_assertion "${1-}" skip '' '' "${2-}"
  return 0
}

fge_unsupported() {
  fge__record_assertion "${1-}" unsupported '' '' "${2-}"
  return 0
}

fge_assert_eq() {
  local id=${1-} exp=${2-} act=${3-} desc=${4:-equality}
  if [ "$exp" = "$act" ]; then
    fge__record_assertion "$id" pass "$exp" "$act" "$desc"
  else
    fge__record_assertion "$id" fail "$exp" "$act" "$desc"
  fi
  return 0
}

fge_assert_ne() {
  local id=${1-} nexp=${2-} act=${3-} desc=${4:-inequality}
  if [ "$nexp" != "$act" ]; then
    fge__record_assertion "$id" pass "not $nexp" "$act" "$desc"
  else
    fge__record_assertion "$id" fail "not $nexp" "$act" "$desc"
  fi
  return 0
}

fge_assert_exit() {
  local id=${1-} exp=${2-0} act=${3:-$FGE_LAST_EXIT} desc=${4:-exit code}
  fge_assert_eq "$id" "$exp" "$act" "$desc"
  return 0
}

fge_assert_contains() {
  local id=${1-} hay=${2-} needle=${3-} desc=${4:-substring present}
  if [ -n "$needle" ] && [[ $hay == *"$needle"* ]]; then
    fge__record_assertion "$id" pass "contains: $needle" 'present' "$desc"
  else
    fge__record_assertion "$id" fail "contains: $needle" 'absent' "$desc"
  fi
  return 0
}

fge_assert_not_contains() {
  local id=${1-} hay=${2-} needle=${3-} desc=${4:-substring absent}
  if [ -n "$needle" ] && [[ $hay == *"$needle"* ]]; then
    fge__record_assertion "$id" fail "absent: $needle" 'present' "$desc"
  else
    fge__record_assertion "$id" pass "absent: $needle" 'absent' "$desc"
  fi
  return 0
}

fge_assert_match() {
  local id=${1-} s=${2-} re=${3-} desc=${4:-regex match}
  if [[ $s =~ $re ]]; then
    fge__record_assertion "$id" pass "match: $re" 'matched' "$desc"
  else
    fge__record_assertion "$id" fail "match: $re" "$s" "$desc"
  fi
  return 0
}

fge_assert_file() {
  local id=${1-} p=${2-} desc=${3:-regular file exists}
  if [ -f "$p" ]; then
    fge__record_assertion "$id" pass "file: $p" 'present' "$desc"
  else
    fge__record_assertion "$id" fail "file: $p" 'absent' "$desc"
  fi
  return 0
}

fge_assert_no_file() {
  local id=${1-} p=${2-} desc=${3:-file absent}
  if [ -e "$p" ]; then
    fge__record_assertion "$id" fail "absent: $p" 'present' "$desc"
  else
    fge__record_assertion "$id" pass "absent: $p" 'absent' "$desc"
  fi
  return 0
}

fge_assert_dir() {
  local id=${1-} p=${2-} desc=${3:-directory exists}
  if [ -d "$p" ]; then
    fge__record_assertion "$id" pass "dir: $p" 'present' "$desc"
  else
    fge__record_assertion "$id" fail "dir: $p" 'absent' "$desc"
  fi
  return 0
}

fge_assert_digest() {
  local id=${1-} exp=${2-} p=${3-} desc=${4:-content digest} act
  if [ ! -f "$p" ]; then
    fge__record_assertion "$id" fail "$exp" "missing file $p" "$desc"
    return 0
  fi
  act=$(fge_digest_file "$p")
  fge_assert_eq "$id" "${exp#sha256:}" "$act" "$desc"
  return 0
}

fge_assert_ndjson() {
  local id=${1-} p=${2-} desc=${3:-valid NDJSON} n=0 bad=0 line
  if [ ! -f "$p" ]; then
    fge__record_assertion "$id" fail "ndjson: $p" 'missing' "$desc"
    return 0
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    [ -n "$line" ] || continue
    if ! fge_json_validate_line "$line"; then
      bad=$n
      break
    fi
  done <"$p"
  if [ "$n" -eq 0 ]; then
    fge__record_assertion "$id" fail 'at least one record' 'empty file' "$desc"
  elif [ "$bad" -eq 0 ]; then
    fge__record_assertion "$id" pass "all $n lines valid" "all $n lines valid" "$desc"
  else
    fge__record_assertion "$id" fail 'all lines valid' "line $bad malformed" "$desc"
  fi
  return 0
}

fge_assert_cmd() {
  local id=${1-} desc=${2-predicate} rc=0
  shift 2 || true
  "$@" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    fge__record_assertion "$id" pass 'exit 0' 'exit 0' "$desc"
  else
    fge__record_assertion "$id" fail 'exit 0' "exit $rc" "$desc"
  fi
  return 0
}

# =============================================================================
# Termination
# =============================================================================

fge__signal_number() {
  case ${1-} in
    HUP) printf 1 ;;
    INT) printf 2 ;;
    TERM) printf 15 ;;
    *) printf 0 ;;
  esac
}

fge__on_signal() {
  local sig=$1 n
  FGE_FAILED=1
  fge__emit note "$FGE_PHASE" "signal:$sig" error '' '' "received SIG$sig" '' '' null
  n=$(fge__signal_number "$sig")
  exit $((128 + n))
}

fge__run_cleanups() {
  local i cmd rc
  FGE_CLEANUP_FAILED_LIST=()
  if [ "${#FGE_CLEANUP_CMDS[@]}" -eq 0 ]; then
    FGE_CLEANUP_STATE=skipped
    return 0
  fi
  FGE_CLEANUP_STATE=ok
  for ((i = ${#FGE_CLEANUP_CMDS[@]} - 1; i >= 0; i--)); do
    cmd=${FGE_CLEANUP_CMDS[$i]}
    rc=0
    eval "$cmd" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 0 ]; then
      FGE_CLEANUP_FAILED_LIST+=("$cmd")
      FGE_CLEANUP_STATE=failed
      FGE_FAILED=1
      fge__emit cleanup cleanup "cleanup#$i" fail "$rc" '' 'cleanup action failed' '' "$cmd" null
    else
      fge__emit cleanup cleanup "cleanup#$i" pass "$rc" '' 'cleanup action ok' '' '' null
    fi
  done
  return 0
}

# Returns the number of children that had to be SIGKILLed, i.e. orphans.
fge__contain_children() {
  local i pid orphans=0
  FGE_ORPHANS=()
  for i in "${!FGE_SPAWN_PIDS[@]}"; do
    pid=${FGE_SPAWN_PIDS[$i]}
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      read -r -t 0.2 -u 9 _ 2>/dev/null || true
      if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid" 2>/dev/null || true
        orphans=$((orphans + 1))
        FGE_ORPHANS+=("${FGE_SPAWN_NAMES[$i]:-pid$pid}")
      fi
    fi
    wait "$pid" 2>/dev/null || true
  done
  return "$orphans"
}

fge__on_exit() {
  local incoming=${1:-0}
  [ "$FGE_IN_TERMINAL" -eq 0 ] || return 0
  FGE_IN_TERMINAL=1
  trap - EXIT INT TERM HUP

  if [ "$FGE_INITIALIZED" -ne 1 ]; then exit "$incoming"; fi

  FGE_PHASE=cleanup
  [ "$incoming" -eq 0 ] || FGE_FAILED=1

  fge__run_cleanups

  local orphans=0
  fge__contain_children || orphans=$?

  # Work directories are removed only on a fully clean run. On any failure the
  # entire run directory, including every work dir, survives for triage.
  local d keep=0
  [ "$FGE_FAILED" -ne 0 ] && keep=1
  [ -n "${FGE_KEEP_TEMP:-}" ] && keep=1
  if [ "$keep" -eq 0 ]; then
    for d in "${FGE_TEMPDIRS[@]+"${FGE_TEMPDIRS[@]}"}"; do
      [ -n "$d" ] || continue
      rm -rf "$d" 2>/dev/null || true
    done
  fi

  # Assertion bookkeeping comes from the on-disk ledger, not from shell
  # variables, so assertions emitted inside background subshells are counted.
  local -a ids=() dups=() passed=() failed_a=() skipped=() unsupported=() errored=()
  local -A seen=()
  local id st
  while IFS=$'\t' read -r id st; do
    [ -n "$id" ] || continue
    if [ -n "${seen[$id]+x}" ]; then
      dups+=("$id")
    else
      seen[$id]=1
      ids+=("$id")
    fi
    case $st in
      pass) passed+=("$id") ;;
      fail) failed_a+=("$id") ;;
      skip) skipped+=("$id") ;;
      unsupported) unsupported+=("$id") ;;
      *) errored+=("$id") ;;
    esac
  done <"$FGE_STATE_DIR/assertions.tsv"

  local discovered=${#ids[@]} zero=false
  [ "$discovered" -eq 0 ] && zero=true

  local timeouts=0
  [ -e "$FGE_STATE_DIR/timeout" ] && timeouts=1

  local ob_out=0 k
  for k in "${!FGE_OBLIGATIONS[@]}"; do
    [ "${FGE_OBLIGATIONS[$k]}" = closed ] || ob_out=$((ob_out + 1))
  done

  local status=pass
  [ "$FGE_FAILED" -ne 0 ] && status=fail
  [ "${#failed_a[@]}" -gt 0 ] && status=fail
  [ "${#errored[@]}" -gt 0 ] && status=fail
  [ "${#skipped[@]}" -gt 0 ] && status=fail
  [ "${#unsupported[@]}" -gt 0 ] && status=fail
  [ "${#dups[@]}" -gt 0 ] && status=fail
  [ "$zero" = true ] && status=fail
  [ "$FGE_CLEANUP_STATE" = failed ] && status=fail
  [ "$orphans" -gt 0 ] && status=fail
  [ "$ob_out" -gt 0 ] && status=fail
  [ "$timeouts" -gt 0 ] && status=fail

  local containment=ok
  { [ "$orphans" -gt 0 ] || [ "$ob_out" -gt 0 ]; } && containment=failed

  local first_attempt=$FGE_FIRST_ATTEMPT_STATUS
  [ -n "$first_attempt" ] || first_attempt=$status

  local exit_code=$incoming
  if [ "$status" = fail ] && [ "$exit_code" -eq 0 ]; then exit_code=1; fi
  if [ "$status" = pass ] && [ "$exit_code" -ne 0 ]; then status=fail; fi

  local wall_ns wall_ms
  wall_ns=$(fge__now_ns)
  wall_ms=$(((wall_ns - FGE_START_NS) / 1000000))

  # Counted from the claimed sequence numbers themselves, not from a hint: the
  # terminal record's own number is the highest claim, so the count it declares
  # is exactly what a validator will find in the log if nothing was lost.
  local rec_count=0 _claim
  for _claim in "$FGE_STATE_DIR"/seq.d/*; do
    [ -e "$_claim" ] || continue
    rec_count=$((rec_count + 1))
  done
  rec_count=$((rec_count + 1))

  fge_resource_mark

  local saved i first=1
  FGE__J=''
  FGE__J+='['
  for i in "${!FGE_PRESERVED_PATHS[@]}"; do
    [ "$first" -eq 1 ] || FGE__J+=','
    first=0
    FGE__J+='{'
    fge__jstr path "${FGE_PRESERVED_PATHS[$i]}"
    FGE__J+=','
    fge__jstr reason "${FGE_PRESERVED_REASONS[$i]}"
    FGE__J+='}'
  done
  if [ "$keep" -eq 1 ]; then
    for d in "${FGE_TEMPDIRS[@]+"${FGE_TEMPDIRS[@]}"}"; do
      [ -n "$d" ] || continue
      [ "$first" -eq 1 ] || FGE__J+=','
      first=0
      FGE__J+='{'
      fge__jstr path "$d"
      FGE__J+=','
      fge__jstr reason 'work dir kept for failure triage'
      FGE__J+='}'
    done
  fi
  FGE__J+=']'
  local preserved=$FGE__J

  FGE__J='"terminal":{'
  fge__jstr status "$status"
  FGE__J+=','
  fge__jnum exit_code "$exit_code"
  FGE__J+=','
  fge__jnum wall_ms "$wall_ms"
  FGE__J+=','
  fge__jnum assertions_discovered "$discovered"
  FGE__J+=','
  fge__esc assertion_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${ids[@]+"${ids[@]}"}"
  FGE__J+=','
  fge__jnum passed "${#passed[@]}"
  FGE__J+=','
  fge__jnum failed "${#failed_a[@]}"
  FGE__J+=','
  fge__jnum skipped "${#skipped[@]}"
  FGE__J+=','
  fge__jnum unsupported "${#unsupported[@]}"
  FGE__J+=','
  fge__jnum errors "${#errored[@]}"
  FGE__J+=','
  fge__jnum timeouts "$timeouts"
  FGE__J+=','
  fge__esc passed_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${passed[@]+"${passed[@]}"}"
  FGE__J+=','
  fge__esc failed_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${failed_a[@]+"${failed_a[@]}"}"
  FGE__J+=','
  fge__esc skipped_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${skipped[@]+"${skipped[@]}"}"
  FGE__J+=','
  fge__esc unsupported_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${unsupported[@]+"${unsupported[@]}"}"
  FGE__J+=','
  fge__esc error_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${errored[@]+"${errored[@]}"}"
  FGE__J+=','
  fge__esc duplicate_ids
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${dups[@]+"${dups[@]}"}"
  FGE__J+=','
  fge__jstr first_attempt_status "$first_attempt"
  FGE__J+=','
  fge__jstr cleanup_state "$FGE_CLEANUP_STATE"
  FGE__J+=','
  fge__esc cleanup_failures
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${FGE_CLEANUP_FAILED_LIST[@]+"${FGE_CLEANUP_FAILED_LIST[@]}"}"
  FGE__J+=','
  fge__jstr containment "$containment"
  FGE__J+=','
  fge__esc orphans
  FGE__J+="\"$FGE__E\":"
  fge__jarr_str_into "${FGE_ORPHANS[@]+"${FGE_ORPHANS[@]}"}"
  FGE__J+=','
  fge__jnum obligations_outstanding "$ob_out"
  FGE__J+=','
  fge__jraw preserved "$preserved"
  FGE__J+=','
  fge__jstr artifact_dir "$FGE_ARTIFACT_DIR"
  FGE__J+=','
  fge__jstr log_path "$FGE_LOG"
  FGE__J+=','
  fge__jraw zero_assertions "$zero"
  FGE__J+=','
  fge__jnum record_count "$rec_count"
  FGE__J+='}'
  saved=$FGE__J

  fge__emit terminal teardown terminal "$status" "$exit_code" "$wall_ms" \
    'terminal summary' '' '' null '' "$saved"

  printf 'fge: run %s status=%s assertions=%d passed=%d failed=%d skipped=%d unsupported=%d\n' \
    "$FGE_RUN_ID" "$status" "$discovered" "${#passed[@]}" "${#failed_a[@]}" \
    "${#skipped[@]}" "${#unsupported[@]}" >&2
  printf 'fge: artifacts: %s\n' "$FGE_ARTIFACT_DIR" >&2
  printf 'fge: replay: %s\n' "$FGE_REPLAY_CMD" >&2

  exit "$exit_code"
}
