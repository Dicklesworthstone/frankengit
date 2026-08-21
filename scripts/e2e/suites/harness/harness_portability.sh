#!/usr/bin/env bash
# e2e: portability and robustness of the shared harness library -- concurrent
# log writers, signal handling, the pure-bash timeout fallback, deterministic
# aggregation ordering, and the static/tooling constraints the harness claims
# for itself (bead frankengit-fg000a-e2e-harness-4ci).
#
# Scope claim: harness mechanics only. Proves nothing about any FrankenGit
# capability.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init

fge_phase setup
work=$(fge_tempdir portability)

# ---------------------------------------------------------------------------
# concurrent log writers
#
# Sequence numbers are allocated under a lock but records are appended outside
# it, so records may land out of order. What must hold is that the seq values
# form exactly {1..N}: that is the property the validator relies on to tell a
# lost record from a merely reordered one.
# ---------------------------------------------------------------------------
fge_phase action
concurrent_writers=12
for i in $(seq 1 "$concurrent_writers"); do
  (fge_note "concurrent-$i" "background writer $i") &
done
wait || true

snapshot="$work/log-snapshot.ndjson"
cp "$FGE_LOG" "$snapshot"

seq_max=0
seq_count=0
seq_dupes=0
declare -A seen_seq=()
bad_lines=0
while IFS= read -r line; do
  if ! fge_json_top "$line"; then
    bad_lines=$((bad_lines + 1))
    continue
  fi
  s=${FGE_JSON[seq]}
  seq_count=$((seq_count + 1))
  if [ -n "${seen_seq[$s]+x}" ]; then
    seq_dupes=$((seq_dupes + 1))
  fi
  seen_seq[$s]=1
  [ "$s" -gt "$seq_max" ] && seq_max=$s
done <"$snapshot"

# ---------------------------------------------------------------------------
# signal handling: SIGTERM must still produce a terminal record
# ---------------------------------------------------------------------------
sig_dir="$work/signal-run"
mkdir -p "$sig_dir"
sig_script="$work/signal_target.sh"
cat >"$sig_script" <<SIGEOF
#!/usr/bin/env bash
set -euo pipefail
. "$E2E_ROOT/lib.sh"
fge_init signal-target
fge_phase assert
fge_assert_eq SIGNAL-TARGET-001 ok ok 'an assertion lands before the signal'
fge_phase action
touch "$sig_dir/ready"
sleep 60
SIGEOF
chmod +x "$sig_script"

FGE_RUN_DIR="$sig_dir" "$sig_script" >"$work/signal.stdout" 2>"$work/signal.stderr" &
sig_pid=$!
waited=0
while [ ! -e "$sig_dir/ready" ] && [ "$waited" -lt 200 ]; do
  sleep 0.05
  waited=$((waited + 1))
done
kill -TERM "$sig_pid" 2>/dev/null || true
sig_exit=0
wait "$sig_pid" || sig_exit=$?

sig_log="$sig_dir/e2e.ndjson"
sig_terminal_lines=0
sig_signal_notes=0
sig_status=''
if [ -f "$sig_log" ]; then
  while IFS= read -r line; do
    case $line in
      *'"kind":"terminal"'*)
        sig_terminal_lines=$((sig_terminal_lines + 1))
        if fge_json_top "$line" && fge_json_top "${FGE_JSON[terminal]}"; then
          sig_status=$(fge_json_unquote "${FGE_JSON[status]}")
        fi
        ;;
    esac
    case $line in
      *'"step":"signal:TERM"'*) sig_signal_notes=$((sig_signal_notes + 1)) ;;
    esac
  done <"$sig_log"
fi
sig_last_kind=''
if [ -s "$sig_log" ]; then
  last=$(tail -n 1 "$sig_log")
  fge_json_top "$last" && sig_last_kind=$(fge_json_unquote "${FGE_JSON[kind]}")
fi

# ---------------------------------------------------------------------------
# the pure-bash timeout fallback, on the path where it does NOT fire
#
# The firing path is a planted negative (selftests/fixtures/neg_timeout.sh and
# its bash-watchdog sibling), because a fired timeout fails its own run by
# design and cannot live in a passing suite.
# ---------------------------------------------------------------------------
saved_impl=$FGE_TIMEOUT_IMPL
FGE_TIMEOUT_IMPL=bash
fge_run_timeout 30 watchdog-within-budget true
watchdog_exit=$FGE_LAST_EXIT
FGE_TIMEOUT_IMPL=$saved_impl

fge_run_timeout 30 coreutils-within-budget true
coreutils_exit=$FGE_LAST_EXIT

# ---------------------------------------------------------------------------
# deterministic aggregation ordering
#
# Names chosen so a C-locale sort and a natural-language sort disagree: under
# LC_ALL=C uppercase sorts before lowercase, so the expected order is B, C, a.
# ---------------------------------------------------------------------------
order_dir="$work/order-suite"
mkdir -p "$order_dir"
for n in a B C; do
  cp "$E2E_ROOT/selftests/fixtures/pos_control.sh" "$order_dir/$n.sh"
  chmod +x "$order_dir/$n.sh"
done
list_one=$("$E2E_ROOT/run_all.sh" --dir "$order_dir" --list | cut -f1 | tr '\n' ' ')
list_two=$("$E2E_ROOT/run_all.sh" --dir "$order_dir" --list | cut -f1 | tr '\n' ' ')

# The regression guard for the reopen incident on this bead: discovery order
# must not follow the ambient locale. A host whose collation folds case sorts
# `a` before `B`, which silently reorders aggregation for reasons unrelated to
# the suite. Run the same discovery under a case-folding locale, if the host has
# one, and require the identical C-order answer.
locale_probe=skipped
for candidate in en_US.utf8 en_US.UTF-8 C.utf8; do
  if locale -a 2>/dev/null | grep -qxF "$candidate"; then
    locale_probe=$(LC_ALL="$candidate" LANG="$candidate" \
      "$E2E_ROOT/run_all.sh" --dir "$order_dir" --list | cut -f1 | tr '\n' ' ')
    break
  fi
done

# ---------------------------------------------------------------------------
# static and tooling constraints the harness claims for itself
# ---------------------------------------------------------------------------
declare -a harness_scripts=()
while IFS= read -r -d '' p; do harness_scripts+=("$p"); done < <(
  find "$E2E_ROOT" -type f -name '*.sh' -not -path '*/oracle/*' -print0 | LC_ALL=C sort -z
)

syntax_failures=''
shebang_failures=''
strict_failures=''
for p in "${harness_scripts[@]}"; do
  bash -n "$p" 2>/dev/null || syntax_failures+="$(basename "$p") "
  # lib.sh is sourced, never executed, so it carries a shellcheck shell
  # directive instead of a shebang. Every other script must be runnable.
  if [ "$(basename "$p")" = lib.sh ]; then
    head -n 1 "$p" | grep -q '^# shellcheck shell=bash$' || shebang_failures+="lib.sh "
  else
    head -n 1 "$p" | grep -q '^#!/usr/bin/env bash$' || shebang_failures+="$(basename "$p") "
  fi
  grep -q '^set -euo pipefail$\|^set -uo pipefail$' "$p" ||
    strict_failures+="$(basename "$p") "
done

# Every script under suites/ must use the full strict mode. The corrupting
# fixtures under selftests/ deliberately omit -e so they can observe a failing
# child, which is why this check is scoped to suites/.
suite_strict_failures=''
while IFS= read -r -d '' p; do
  grep -q '^set -euo pipefail$' "$p" || suite_strict_failures+="$(basename "$p") "
done < <(find "$E2E_ROOT/suites" -type f -name '*.sh' -print0 | LC_ALL=C sort -z)

# Tooling constraints, detected in COMMAND POSITION only.
#
# A bare word-boundary match is not good enough and the first version of this
# check proved it: it flagged `fge_cmd_digest git status --short`, which only
# hashes an argv and never runs anything, and it flagged this file for quoting
# the tool names inside its own pattern. A name mentioned in prose, quoted in a
# string, or passed as data is not an invocation. So the detectors below anchor
# on positions where a command can actually start -- line start, `;`, `&`, `|`,
# `(`, `$(` -- and comment lines are stripped first.
#
# Both detectors are then run against a planted violation and a near-identical
# permitted file, so the narrowing above cannot quietly become a loophole.
CMD_START='(^|[;&|(])[[:space:]]*'

# Comment lines are dropped, then quoted spans are removed so a tool NAME
# appearing inside a string is not mistaken for an invocation. That distinction
# is not cosmetic: a peer suite printing a JSON receipt whose prose read
# "...fgit arm is in-process; git arm is a sandboxed process spawn" was reported
# as shelling out to git, because the `; git ` inside its printf format matched
# CMD_START. That file invokes nothing.
#
# Ignoring string CONTENTS makes the detector more accurate, not weaker: text in
# a literal cannot execute. The single exception is `eval`, which executes its
# string argument, so any line mentioning `eval` is left intact and searched in
# full. FG-000A-PORT-032/033/034 pin both halves through these very functions.
detect__strip() {
  grep -v '^[[:space:]]*#' "$1" |
    sed -E "/eval/! { s/'[^']*'//g; s/\"[^\"]*\"//g; }"
}

# `eval` lines are matched PERMISSIVELY -- any occurrence of the tool name, not
# just one at a command start. `eval "git rev-parse HEAD"` invokes git, but the
# character before `git` is a quote, so CMD_START never matched it. That hole
# predates the string-stripping above; it was verified against the previous
# detector before this was written, so it is a hole being closed, not one being
# introduced. Over-eagerness on `eval` lines is the right trade: `eval` is rare
# in a harness and suspicious when present, so a false positive there costs one
# justification and a miss costs the whole gate.
detect__eval_lines() {
  grep -v '^[[:space:]]*#' "$1" | grep 'eval'
}

detect_forbidden_tool() {
  detect__strip "$1" |
    grep -qE "${CMD_START}(jq|python3?|perl|g?awk|mawk)([[:space:]]|\$)" && return 0
  detect__eval_lines "$1" |
    grep -qE "(jq|python3?|perl|g?awk|mawk)([[:space:]]|\$)"
}

detect_git_subprocess() {
  detect__strip "$1" |
    grep -qE "${CMD_START}git([[:space:]]|\$)" && return 0
  detect__eval_lines "$1" | grep -qE "git([[:space:]]|\$)"
}

# This file is excluded from its own sweep because the planted-violation
# heredocs below contain, by construction, exactly the invocations the
# detectors look for. The exclusion is not a loophole: the same two detectors
# are exercised against a planted violation and a permitted near-twin
# immediately afterwards, so a detector that stopped working would fail here
# rather than pass quietly.
self_basename=$(basename "${BASH_SOURCE[0]}")
forbidden_tools=''
git_subprocess=''
swept=0
for p in "${harness_scripts[@]}"; do
  [ "$(basename "$p")" = "$self_basename" ] && continue
  swept=$((swept + 1))
  detect_forbidden_tool "$p" && forbidden_tools+="$(basename "$p") "
  detect_git_subprocess "$p" && git_subprocess+="$(basename "$p") "
done

# Planted controls for the two detectors.
planted_tool="$work/planted_tool.sh"
cat >"$planted_tool" <<'PLANTEDEOF'
#!/usr/bin/env bash
jq '.a' input.json
PLANTEDEOF
permitted_tool="$work/permitted_tool.sh"
cat >"$permitted_tool" <<'PLANTEDEOF'
#!/usr/bin/env bash
# we deliberately avoid jq, python and awk here
printf '%s\n' 'jq is named in this string but never invoked'
PLANTEDEOF
planted_git="$work/planted_git.sh"
cat >"$planted_git" <<'PLANTEDEOF'
#!/usr/bin/env bash
rev=$(git rev-parse HEAD)
PLANTEDEOF
permitted_git="$work/permitted_git.sh"
cat >"$permitted_git" <<'PLANTEDEOF'
#!/usr/bin/env bash
fge_cmd_digest git status --short
PLANTEDEOF

# The exact shape that produced a false positive against a peer's committed
# suite: a command separator followed by a tool name, both inside a string.
prose_tools="$work/prose_tools.sh"
cat >"$prose_tools" <<'PLANTEDEOF'
#!/usr/bin/env bash
printf '%s\n' 'fgit arm is in-process; git arm is a sandboxed process spawn'
printf '%s\n' "measured without jq; awk was not used either"
PLANTEDEOF

# ...and the hole that stripping strings would otherwise open. `eval` executes
# its argument, so a quoted invocation there is a real one and must still fire.
eval_git="$work/eval_git.sh"
cat >"$eval_git" <<'PLANTEDEOF'
#!/usr/bin/env bash
eval "git rev-parse HEAD"
PLANTEDEOF

# Exercised through the REAL detector functions, not a reimplementation of them:
# a copy could drift from the thing actually gating the swarm.
prose_git_fired=no
detect_git_subprocess "$prose_tools" && prose_git_fired=yes
prose_tool_fired=no
detect_forbidden_tool "$prose_tools" && prose_tool_fired=yes
eval_git_fired=no
detect_git_subprocess "$eval_git" && eval_git_fired=yes

tool_detector_fires=no
detect_forbidden_tool "$planted_tool" && tool_detector_fires=yes
tool_detector_quiet=yes
detect_forbidden_tool "$permitted_tool" && tool_detector_quiet=no
git_detector_fires=no
detect_git_subprocess "$planted_git" && git_detector_fires=yes
git_detector_quiet=yes
detect_git_subprocess "$permitted_git" && git_detector_quiet=no

harness_script_count=${#harness_scripts[@]}

# ---------------------------------------------------------------------------
# set -u initialisation guard for run_all.sh's validator state
#
# A real defect motivated this: a `RA_V_TIMEOUTS` read was added without an
# initializer, and under `set -u` that aborted run_all on EVERY script --
# including the passing controls -- so the whole suite reported failures that
# had nothing to do with the scripts under test. The failure mode is nasty
# because it looks like twenty unrelated bugs instead of one missing line.
#
# Every RA_V_* must therefore be either a top-level scalar assignment or a
# `declare -a` array. The detector is exercised against a planted copy with an
# initializer removed, so it cannot rot into a no-op.
# ---------------------------------------------------------------------------
detect_uninitialised_state() {
  local file=$1 n out=''
  for n in $(grep -oE 'RA_V_[A-Z_]+' "$file" | sort -u); do
    grep -qE "^${n}=" "$file" && continue
    grep -qE "^declare -a .*\b${n}=\(\)" "$file" && continue
    out+="$n "
  done
  printf '%s' "$out"
}

uninitialised_state=$(detect_uninitialised_state "$E2E_ROOT/run_all.sh")

planted_uninit="$work/planted_uninit.sh"
sed 's/^RA_V_TIMEOUTS=0$//' "$E2E_ROOT/run_all.sh" >"$planted_uninit"
planted_uninit_found=$(detect_uninitialised_state "$planted_uninit")

fge_phase assert

# concurrency
fge_assert_eq FG-000A-PORT-001 0 "$bad_lines" \
  'every record survives concurrent writers as valid JSON'
fge_assert_eq FG-000A-PORT-002 0 "$seq_dupes" \
  'concurrent writers never share a sequence number'
fge_assert_eq FG-000A-PORT-003 "$seq_count" "$seq_max" \
  'sequence numbers form exactly {1..N} after concurrent writes'
fge_assert_cmd FG-000A-PORT-004 'all background writers were recorded' \
  test "$seq_count" -ge "$concurrent_writers"

# signals
fge_assert_eq FG-000A-PORT-005 1 "$sig_terminal_lines" \
  'a SIGTERMed run still emits exactly one terminal record'
fge_assert_eq FG-000A-PORT-006 terminal "$sig_last_kind" \
  'the terminal record is still the last line after a signal'
fge_assert_eq FG-000A-PORT-007 1 "$sig_signal_notes" \
  'the received signal is recorded as its own step'
fge_assert_eq FG-000A-PORT-008 fail "$sig_status" \
  'a signalled run is a failure, never a quiet success'
fge_assert_eq FG-000A-PORT-009 143 "$sig_exit" \
  'a SIGTERMed run exits 128+15'

# timeout implementations
fge_assert_eq FG-000A-PORT-010 0 "$watchdog_exit" \
  'the pure-bash watchdog lets a command inside its budget finish'
fge_assert_eq FG-000A-PORT-011 0 "$coreutils_exit" \
  'the coreutils timeout lets a command inside its budget finish'
fge_assert_match FG-000A-PORT-012 "$FGE_TIMEOUT_IMPL" '^(coreutils|bash)$' \
  'the timeout implementation in use is named in the record'

# ordering
fge_assert_eq FG-000A-PORT-013 'B C a ' "$list_one" \
  'discovery order is a C-locale sort, not a locale-dependent one'
fge_assert_eq FG-000A-PORT-014 "$list_one" "$list_two" \
  'discovery order is stable across runs'
if [ "$locale_probe" = skipped ]; then
  # No case-folding locale on this host, so the property cannot be observed
  # here. Recorded as an explicit unsupported result rather than a silent pass:
  # a guard that quietly does nothing is worse than a missing one.
  fge_unsupported FG-000A-PORT-031 \
    'no case-folding locale is installed, so locale-independence cannot be observed on this host'
else
  fge_assert_eq FG-000A-PORT-031 "$list_one" "$locale_probe" \
    'discovery order is identical under a case-folding locale'
fi

# static and tooling
fge_assert_eq FG-000A-PORT-015 '' "$syntax_failures" \
  'every harness script parses under bash -n'
fge_assert_eq FG-000A-PORT-016 '' "$shebang_failures" \
  'every harness script declares #!/usr/bin/env bash'
fge_assert_eq FG-000A-PORT-017 '' "$strict_failures" \
  'every harness script enables strict shell mode'
fge_assert_eq FG-000A-PORT-018 '' "$suite_strict_failures" \
  'every suite script uses the full set -euo pipefail'
fge_assert_eq FG-000A-PORT-032 no "$prose_git_fired" \
  'a git name inside a string literal is prose, not an invocation'

fge_assert_eq FG-000A-PORT-033 no "$prose_tool_fired" \
  'a jq or awk name inside a string literal is prose, not an invocation'

fge_assert_eq FG-000A-PORT-034 yes "$eval_git_fired" \
  'eval of a quoted git command is still an invocation and still fires'

fge_assert_eq FG-000A-PORT-019 '' "$forbidden_tools" \
  'no harness script invokes jq, python, perl or awk'
fge_assert_eq FG-000A-PORT-020 '' "$git_subprocess" \
  'no harness script shells out to git'
fge_assert_eq FG-000A-PORT-024 yes "$tool_detector_fires" \
  'the forbidden-tool detector fires on a planted jq invocation'
fge_assert_eq FG-000A-PORT-025 yes "$tool_detector_quiet" \
  'the forbidden-tool detector ignores a tool name that is only mentioned'
fge_assert_eq FG-000A-PORT-026 yes "$git_detector_fires" \
  'the git detector fires on a planted git subprocess'
fge_assert_eq FG-000A-PORT-027 yes "$git_detector_quiet" \
  'the git detector ignores a git argv that is only digested, never run'
fge_assert_cmd FG-000A-PORT-021 'the static checks covered a real file set' \
  test "$harness_script_count" -ge 10
fge_assert_cmd FG-000A-PORT-028 'the tooling sweep covered every harness script but this one' \
  test "$swept" -eq "$((harness_script_count - 1))"
fge_assert_eq FG-000A-PORT-029 '' "$uninitialised_state" \
  'every RA_V_* in run_all.sh has an initializer, so set -u cannot abort the runner'
fge_assert_eq FG-000A-PORT-030 'RA_V_TIMEOUTS ' "$planted_uninit_found" \
  'the initialisation guard detects a removed initializer rather than passing vacuously'

# environment identity is recorded rather than assumed
fge_assert_match FG-000A-PORT-022 "$FGE_DIGEST_TOOL" '^(sha256sum|shasum|openssl)$' \
  'the sha-256 helper actually in use is named in the record'
fge_assert_match FG-000A-PORT-023 "$FGE_TIME_RES" '^(us|ns|s)$' \
  'the clock resolution actually in use is named in the record'
