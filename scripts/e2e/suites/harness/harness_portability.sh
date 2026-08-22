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
# The pinned-oracle DRIVERS are exempt: they exist to launch upstream Git inside
# Bubblewrap, so the git and forbidden-tool detectors would fire on them by
# design. The exemption is scoped to that one directory by absolute path rather
# than to the glob `*/oracle/*`, which was the original form and had quietly
# widened: when FG-000B relocated its selftest to suites/oracle/, that glob
# exempted a DISCOVERED SUITE from the syntax, shebang, strict-mode and tooling
# checks every other suite is held to -- silently, because nothing states the
# exemption exists. It hid nothing (that suite invokes neither git nor a
# forbidden tool, and carries both a shebang and strict mode), but a gate whose
# scope drifts with a peer's directory naming is a gate that cannot be relied on.
# Anything under suites/ is now always swept.
declare -a harness_scripts=()
while IFS= read -r -d '' p; do harness_scripts+=("$p"); done < <(
  find "$E2E_ROOT" -type f -name '*.sh' -not -path "$E2E_ROOT/oracle/*" -print0 |
    LC_ALL=C sort -z
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

# ---------------------------------------------------------------------------
# root-level orphan detection
#
# run_all discovers `suites/**` and nothing else, and says so in its own header.
# A suite that lands anywhere else is not refused -- it simply never runs, and
# its acceptance ids go on reading as coverage for whatever bead cited them.
# The silence is the defect. Two real instances:
#   * scripts/e2e/verify_artifact_probe.sh carried 28 FG-001-PROBE-* ids through
#     the CLOSURE of FG-001 without ever executing (bead frankengit-osqi);
#   * scripts/e2e/oracle/selftest.sh held the pinned-Git sandbox's fail-closed
#     evidence -- relied on by five discovered suites -- until FG-000B moved it.
#
# Two escapes are legitimate and must not fire:
#   * a script another file DRIVES by name. The 20 selftests/fixtures live this
#     way, and self_test.sh names them by RUN ID (`selftests-fixtures-<stem>`)
#     rather than by filename, which is why the stem is the token searched for
#     and not the basename with its extension.
#   * a script whose own header says why it sits outside suites/. self_test.sh
#     does, because it drives this runner and would otherwise recurse into
#     itself. verify_artifact_probe.sh gives no such reason.
#
# The candidate list is built here rather than reusing `harness_scripts`,
# which excludes `*/oracle/*`. That exclusion is right for the tooling sweep --
# the oracle legitimately spawns git -- but reusing it here would make this gate
# blind to an orphan under an oracle/ directory, which is precisely where one of
# the two real instances lived.
# ---------------------------------------------------------------------------
# This suite is excluded from the invoker search for the same reason it is
# excluded from its own tooling sweep: it necessarily NAMES the orphan it gates
# on, and the search reads file contents. Without the exclusion the gate becomes
# its own alibi -- verify_artifact_probe.sh never names itself, so the only hit
# was the comment in this file, and the detector spared the very file it exists
# to catch.
orphan_self_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

is_orphan_candidate() {
  # A suite SOURCES the library and CALLS fge_init. lib.sh defines fge_init
  # without sourcing itself; run_all.sh sources the library without calling it.
  # Neither is a suite, so neither can be orphaned.
  grep -qE '^[[:space:]]*(\.|source)[[:space:]].*lib\.sh' "$1" || return 1
  grep -qE '^[[:space:]]*fge_init\b' "$1" || return 1
  return 0
}

detect_root_orphan() {
  # $1 = candidate script, $2 = tree to search for an invoker (default E2E_ROOT).
  # Returns 0 when the candidate is an orphan.
  local p=$1 root=${2:-$E2E_ROOT} stem hits h
  case $p in
    */suites/*) return 1 ;;
  esac
  is_orphan_candidate "$p" || return 1
  head -n 20 "$p" |
    grep -qiE 'deliberately (lives )?outside|would recurse|drives this runner' &&
    return 1
  stem=$(basename "$p" .sh)
  # Deliberately NOT `grep -rl ... | grep -q ...`. `grep -q` exits on its first
  # match and closes the pipe, the producer dies of SIGPIPE, and `set -o
  # pipefail` turns that into 141. A stem with MANY references then looks
  # identical to a stem with none, while a stem with exactly one reference
  # passes -- an inversion that reported lib.sh as an orphan and spared the real
  # one on this gate's first run. The list is captured, then walked.
  hits=$(grep -rl -- "$stem" "$root" || true)
  while IFS= read -r h; do
    [ -z "$h" ] && continue
    [ "$h" = "$p" ] && continue
    [ "$h" = "$orphan_self_path" ] && continue
    return 1
  done <<<"$hits"
  return 0
}

root_orphans=''
orphan_candidates=0
while IFS= read -r -d '' p; do
  case $p in
    */suites/*) continue ;;
  esac
  is_orphan_candidate "$p" || continue
  orphan_candidates=$((orphan_candidates + 1))
  detect_root_orphan "$p" && root_orphans+="$(basename "$p" .sh) "
done < <(find "$E2E_ROOT" -type f -name '*.sh' -print0 | LC_ALL=C sort -z)

# Planted controls, exercised through the REAL detector rather than a copy of
# it: a reimplementation could drift from the thing actually gating the swarm.
orphan_probe="$work/orphan-probe"
mkdir -p "$orphan_probe"

planted_orphan="$orphan_probe/planted_orphan.sh"
cat >"$planted_orphan" <<'PLANTEDEOF'
#!/usr/bin/env bash
. "$SCRIPT_DIR/lib.sh"
fge_init planted-orphan
PLANTEDEOF

# Permitted twin 1: identical, except a driver names it.
driven_twin="$orphan_probe/driven_twin.sh"
cat >"$driven_twin" <<'PLANTEDEOF'
#!/usr/bin/env bash
. "$SCRIPT_DIR/lib.sh"
fge_init driven-twin
PLANTEDEOF
cat >"$orphan_probe/driver.sh" <<'PLANTEDEOF'
#!/usr/bin/env bash
# names the stem the way self_test.sh names a fixture: by run id, not filename
run_case selftests-fixtures-driven_twin
PLANTEDEOF

# Permitted twin 2: identical, except its header declares the exception.
declared_twin="$orphan_probe/declared_twin.sh"
cat >"$declared_twin" <<'PLANTEDEOF'
#!/usr/bin/env bash
# This deliberately lives outside suites/ because it drives this runner and
# would recurse into itself if discovered.
. "$SCRIPT_DIR/lib.sh"
fge_init declared-twin
PLANTEDEOF

orphan_detector_fires=no
detect_root_orphan "$planted_orphan" "$orphan_probe" && orphan_detector_fires=yes
orphan_detector_spares_driven=yes
detect_root_orphan "$driven_twin" "$orphan_probe" && orphan_detector_spares_driven=no
orphan_detector_spares_declared=yes
detect_root_orphan "$declared_twin" "$orphan_probe" && orphan_detector_spares_declared=no

fge_field root_orphan_candidates "$orphan_candidates"

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

# ---------------------------------------------------------------------------
# MEASURED, NOT GATED: suites whose failing step would lose its own attribution
#
# fge_run and fge_capture return the command's exit status, so under
# `set -euo pipefail` a bare call that fails kills the script before
# FGE_LAST_EXIT is read and before the assertion meant to report it can run. The
# run is still caught -- it is not a false green -- but it reports
# `status=fail failed=0` with the remaining assertions never executed, so the
# operator learns the suite died rather than which check broke.
#
# Emitted as a field rather than an assertion, on purpose. Asserting today would
# red this gate for every affected suite at once and block the sweep, which is
# not a call I get to make for ten other agents' files. Documented the trap in
# lib.sh's header instead (8bee060); this measures whether that worked.
#
# §16.3 justification for carrying a process artifact at all:
#   consumer          GoldLotus, for dispatch -- who still has the pattern.
#   gate it feeds     FG-000A-PORT-035, once the count is zero.
#   defect class      a failing step deleting itself from the evidence record.
#   deletion condition when bare_exit_reads reaches 0, convert to that assertion
#                     and remove this block. If the count is still climbing a day
#                     from now, documentation was the wrong instrument and the
#                     gate should land with a grace period instead.
bare_exit_reads=0
for p in "${harness_scripts[@]}"; do
  [ "$(basename "$p")" = "$self_basename" ] && continue
  # A statement is suspect when it is an unguarded fge_run/fge_capture whose
  # next few lines read FGE_LAST_EXIT: that combination says "I intend to report
  # this failure" while guaranteeing it cannot.
  while IFS= read -r hit; do
    bare_exit_reads=$((bare_exit_reads + 1))
  done < <(
    grep -nE "^[[:space:]]*fge_(run|capture)[[:space:]]" "$p" |
      cut -d: -f1 |
      while IFS= read -r ln; do
        stmt=$(sed -n "${ln},$((ln + 4))p" "$p" | tr '\n' ' ')
        case $stmt in
          *"||"* | *"&&"*) continue ;;
        esac
        case $stmt in
          *FGE_LAST_EXIT*) printf '%s\n' "$ln" ;;
        esac
      done
  )
done
fge_field bare_exit_reads "$bare_exit_reads"
fge_note bare-exit-read-debt \
  "$bare_exit_reads unguarded fge_run/fge_capture call sites read FGE_LAST_EXIT; each would lose its failing assertion under set -e. Measured, not gated -- see FG-000A-PORT-035 deletion condition."

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

# discovery integrity: nothing outside suites/ may assert in silence
#
# Pinned to the ONE orphan already filed as a bead rather than to the empty
# string, because verify_artifact_probe.sh has never executed and moving it into
# suites/ could turn the lane red for all sixteen panes on the next run -- that
# sequencing is the orchestrator's to make, not this suite's to spring. The
# expectation is still a real gate: a SECOND orphan changes this string and
# fails here immediately.
#
# DELETION CONDITION: when frankengit-osqi dispositions verify_artifact_probe.sh
# -- relocated under suites/, or retired -- the expected value below becomes the
# empty string. It is written as an exact match precisely so that resolving the
# bead cannot leave a stale allowance behind: the assertion fails until it is
# updated.
fge_assert_eq FG-000A-PORT-036 'verify_artifact_probe ' "$root_orphans" \
  'the only unrun root-level suite is the one frankengit-osqi tracks'
fge_assert_eq FG-000A-PORT-037 yes "$orphan_detector_fires" \
  'the orphan detector fires on a planted root-level suite with no invoker'
fge_assert_eq FG-000A-PORT-038 yes "$orphan_detector_spares_driven" \
  'the orphan detector spares a root-level suite a driver names by stem'
fge_assert_eq FG-000A-PORT-039 yes "$orphan_detector_spares_declared" \
  'the orphan detector spares a root-level suite that declares why in its header'
fge_assert_cmd FG-000A-PORT-040 'the orphan scan covered a real candidate set' \
  test "$orphan_candidates" -ge 15

# ---------------------------------------------------------------------------
# FG-091 profile gate: the manifest refusals must be able to FIRE
#
# The gate refuses four manifest defects. Each was verified by hand when
# written, and a hand verification preserves nothing -- the next person to touch
# the loader cannot tell which branches were ever exercised. These plant each
# defect into a TEMPORARY PROFILE beside the real manifests and require the
# specific refusal.
#
# WHY A TEMPORARY PROFILE RATHER THAN A COPIED TREE. The first version of this
# probe copied run_all.sh and suites/harness into a scratch directory. Every
# refusal passed and the CONTROL failed: script ids are derived repo-relative,
# so a copied tree produces ids that match no manifest entry, and the good
# manifest reported all three required suites as simultaneously missing and
# unregistered. Four refusals passing in an environment where everything is
# refused is exactly the vacuity the control exists to catch, and it caught it.
#
# `--list` throughout, so the nested runner stops after discovery and set
# checking. This suite already runs under run_all; a nested full run would
# execute the corpus inside the corpus.
#
# DELETION CONDITION: these go when the profile gate does. Not a process
# artifact -- each fails the run if its refusal stops working, which is the
# §16.3 boundary test for product.
# ---------------------------------------------------------------------------
fge_phase action
probe_profile="zz-gate-probe-$$"
probe_manifest_path="$E2E_ROOT/manifests/$probe_profile.tsv"
# Registered before the file exists: a probe that dies mid-way must not leave a
# stale manifest behind for the next run to trip over.
fge_cleanup_register rm -f -- "$probe_manifest_path"
good_manifest=$(cat "$E2E_ROOT/manifests/harness.tsv")

probe_manifest() {
  local body=$1 status=0
  printf '%s\n' "$body" | cat >"$probe_manifest_path"
  "$E2E_ROOT/run_all.sh" --profile "$probe_profile" --list >/dev/null 2>&1 || status=$?
  printf '%s' "$status"
}

first_required=$(printf '%s\n' "$good_manifest" | grep '^suites-harness-harness_json' | head -1)

probe_control=$(probe_manifest "$good_manifest")
probe_duplicate=$(probe_manifest "$good_manifest
$first_required")
probe_classification=$(probe_manifest "$(printf '%s\n' "$good_manifest" |
  sed 's/	required	mechanism/	mandatory	mechanism/')")
probe_incomplete=$(probe_manifest "$good_manifest
suites-harness-truncated	bead	g0")
# A CONSISTENT manifest naming a suite that is not on disk. Both columns are
# renamed together, so the row is internally coherent and the failure is
# genuinely about the release surface rather than about a malformed row -- which
# is what PORT-046 covers separately. Renaming only the id column, as this probe
# first did, is caught earlier by the path/id agreement check and would have
# made this assertion silently test that instead.
probe_rename=$(probe_manifest "$(printf '%s\n' "$good_manifest" |
  sed 's/^suites-harness-harness_json	/suites-harness-harness_json_v2	/' |
  sed 's|/harness/harness_json.sh|/harness/harness_json_v2.sh|')")
# A row whose path column points at a different suite than its id column. Both
# describe the same thing, so they can drift apart -- and after a rename it is
# normal for one to be updated and the other missed.
# An OPTIONAL row must be accepted, not refused -- and must not be selected.
# Without this the optional branch is unexercised: the loader would reject every
# optional entry, or silently drop it, and nothing here would notice.
probe_optional=$(probe_manifest "$good_manifest
suites-treefs-path_security	frankengit-fg026a-treefs-path-security	g6	scripts/e2e/suites/treefs/path_security.sh	any	optional	mechanism	pass")
probe_path_mismatch=$(probe_manifest "$(printf '%s\n' "$good_manifest" |
  sed 's|g0	scripts/e2e/suites/harness/harness_json.sh|g0	scripts/e2e/suites/harness/harness_mechanics.sh|')")
rm -f -- "$probe_manifest_path"

fge_phase assert
fge_assert_eq FG-000A-PORT-041 0 "$probe_control" \
  'the unmodified manifest passes, so the refusals below are not refusing everything'
fge_assert_eq FG-000A-PORT-042 2 "$probe_duplicate" \
  'a duplicate manifest entry is refused before the run, not silently counted twice'
fge_assert_eq FG-000A-PORT-043 2 "$probe_classification" \
  'a mistyped classification is refused rather than dropping the row out of the required set'
fge_assert_eq FG-000A-PORT-044 2 "$probe_incomplete" \
  'an incomplete manifest row is refused rather than read with empty columns'
fge_assert_eq FG-000A-PORT-045 1 "$probe_rename" \
  'a renamed suite fails the set check: a rename is a release-surface change needing approval'
fge_assert_eq FG-000A-PORT-046 2 "$probe_path_mismatch" \
  'a row whose declared path derives a different id than the row declares is refused'
fge_assert_eq FG-000A-PORT-047 0 "$probe_optional" \
  'an optional manifest row is accepted rather than refused, so the optional branch is exercised'

# ---------------------------------------------------------------------------
# FG-091: every manifest row's owning bead must RESOLVE
#
# A row names an owning bead so a reader can find who is accountable for the
# suite. A typo, a tombstoned id, or a bead that was never filed leaves that
# column pointing at nothing, and nothing today notices -- the set check only
# looks at suite ids.
#
# WHY "RESOLVES" AND NOT "IS OPEN". The bead's wording is "exactly one ACTIVE
# owning Bead", and I nearly read that as open. It cannot mean that: every
# suite's originating bead eventually closes, so requiring an open owner would
# fail for every mature suite in the corpus, including all three here -- fg000a
# is CLOSED and is the correct owner of the harness suites. Measured: br show
# exits 0 for a closed bead, 0 for a blocked one, and 3 for an id that does not
# exist. Existence is the property that discriminates a real owner from a
# detached one; status does not.
#
# WHY THIS LIVES IN THE SUITE AND NOT IN run_all. The runner must not depend on
# the tracker: an e2e corpus that fails when br is missing or slow reports a
# defect in something it does not test. Here the dependency is optional and
# visible -- if br is absent the cell is a typed unsupported, so the check
# degrades into a named non-claim rather than into a false green or a broken
# run. That is the same shape as the oracle-unavailable arm in export_crash.
#
# DELETION CONDITION: goes when the manifest does.
# ---------------------------------------------------------------------------
fge_phase action
owner_probe_state=available
command -v br >/dev/null 2>&1 || owner_probe_state=unavailable

owner_unresolved=''
owner_checked=0
if [ "$owner_probe_state" = available ]; then
  while IFS=$'\t' read -r o_id o_bead _rest; do
    case $o_id in '' | '#'*) continue ;; esac
    owner_checked=$((owner_checked + 1))
    RUST_LOG=error br show "$o_bead" >/dev/null 2>&1 || owner_unresolved="$owner_unresolved$o_bead "
  done <"$E2E_ROOT/manifests/harness.tsv"
fi

# The probe must be able to fail, or "no unresolved owners" is a statement about
# a loop that never ran.
owner_detector_fires=no
if [ "$owner_probe_state" = available ]; then
  RUST_LOG=error br show frankengit-owner-that-cannot-exist >/dev/null 2>&1 ||
    owner_detector_fires=yes
fi

fge_phase assert
if [ "$owner_probe_state" = available ]; then
  fge_assert_eq FG-000A-PORT-048 '' "$owner_unresolved" \
    'every manifest row names an owning bead that resolves in the tracker'
  fge_assert_cmd FG-000A-PORT-049 'the owner check covered every manifest row' \
    test "$owner_checked" -ge 3
  fge_assert_eq FG-000A-PORT-050 yes "$owner_detector_fires" \
    'the owner check rejects a bead id that does not exist, so a clean result is not vacuous'
else
  fge_unsupported FG-000A-PORT-048 \
    'the beads tracker (br) is not on PATH, so manifest owning-bead resolution was not verified; the runner deliberately does not depend on the tracker, so this degrades to a named non-claim rather than failing the corpus'
  fge_unsupported FG-000A-PORT-049 \
    'owner-check coverage not measured: br unavailable'
  fge_unsupported FG-000A-PORT-050 \
    'owner-check falsifiability not demonstrated: br unavailable'
fi
