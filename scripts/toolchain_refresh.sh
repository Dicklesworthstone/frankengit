#!/usr/bin/env bash
# FrankenGit toolchain-refresh lane (FG-068), executing the D15 cadence policy
# recorded in docs/ADR-0010-NIGHTLY-ADVANCEMENT-CADENCE.md.
#
# A toolchain advancement is a MATERIAL change (AGENTS.md §3.4). This lane is
# what turns "someone bumped the pin" into "the pin moved because an evidence
# pack said it could". It proposes a candidate nightly, records the compiler
# fingerprints that make a result reproducible, runs the gate matrix, and either
# emits an evidence pack authorising the pin-bump commit or refuses with a typed
# reason naming the gate that regressed.
#
# WHAT THIS LANE IS NOT. It does not move the pin. ADR-0010 clause 3 requires
# the advancement to be one commit that moves `rust-toolchain.toml` and its
# mechanically coupled bootstrap-link metadata, separately from implementation
# fallout. A lane that edited the pin itself would let the evidence and the
# change land together unexamined. This lane
# only ever produces (or refuses to produce) the evidence that such a commit
# must cite.
#
# Usage:
#   scripts/toolchain_refresh.sh --candidate nightly-YYYY-MM-DD [options]
#   scripts/toolchain_refresh.sh --dry-run          # candidate := current pin
#
# Options:
#   --candidate <toolchain>  the nightly to evaluate (default: the current pin)
#   --dry-run                evaluate the current pin; expected to be a no-op pass
#   --gate-runner <path>     command invoked as `<path> <lane>` for each gate
#                            (default: scripts/verify.sh). Exists so the lane's
#                            refusal semantics can be exercised without running
#                            the full workspace matrix; see the NON-CLAIM below.
#   --out <dir>              evidence pack directory (default: evidence/toolchain)
#   --gate-timeout <secs>    per-gate wall clock ceiling (default: 1800). A gate
#                            that exceeds it is INCONCLUSIVE, which is neither a
#                            pass nor a regression -- see the loop below.
#   --verify-bump            the CHECKER HOOK: assert the pin currently in
#                            rust-toolchain.toml is backed by an evidence pack.
#                            Runs no gates. This is what makes a pin bump without
#                            evidence detectable instead of merely discouraged.
#
# Exit codes:
#   0  candidate passed every gate; evidence pack written; a pin bump may cite it
#   3  typed refusal: a gate regressed, or the candidate is not installed
#   2  usage error
#
# NON-CLAIM, stated here rather than implied: `--gate-runner` makes the gate
# matrix injectable, and the e2e suite uses that to drive the refusal paths
# deterministically. That proves the LANE's logic — fingerprinting, comparison,
# refusal, evidence emission — and proves nothing about the gates themselves,
# which have their own lanes. A green run of this lane means "the gates I was
# told to run reported success", never "the toolchain is good".
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

SCHEMA="frankengit.toolchain-refresh.v1"
PIN_FILE="rust-toolchain.toml"
GATES="docs constitution"

candidate=""
dry_run=0
verify_bump=0
gate_runner="scripts/verify.sh"
out_dir="evidence/toolchain"
gate_timeout=1800

die() { printf 'toolchain-refresh: %s\n' "$1" >&2; exit 2; }
note() { printf 'toolchain-refresh: %s\n' "$1" >&2; }
refuse() { printf 'toolchain-refresh: REFUSED: %s\n' "$1" >&2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --candidate) candidate="${2-}"; [ -n "$candidate" ] || die "--candidate needs a value"; shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --gate-runner) gate_runner="${2-}"; [ -n "$gate_runner" ] || die "--gate-runner needs a value"; shift 2 ;;
    --out) out_dir="${2-}"; [ -n "$out_dir" ] || die "--out needs a value"; shift 2 ;;
    --verify-bump) verify_bump=1; shift ;;
    --gate-timeout) gate_timeout="${2-}"; [ -n "$gate_timeout" ] || die "--gate-timeout needs a value"; shift 2 ;;
    -h | --help) sed -n '1,40p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

# ------------------------------------------------------------- the current pin
[ -f "$PIN_FILE" ] || die "$PIN_FILE is missing; there is no pin to advance from"
current_pin=$(LC_ALL=C grep -m1 -E '^channel[[:space:]]*=' "$PIN_FILE" |
  sed -E 's/^channel[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/')
[ -n "$current_pin" ] || die "$PIN_FILE declares no channel"

# A floating channel is refused outright: AGENTS.md §3.4 requires a DATED
# nightly, and "advance from `nightly`" is not a question with an answer.
case "$current_pin" in
  nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
  *)
    refuse "the current pin '$current_pin' is not a dated nightly; §3.4 requires one"
    exit 3
    ;;
esac

# ------------------------------------------------------------- the checker hook
#
# ADR-0010 clause 3 makes an advancement one commit that moves the pin. That is
# only enforceable if a moved pin without evidence is DETECTABLE, so this mode
# answers exactly one question -- is the pin that is currently checked in backed
# by a pack that names it? -- and runs nothing else. It is cheap enough to sit
# in a pre-commit guard or a docs lane.
if [ "$verify_bump" -eq 1 ]; then
  pack="$out_dir/$current_pin.pack"
  if [ ! -f "$pack" ]; then
    refuse "the checked-in pin '$current_pin' has no evidence pack at $pack."
    refuse "  A pin bump must cite the pack produced by evaluating that candidate."
    exit 3
  fi
  if ! LC_ALL=C grep -qE "^candidate	$current_pin\$" "$pack"; then
    refuse "$pack exists but does not name '$current_pin' as its candidate."
    exit 3
  fi
  note "OK: pin '$current_pin' is backed by $pack"
  exit 0
fi

if [ "$dry_run" -eq 1 ] && [ -z "$candidate" ]; then
  candidate="$current_pin"
fi
[ -n "$candidate" ] || die "no candidate; pass --candidate <toolchain> or --dry-run"

note "current pin: $current_pin"
note "candidate  : $candidate"

# A candidate that is not the current pin and not older is the normal case; a
# candidate OLDER than the pin is a rollback and must be stated as one rather
# than slipping through as an advancement.
if [ "$candidate" != "$current_pin" ]; then
  older=$(printf '%s\n%s\n' "$current_pin" "$candidate" | LC_ALL=C sort | head -1)
  if [ "$older" = "$candidate" ]; then
    note "NOTE: candidate is older than the current pin; this is a ROLLBACK evaluation"
  fi
fi

# ------------------------------------------------------------- fingerprints
#
# ADR-0010 clause 4 makes determinism the blocking check, and a determinism
# result is meaningless without knowing which compiler produced it. Codegen
# differences track the LLVM version at least as often as the rustc version, so
# both are recorded; a pack missing either cannot support a reproducibility
# claim later.
if ! command -v rustc >/dev/null 2>&1; then
  refuse "rustc is not on PATH; the candidate cannot be fingerprinted"
  exit 3
fi

fingerprint=$(rustc -vV 2>/dev/null)
rustc_release=$(printf '%s\n' "$fingerprint" | LC_ALL=C grep -m1 '^release:' | sed 's/^release:[[:space:]]*//')
rustc_commit=$(printf '%s\n' "$fingerprint" | LC_ALL=C grep -m1 '^commit-hash:' | sed 's/^commit-hash:[[:space:]]*//')
rustc_host=$(printf '%s\n' "$fingerprint" | LC_ALL=C grep -m1 '^host:' | sed 's/^host:[[:space:]]*//')
llvm_version=$(printf '%s\n' "$fingerprint" | LC_ALL=C grep -m1 '^LLVM version:' | sed 's/^LLVM version:[[:space:]]*//')

for field in rustc_release rustc_commit rustc_host llvm_version; do
  eval "value=\${$field}"
  if [ -z "$value" ]; then
    refuse "could not read '$field' from rustc -vV; the evidence pack would be unreproducible"
    exit 3
  fi
done

note "rustc $rustc_release ($rustc_commit) host=$rustc_host llvm=$llvm_version"

# The fingerprint above describes the ACTIVE toolchain, which is not
# automatically the candidate. If they differ, every gate result below was
# produced by a compiler the pack does not name, and the pack becomes evidence
# about something it never measured -- the most damaging thing an evidence
# artifact can be, because it is indistinguishable from a real one.
#
# So the identity is verified rather than assumed. `rustup` is the authority
# when present; when it is absent the lane says so IN THE PACK rather than
# silently downgrading to a guess, because a reader must be able to tell a
# verified attribution from an unverified one.
active_toolchain=""
identity="unverified-no-rustup"
if command -v rustup >/dev/null 2>&1; then
  active_toolchain=$(rustup show active-toolchain 2>/dev/null | head -1 | cut -d' ' -f1)
  if [ -n "$active_toolchain" ]; then
    case "$active_toolchain" in
      "$candidate" | "$candidate"-*)
        identity="verified"
        ;;
      *)
        refuse "the active toolchain is '$active_toolchain' but the candidate is '$candidate'."
        refuse "  Gate results would be attributed to a compiler that did not produce them."
        refuse "  Activate the candidate first (rustup toolchain install $candidate), then re-run."
        exit 3
        ;;
    esac
  fi
fi
note "toolchain identity: $identity${active_toolchain:+ ($active_toolchain)}"

# ------------------------------------------------------------- the gate matrix
[ -x "$gate_runner" ] || [ -f "$gate_runner" ] || {
  refuse "gate runner '$gate_runner' is not present"
  exit 3
}

# Each gate runs under a wall-clock ceiling. This is not defensive padding: the
# gates shell out to cargo, and on a shared build host a gate can sit queued
# behind another agent's build lock for longer than any useful evaluation
# window. Without a ceiling this lane simply never returns, which is the worst
# outcome available to it -- an evidence lane that hangs produces no evidence
# and no refusal, so nobody learns anything and the run looks merely slow.
#
# A timed-out gate is INCONCLUSIVE, and inconclusive is deliberately a third
# state rather than being folded into failure. "The gate said no" and "the gate
# never answered" call for different responses -- investigate the candidate
# versus re-run when the host is quiet -- and collapsing them would send a
# reader chasing a toolchain regression that was really lock contention. Both
# still block the pack: only an affirmative pass authorises a bump.
gate_results=""
regressed=""
inconclusive=""
for gate in $GATES; do
  gate_exit=0
  if command -v timeout >/dev/null 2>&1; then
    timeout "$gate_timeout" "$gate_runner" "$gate" >/dev/null 2>&1 || gate_exit=$?
  else
    "$gate_runner" "$gate" >/dev/null 2>&1 || gate_exit=$?
  fi
  gate_results="$gate_results $gate=$gate_exit"
  case "$gate_exit" in
    0) ;;
    124 | 137) inconclusive="$inconclusive $gate(timeout>${gate_timeout}s)" ;;
    *) regressed="$regressed $gate(exit=$gate_exit)" ;;
  esac
done
note "gates:$gate_results"

# ------------------------------------------------------------- the verdict
#
# Refusal is the interesting direction and is therefore explicit: a regressed
# gate produces NO evidence pack at all. Emitting a pack that records its own
# failure would create an artifact a pin bump could cite while a reader assumed
# citation implied authorisation.
if [ -n "$inconclusive" ]; then
  refuse "candidate '$candidate' is INCONCLUSIVE:$inconclusive"
  refuse "  a gate did not finish within ${gate_timeout}s. This is NOT a regression:"
  refuse "  nothing was learned about the candidate. Re-run when the host is quiet,"
  refuse "  or raise --gate-timeout. No evidence pack written."
  exit 3
fi

if [ -n "$regressed" ]; then
  refuse "candidate '$candidate' regressed:$regressed"
  refuse "  no evidence pack written; the pin may not move on this candidate"
  exit 3
fi

mkdir -p "$out_dir" || die "cannot create evidence directory $out_dir"
pack="$out_dir/$candidate.pack"

# The pack is the artifact a pin-bump commit cites, so it records what was
# evaluated, what produced the result, and what was NOT covered. The last of
# those is the part a reader needs most and the part an evidence artifact
# usually omits.
{
  printf 'schema\t%s\n' "$SCHEMA"
  printf 'current_pin\t%s\n' "$current_pin"
  printf 'candidate\t%s\n' "$candidate"
  printf 'rustc_release\t%s\n' "$rustc_release"
  printf 'rustc_commit\t%s\n' "$rustc_commit"
  printf 'rustc_host\t%s\n' "$rustc_host"
  printf 'llvm_version\t%s\n' "$llvm_version"
  printf 'gate_runner\t%s\n' "$gate_runner"
  printf 'gate_timeout_seconds\t%s\n' "$gate_timeout"
  printf 'toolchain_identity\t%s\n' "$identity"
  printf 'active_toolchain\t%s\n' "${active_toolchain:-unknown}"
  for gate in $GATES; do
    printf 'gate\t%s\tpass\n' "$gate"
  done
  printf 'not_covered\tperformance\tno benchmark delta was measured by this run\n'
  printf 'not_covered\tgates\tonly the gates listed above were run\n'
  if [ "$identity" != "verified" ]; then
    printf 'not_covered\tattribution\trustup absent: gate results are NOT verified to come from the named candidate\n'
  fi
} > "$pack" || die "cannot write evidence pack $pack"

note "evidence pack: $pack"
note "OK: candidate '$candidate' passed every gate; a pin bump may cite this pack"
exit 0
