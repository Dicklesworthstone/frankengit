#!/usr/bin/env bash
# FrankenGit D14 license gate (FG-062).
#
# Refuses a release while the licensing model is unresolved, and refuses one
# where the resolved model is not stated identically everywhere it is stated.
#
# WHY THIS IS A SEPARATE, DURABLE GATE. `scripts/verify.sh release` already
# refuses today, but for an unrelated reason: no releasable binary exists yet.
# That refusal is TEMPORARY and is removed the day FG-035/FG-091 make releases
# real. If the launch-blocking licensing requirement rode on it, it would
# silently evaporate at exactly the moment it starts to matter. This gate does
# not depend on that one and does not go away when it does.
#
# Exit codes:
#   0  a decision is recorded and every surface agrees -- release may proceed
#   3  typed refusal: the decision is unresolved, or the surfaces disagree
#   2  usage or environment error
#
# The gate reads ONE canonical marker, in one authoritative document. It does
# not infer the decision from prose, because a gate that guesses is a gate that
# can be argued with.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 2

DECISION_DOC="docs/LICENSING_DECISION.md"
MARKER_PREFIX="<!-- fgit-license-decision:"
OSI_PREFIX="<!-- fgit-license-osi:"

fail=0
note() { printf 'license-gate: %s\n' "$1" >&2; }

if [ ! -f "$DECISION_DOC" ]; then
  note "REFUSED: $DECISION_DOC is missing; D14 cannot be evidenced."
  exit 3
fi

# ---------------------------------------------------------------- the marker
#
# Exactly one canonical marker line must exist. Two markers is not a decision,
# it is an argument, and picking one of them would be the gate inventing an
# answer.
marker_count=$(LC_ALL=C grep -c "^$MARKER_PREFIX" "$DECISION_DOC" || true)
if [ "$marker_count" -ne 1 ]; then
  note "REFUSED: expected exactly one '$MARKER_PREFIX ...' line in $DECISION_DOC, found $marker_count."
  exit 3
fi

status=$(LC_ALL=C grep "^$MARKER_PREFIX" "$DECISION_DOC" | sed -E 's/^<!-- fgit-license-decision:[[:space:]]*([A-Za-z0-9_.+-]+).*/\1/')

case "$status" in
  UNRESOLVED)
    note "REFUSED: D14 (license model) is UNRESOLVED."
    note "  A release may not ship under a provisional source-available rider."
    note "  Record the decision in $DECISION_DOC and set the marker to the chosen SPDX"
    note "  expression (or a named non-OSI model). See FG-062."
    exit 3
    ;;
  "")
    note "REFUSED: the decision marker in $DECISION_DOC has no parseable value."
    exit 3
    ;;
esac

note "decision marker: $status"

# A recorded decision must also say whether it is OSI-approved. The claim rule
# ("no doc claims open source until the license actually is") outlives the
# decision, so the answer has to be recorded rather than inferred from the SPDX
# string -- inferring it would mean this gate maintaining its own opinion of the
# OSI list, which is exactly the kind of second source of truth the project
# refuses elsewhere.
osi_count=$(LC_ALL=C grep -c "^$OSI_PREFIX" "$DECISION_DOC" || true)
if [ "$osi_count" -ne 1 ]; then
  note "REFUSED: expected exactly one '$OSI_PREFIX ...' line in $DECISION_DOC, found $osi_count."
  exit 3
fi
osi=$(LC_ALL=C grep "^$OSI_PREFIX" "$DECISION_DOC" | sed -E 's/^<!-- fgit-license-osi:[[:space:]]*([A-Za-z]+).*/\1/')
case "$osi" in
  yes | no) ;;
  *)
    note "REFUSED: a recorded decision must set the OSI marker to exactly 'yes' or 'no'; found '$osi'."
    note "  It is 'unknown' only while D14 is unresolved. See FG-062."
    exit 3
    ;;
esac
note "osi-approved: $osi"

# ------------------------------------------------- surfaces must agree exactly
#
# A resolved decision that only half the repository knows about is worse than
# an unresolved one: it lets a release claim terms the LICENSE file does not
# grant. Each surface below is checked for the decided value, and every
# disagreement is reported (not just the first) so one pass fixes all of them.
# Escapes a value for safe use inside an extended regular expression.
ere_escape() {
  printf '%s' "$1" | sed -E 's/[][(){}.^$*+?|\\]/\\&/g'
}

# A surface STATES the decided terms when it carries them as a standalone token
# on at least one line that does not deny them.
#
# The obvious implementation -- `grep -qF "$status"` -- is wrong, and was this
# gate's own bug until it was probed: under a decision of `MIT`, a README
# reading "This project is NOT MIT licensed" satisfied a substring match and the
# gate reported every surface consistent. That is the act-versus-mention
# confusion this repository has now hit five times, and a licensing gate is the
# worst place for it, because denial is the single most likely thing a stale
# surface actually says.
#
# Two corrections:
#   token boundary -- `Apache-2.0` must not be satisfied by
#     `Apache-2.0-WITH-LLVM-exception`, which is different terms, so an adjacent
#     identifier character disqualifies the match;
#   negation filter -- a line denying the terms does not state them. At least
#     one surviving line is required, so an incidental "not" elsewhere in the
#     file cannot suppress a genuine statement.
surface_states_terms() {
  local path="$1" esc pattern
  esc=$(ere_escape "$status")
  pattern="(^|[^A-Za-z0-9_+-])${esc}($|[^A-Za-z0-9_+-])"
  LC_ALL=C grep -E "$pattern" "$path" 2>/dev/null \
    | LC_ALL=C grep -viE "is ?n'?o?t|(^|[^a-z])(not|never|neither|nor|rather than|instead of|other than|excluding|no longer)([^a-z]|$)" \
    | LC_ALL=C grep -q .
}

check_surface() {
  local label="$1" path="$2"
  if [ ! -f "$path" ]; then
    note "REFUSED: $label ($path) is missing while a decision is recorded."
    fail=1
    return
  fi
  if ! surface_states_terms "$path"; then
    note "REFUSED: $label ($path) does not state the decided terms '$status'."
    note "  (a line that merely MENTIONS or DENIES them does not count as stating them)"
    fail=1
  fi
}

check_surface "LICENSE" "LICENSE"
check_surface "README licensing section" "README.md"
check_surface "CONTRIBUTING inbound terms" "CONTRIBUTING.md"

# Cargo metadata must not silently imply different terms. `license-file` is
# acceptable only while it points at a LICENSE that states the decided value,
# which the LICENSE check above already established.
if LC_ALL=C grep -qE '^license[[:space:]]*=' Cargo.toml; then
  if ! LC_ALL=C grep -qE "^license[[:space:]]*=[[:space:]]*\"$status\"" Cargo.toml; then
    note "REFUSED: root Cargo.toml 'license' does not equal the decided terms '$status'."
    fail=1
  fi
elif ! LC_ALL=C grep -qE '^license-file[[:space:]]*=' Cargo.toml; then
  note "REFUSED: root Cargo.toml declares neither 'license' nor 'license-file'."
  fail=1
fi

# ------------------------------------------- per-component licences (option D)
#
# Option D deliberately splits a reciprocal server from permissive clients,
# SDKs, schemas and conformance kits. A gate that only checked the root
# expression would pass such a repository while saying nothing about the crates
# that carry their OWN terms -- which under option D is the entire point of the
# decision, so the gate would be blindest exactly where the decision is most
# complex.
#
# The rule: every first-party crate that declares its own `license` must either
# match the root decision, or be named in the decision document. A split is
# allowed; an UNRECORDED split is not, because that is how a crate quietly ships
# terms nobody ruled on.
while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  crate_license=$(LC_ALL=C grep -m1 -E '^license[[:space:]]*=[[:space:]]*"' "$manifest" \
    | sed -E 's/^license[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/')
  [ -n "$crate_license" ] || continue
  [ "$crate_license" = "$status" ] && continue
  if ! LC_ALL=C grep -qF "$crate_license" "$DECISION_DOC"; then
    note "REFUSED: $manifest declares license '$crate_license', which is neither the decided"
    note "  root terms '$status' nor recorded as part of a split in $DECISION_DOC."
    fail=1
  fi
done < <(find crates -mindepth 2 -maxdepth 2 -name Cargo.toml 2>/dev/null | LC_ALL=C sort)

if [ "$fail" -ne 0 ]; then
  note "REFUSED: the recorded decision is not stated consistently across every surface."
  exit 3
fi

note "OK: D14 resolved as '$status' and stated consistently on every surface."
exit 0
