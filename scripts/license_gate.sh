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

# ------------------------------------------------- surfaces must agree exactly
#
# A resolved decision that only half the repository knows about is worse than
# an unresolved one: it lets a release claim terms the LICENSE file does not
# grant. Each surface below is checked for the decided value, and every
# disagreement is reported (not just the first) so one pass fixes all of them.
check_surface() {
  local label="$1" path="$2"
  if [ ! -f "$path" ]; then
    note "REFUSED: $label ($path) is missing while a decision is recorded."
    fail=1
    return
  fi
  if ! LC_ALL=C grep -qF "$status" "$path"; then
    note "REFUSED: $label ($path) does not state the decided terms '$status'."
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
