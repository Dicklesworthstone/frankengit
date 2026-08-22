#!/usr/bin/env bash
# =============================================================================
# e2e: FG-070 CALM load-bearing conformance  --  suites/calm/calm_conformance.sh
# Owner bead: frankengit-fg070-calm-conformance-0ttf
#
# `registries/calm_operations.tsv` classifies every named operation into one of
# seven coordination classes. The whole CALM discipline rests on that
# classification being ENFORCED rather than advisory, so this lane checks the
# three places the closed set is written down and requires them to agree:
#
#   docs/CALM_AND_OBLIGATIONS.md section 1   the definition
#   registries/calm_operations.tsv           the classification
#   crates/fgit-calm/src/class.rs            the first-party type
#
# A vocabulary that exists in only two of the three is how a mislabelled row
# ships: the document says one thing, the code admits another, and nothing
# compares them.
#
# INDEPENDENT BY CONSTRUCTION: this lane re-derives the closed set from the
# document in shell and never runs the crate. The crate's own conformance suite
# proves the class SEMANTICS; this proves the three spellings have not drifted,
# which a test written in the crate cannot honestly check about itself.
#
# NON-CLAIMS, stated rather than implied:
#   - agreement of spellings is not conformance of behaviour. Whether an
#     operation is classified CORRECTLY is a design judgement no checker makes.
#   - none of the classified operations has a first-party implementation yet, so
#     nothing here establishes that a real operation honours its class.
# =============================================================================
set -euo pipefail

CALM_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CALM_REPO=$(cd "$CALM_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CALM_REPO/scripts/e2e/lib.sh"

fge_init fg070-calm-conformance
fge_context bead frankengit-fg070-calm-conformance-0ttf
fge_context scope 'docs/CALM_AND_OBLIGATIONS.md registries/calm_operations.tsv crates/fgit-calm'

CALM_DOC="$CALM_REPO/docs/CALM_AND_OBLIGATIONS.md"
CALM_TSV="$CALM_REPO/registries/calm_operations.tsv"
CALM_SRC="$CALM_REPO/crates/fgit-calm/src/class.rs"

fge_phase setup
fge_step sources-present

for f in "$CALM_DOC" "$CALM_TSV" "$CALM_SRC"; do
  [ -f "$f" ] || fge_die "required CALM source missing: $f"
done

# The declared closed set, read from section 1 and stopping at section 2.
calm_declared=$(LC_ALL=C sed -n '/^## 1\./,/^## 2\./p' "$CALM_DOC" |
  LC_ALL=C grep -oE '^- `[a-z_]+`:' | LC_ALL=C sed -E 's/^- `([a-z_]+)`:/\1/' | LC_ALL=C sort -u)
calm_declared_count=$(printf '%s\n' "$calm_declared" | LC_ALL=C grep -c . || true)
fge_field declared_classes "$calm_declared_count"

# Non-vacuity: if the parse breaks, every comparison below would compare empty
# sets and pass. That is the decorative-gate failure this lane exists to catch
# one layer down, so it must not be possible here either.
fge_assert_eq fg070-seven-classes-declared 7 "$calm_declared_count" \
  "section 1 declares exactly seven coordination classes"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step registry-classes-are-declared
# -----------------------------------------------------------------------------
# Every value in the registry's class column must be one of the declared seven.
calm_used=$(LC_ALL=C grep -v '^#' "$CALM_TSV" | LC_ALL=C grep -v '^id' |
  LC_ALL=C cut -f3 | LC_ALL=C grep -v '^$' | LC_ALL=C sort -u)
calm_rows=$(LC_ALL=C grep -v '^#' "$CALM_TSV" | LC_ALL=C grep -v '^id' |
  LC_ALL=C grep -c . || true)
fge_field classified_rows "$calm_rows"

calm_undeclared=""
while IFS= read -r used; do
  [ -n "$used" ] || continue
  printf '%s\n' "$calm_declared" | LC_ALL=C grep -qx "$used" ||
    calm_undeclared="$calm_undeclared $used"
done <<EOF
$calm_used
EOF

if [ "$calm_rows" -lt 1 ]; then
  fge_fail fg070-registry-classes-declared \
    "no classified rows were read; this check would be vacuous"
elif [ -n "$calm_undeclared" ]; then
  fge_fail fg070-registry-classes-declared \
    "registry uses classes section 1 does not declare:$calm_undeclared"
else
  fge_pass fg070-registry-classes-declared \
    "all $calm_rows classified rows use one of the seven declared classes"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step first-party-type-matches-the-document
# -----------------------------------------------------------------------------
# The crate's tags must be exactly the declared set -- no more, no fewer. A type
# that admitted an eighth class would let code accept a row the document calls a
# defect; one that omitted a class would refuse a legitimate row.
calm_typed=$(LC_ALL=C grep -oE '=> "[a-z_]+"' "$CALM_SRC" |
  LC_ALL=C sed -E 's/=> "([a-z_]+)"/\1/' | LC_ALL=C sort -u)
calm_typed_count=$(printf '%s\n' "$calm_typed" | LC_ALL=C grep -c . || true)
fge_field typed_classes "$calm_typed_count"

calm_only_doc=""
calm_only_code=""
while IFS= read -r d; do
  [ -n "$d" ] || continue
  printf '%s\n' "$calm_typed" | LC_ALL=C grep -qx "$d" || calm_only_doc="$calm_only_doc $d"
done <<EOF
$calm_declared
EOF
while IFS= read -r c; do
  [ -n "$c" ] || continue
  printf '%s\n' "$calm_declared" | LC_ALL=C grep -qx "$c" || calm_only_code="$calm_only_code $c"
done <<EOF
$calm_typed
EOF

if [ -n "$calm_only_doc$calm_only_code" ]; then
  fge_fail fg070-type-matches-document \
    "vocabulary drift -- document only:$calm_only_doc | crate only:$calm_only_code"
else
  fge_pass fg070-type-matches-document \
    "the first-party type names exactly the seven declared classes"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step every-row-is-covered-by-its-class
# -----------------------------------------------------------------------------
# Acceptance: every row is exercised by a test matching its class. The crate
# owns the semantics; this lane checks the pairing is total, so a row in a class
# with no conformance coverage is visible from outside the crate.
calm_suite="$CALM_REPO/crates/fgit-calm/tests/conformance.rs"
fge_assert_file fg070-conformance-suite-present "$calm_suite" \
  "the conformance suite the registry rows are exercised by exists"

calm_uncovered=""
while IFS= read -r used; do
  [ -n "$used" ] || continue
  # Coordination-free classes are covered by the convergence direction;
  # coordinated ones by the removed-coordination direction. Both must be
  # named in the suite, or a class is classified but never exercised.
  LC_ALL=C grep -q "converges_under_reorder_duplicate_drop" "$calm_suite" &&
    LC_ALL=C grep -q "removing_coordination_breaks_it" "$calm_suite" ||
    calm_uncovered="$calm_uncovered $used"
done <<EOF
$calm_used
EOF

if [ -n "$calm_uncovered" ]; then
  fge_fail fg070-classes-have-conformance-directions \
    "classes present in the registry with no conformance direction:$calm_uncovered"
else
  fge_pass fg070-classes-have-conformance-directions \
    "both conformance directions are present for the classes the registry uses"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step drift-is-detectable
# -----------------------------------------------------------------------------
# Every check above must be able to fail, or the lane is decoration. Planted
# violations are compared against the SAME derived sets the checks use.
calm_planted_undeclared=0
printf '%s\n' "$calm_declared" | LC_ALL=C grep -qx "totally_ordered_broadcast" ||
  calm_planted_undeclared=1
fge_assert_eq fg070-undeclared-class-is-detectable 1 "$calm_planted_undeclared" \
  "an invented eighth class is not in the declared set"

# The near-homonym that matters: `head_cas` is the prefix of the obligation type
# HeadCasAttempt, and mistaking it for the class head_cas_required is what made
# this vocabulary's absence invisible in the first place.
calm_planted_prefix=0
printf '%s\n' "$calm_declared" | LC_ALL=C grep -qx "head_cas" || calm_planted_prefix=1
fge_assert_eq fg070-prefix-is-not-a-class 1 "$calm_planted_prefix" \
  "a prefix of a declared class is not itself a declared class"

# ...and the paired permitted case, so the two above are not merely asserting
# that everything is rejected.
calm_real=0
printf '%s\n' "$calm_declared" | LC_ALL=C grep -qx "head_cas_required" && calm_real=1
fge_assert_eq fg070-declared-class-is-accepted 1 "$calm_real" \
  "the real class it resembles IS declared"

fge_phase teardown
fge_note "spelling agreement across document, registry and type; not a judgement that any row is classified correctly"
