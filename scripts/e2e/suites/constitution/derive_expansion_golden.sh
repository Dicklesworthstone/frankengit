#!/usr/bin/env bash
# e2e: golden-expansion audit for authority-sensitive generated code
# (bead frankengit-fg069-procmacro-audit-0gse).
#
# DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md:142 requires that "authority-
# sensitive generated code has a checked-in schema fingerprint and golden
# expansion test". This is that test.
#
# WHAT THE GENERATED CODE ACTUALLY IS, since the bead's own premise was stale.
# The bead assumed serde derives on canonical identity types. There are none:
# no first-party crate depends on serde, thiserror, prost, zerocopy, pin-project
# or bincode, and ADR-0002 made the canonical codec hand-owned precisely so
# encoding is not derive-driven. A golden over serde output would assert over an
# empty set and pass forever.
#
# The authority-sensitive generated code we DO have is the BUILTIN derives on
# the identity types. `#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]` on a
# struct generates comparison, ordering and hashing in FIELD DECLARATION ORDER.
# For `InternalObjectId` the expansion compares algorithm -> domain ->
# codec_version -> digest, in that order. Reordering those fields is a
# source-level edit with no visible call-site change that silently alters total
# ordering and hash bucketing for the repository's canonical identity — which
# decides BTreeMap lookup and every ordering comparison built on it. That is
# exactly the "a version bump could silently change identity" risk the
# constitution names, reached by a different vector than the bead expected.
#
# TOOLING: `rustc -Zunpretty=expanded` via `cargo rustc`. This adds NO
# dependency — rust-toolchain.toml already pins a dated nightly. `cargo-expand`
# would have needed a registries/dependency_policy.tsv tooling row (cf. DEP-011
# nektos-act) and is deliberately not used.
#
# A TOOLCHAIN BUMP THAT CHANGES DERIVE EXPANSION WILL FAIL THIS TEST. That is
# intended, not a defect: AGENTS.md §3.4 makes a toolchain advancement a
# material change requiring exactly this kind of evidence. Re-bless the golden
# only with the expansion diff read and recorded.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init

fge_phase setup
fge_context bead frankengit-fg069-procmacro-audit-0gse
fge_context constitution_line "DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md:142"

REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
GOLDEN_DIR="$E2E_ROOT/suites/constitution/goldens"
GOLDEN="$GOLDEN_DIR/fgit_types_identity_derives.expanded"

# The designated authority-sensitive set: the canonical internal identity plus
# every component its derived ordering and hashing depend on. Extending this
# list is a deliberate act, not a glob, so nothing joins the golden silently.
AUTHORITY_TYPES="InternalObjectId DigestBytes DigestAlgorithmId CodecVersion DomainTag"

# ---------------------------------------------------------------------------
# expand
# ---------------------------------------------------------------------------
fge_phase action

expanded="$(fge_artifact_path expansion/fgit-types.expanded.rs)"
fge_capture expand-fgit-types \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
  cargo rustc --manifest-path "$REPO_ROOT/Cargo.toml" -p fgit-types --lib -- \
  -Zunpretty=expanded
expand_exit=$FGE_LAST_EXIT
cp "$FGE_LAST_STDOUT_FILE" "$expanded" 2>/dev/null || true
fge_artifact expansion/fgit-types.expanded.rs rust-source

# ---------------------------------------------------------------------------
# extract the derive impls for the designated types
#
# Pure bash: rustc's pretty-printer emits each impl at a stable indentation, so
# a block runs from `    impl ... for <Type> {` to the next line that is exactly
# four spaces and a closing brace. No jq/python/awk — the harness adds nothing
# to the closed dependency universe, and that rule applies to its own suites.
# ---------------------------------------------------------------------------
extract_derives() {
  local source=$1 wanted=$2 type_name in_block=0
  for type_name in $wanted; do
    in_block=0
    while IFS= read -r line; do
      if [ "$in_block" -eq 0 ]; then
        case $line in
          "    impl "*" for $type_name {")
            in_block=1
            printf '%s\n' "$line"
            ;;
          "    impl "*" for $type_name<"*)
            in_block=1
            printf '%s\n' "$line"
            ;;
        esac
        continue
      fi
      printf '%s\n' "$line"
      [ "$line" = "    }" ] && in_block=0
    done <"$source"
  done
}

observed="$(fge_artifact_path expansion/identity_derives.observed)"
if [ -s "$expanded" ]; then
  extract_derives "$expanded" "$AUTHORITY_TYPES" >"$observed"
else
  : >"$observed"
fi
fge_artifact expansion/identity_derives.observed text

observed_lines=0
while IFS= read -r _l; do observed_lines=$((observed_lines + 1)); done <"$observed"

# Count how many of the designated types actually appear, so an extraction that
# silently matched nothing cannot masquerade as a passing golden.
covered=0
missing=""
for t in $AUTHORITY_TYPES; do
  if grep -q " for $t {" "$observed" 2>/dev/null || grep -q " for $t<" "$observed" 2>/dev/null; then
    covered=$((covered + 1))
  else
    missing="$missing$t "
  fi
done

# Ordering evidence: the Ord impl for the canonical identity must compare its
# fields in declaration order. Captured as its own assertion so a reorder is
# reported as what it is rather than as an opaque golden diff.
ord_order=""
if grep -q "impl ::core::cmp::Ord for InternalObjectId" "$observed"; then
  ord_order="$(grep -oE 'Ord::cmp\(&self\.[a-z_]+' "$observed" | sed 's/.*self\.//' | tr '\n' ' ')"
fi

golden_state=absent
[ -f "$GOLDEN" ] && golden_state=present

diff_path="$(fge_artifact_path expansion/golden.diff)"
diff_exit=0
if [ "$golden_state" = present ]; then
  diff -u "$GOLDEN" "$observed" >"$diff_path" 2>&1 || diff_exit=$?
  fge_artifact expansion/golden.diff text
fi

# ---------------------------------------------------------------------------
# assertions
# ---------------------------------------------------------------------------
fge_phase assert

fge_assert_eq FG-069-EXPAND-001 0 "$expand_exit" \
  'rustc -Zunpretty=expanded succeeds with the pinned nightly and no extra tooling'

fge_assert_cmd FG-069-EXPAND-002 'the expansion produced real output' \
  test "$observed_lines" -gt 20

fge_assert_eq FG-069-EXPAND-003 '' "$missing" \
  'every designated authority-sensitive type appears in the extracted expansion'

fge_assert_eq FG-069-EXPAND-004 5 "$covered" \
  'all five designated types were extracted, so the golden is not vacuous'

# The load-bearing one: field declaration order decides identity ordering.
fge_assert_eq FG-069-EXPAND-005 'algorithm domain codec_version digest ' "$ord_order" \
  'InternalObjectId Ord compares fields in declaration order; a reorder changes identity ordering'

fge_assert_eq FG-069-EXPAND-006 present "$golden_state" \
  'a checked-in golden exists, as the constitution requires'

fge_assert_eq FG-069-EXPAND-007 0 "$diff_exit" \
  'the expansion matches the checked-in golden byte for byte'

# Recorded, not asserted as a failure: the builtin Clone derive emits
# `unsafe impl ::core::clone::TrivialClone` into a crate carrying
# `#![forbid(unsafe_code)]`. It is permitted because it is
# `#[automatically_derived]`, but a project whose V1 target is "zero first-party
# unsafe" should know that sentence has an asterisk. Asserting its PRESENCE
# would break on a toolchain that stops emitting it, so this records the count
# as evidence rather than pinning it.
trivial_clone=0
if [ -s "$expanded" ]; then
  trivial_clone="$(grep -c 'unsafe impl ::core::clone::TrivialClone' "$expanded" || true)"
fi
fge_field trivial_clone_impls "$trivial_clone"
fge_field authority_types "$AUTHORITY_TYPES"
fge_note trivial-clone-ledger \
  "builtin Clone derive emits $trivial_clone 'unsafe impl TrivialClone' into a forbid(unsafe_code) crate; permitted via automatically_derived, recorded so the zero-unsafe claim keeps its asterisk"
