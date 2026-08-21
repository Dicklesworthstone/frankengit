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
REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init

fge_phase setup
fge_context bead frankengit-fg069-procmacro-audit-0gse
fge_context constitution_line "DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md:142"

GOLDEN_DIR="$E2E_ROOT/suites/constitution/goldens"
GOLDEN="$GOLDEN_DIR/fgit_types_identity_derives.expanded"

# The designated authority-sensitive set: the canonical internal identity plus
# the component types whose ordering and hashing it DERIVES. Extending this list
# is a deliberate act, not a glob, so nothing joins the golden silently.
#
# DigestBytes is deliberately absent. It hand-writes PartialEq/PartialOrd/Ord/
# Hash for constant-time comparison, so it has no generated ordering to pin, and
# sweeping its hand-written impls in would make the golden churn on ordinary
# refactors -- see the note on extract_derives below.
#
# APPLICABILITY LIMIT, recorded rather than papered over: InternalObjectId's
# derived Ord delegates its `digest` field to that hand-written DigestBytes Ord.
# This golden therefore pins the ORDER in which the four fields are consulted,
# not the comparison semantics of every field. A change inside DigestBytes::cmp
# alters identity ordering and this suite will not see it. That case is
# fgit-types' own to test; FG-069-EXPAND-008 records the boundary so the gap is
# visible instead of implied.
AUTHORITY_TYPES="InternalObjectId DigestAlgorithmId CodecVersion DomainTag"

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
# Only blocks carrying `#[automatically_derived]` are captured. That marker is
# rustc's own statement that the code was generated, so the golden covers
# exactly what the constitution names -- generated code -- and nothing else.
#
# The narrowing is deliberate and load-bearing. `DigestBytes` hand-writes its
# PartialEq/Ord/Hash (constant-time comparison), and an earlier version of this
# extractor swept those in. A golden that churns whenever someone refactors a
# hand-written impl trains reviewers to re-bless it reflexively, and a
# reflexively re-blessed golden protects nothing (RH-3). A hand-written Ord
# change is also visible as a source diff in review; a DERIVED Ord change from a
# field reorder is not visible anywhere, which is precisely why the generated
# half is the half that needs pinning.
extract_derives() {
  local source=$1 wanted=$2 type_name in_block=0 prev=""
  for type_name in $wanted; do
    in_block=0
    prev=""
    while IFS= read -r line; do
      if [ "$in_block" -eq 0 ]; then
        if [ "$prev" = "    #[automatically_derived]" ]; then
          case $line in
            "    impl "*" for $type_name {" | "    impl "*" for $type_name<"*)
              in_block=1
              printf '%s\n' "$prev"
              printf '%s\n' "$line"
              ;;
          esac
        fi
        prev=$line
        continue
      fi
      printf '%s\n' "$line"
      [ "$line" = "    }" ] && in_block=0
      prev=$line
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
# Scoped to the InternalObjectId Ord block only. An unscoped grep over the whole
# extract also swept in CodecVersion's own Ord (major, minor) and produced a
# field list belonging to two types at once -- a wrong answer that looked like a
# real one on first run.
# Pull one named impl block out of the extract. Written once and used for both
# Ord and Hash: the two derives whose field order is separately load-bearing.
extract_one_impl() {
  local header=$1 source=$2 dest=$3 line in_block=0
  : >"$dest"
  while IFS= read -r line; do
    if [ "$in_block" -eq 0 ]; then
      [ "$line" = "$header" ] || continue
      in_block=1
      printf '%s\n' "$line" >>"$dest"
      continue
    fi
    printf '%s\n' "$line" >>"$dest"
    [ "$line" = "    }" ] && in_block=0
  done <"$source"
}

ord_block="$(fge_artifact_path expansion/internal_object_id_ord.rs)"
extract_one_impl "    impl ::core::cmp::Ord for InternalObjectId {" "$observed" "$ord_block"
ord_order="$(grep -oE 'Ord::cmp\(&self\.[a-z_]+' "$ord_block" | sed 's/.*self\.//' | tr '\n' ' ')"

# Hash carries the same risk as Ord and is easy to overlook because nothing
# reads like a comparison: the derive hashes fields in declaration order, so a
# reorder changes every hash bucket for the canonical identity. Asserted
# separately from the golden so a reorder names itself instead of arriving as an
# opaque diff.
hash_block="$(fge_artifact_path expansion/internal_object_id_hash.rs)"
extract_one_impl "    impl ::core::hash::Hash for InternalObjectId {" "$observed" "$hash_block"
hash_order="$(grep -oE 'Hash::hash\(&self\.[a-z_]+' "$hash_block" | sed 's/.*self\.//' | tr '\n' ' ')"

golden_state=absent
[ -f "$GOLDEN" ] && golden_state=present

diff_path="$(fge_artifact_path expansion/golden.diff)"
# An ABSENT golden is a FAILURE, not a skip. Leaving diff_exit at 0 here made
# the golden assertion pass vacuously on the very first run, when no golden
# existed at all -- a test that could not fail, which is the exact shape this
# suite exists to catch elsewhere. Caught on first execution.
diff_exit=1
if [ "$golden_state" = present ]; then
  diff_exit=0
  diff -u "$GOLDEN" "$observed" >"$diff_path" 2>&1 || diff_exit=$?
else
  printf 'no golden at %s; nothing to compare against\n' "$GOLDEN" >"$diff_path"
fi
fge_artifact expansion/golden.diff text

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

fge_assert_eq FG-069-EXPAND-004 4 "$covered" \
  'all four designated types were extracted, so the golden is not vacuous'

# The load-bearing one: field declaration order decides identity ordering.
fge_assert_eq FG-069-EXPAND-005 'algorithm domain codec_version digest ' "$ord_order" \
  'InternalObjectId Ord compares fields in declaration order; a reorder changes identity ordering'

fge_assert_eq FG-069-EXPAND-009 'algorithm domain codec_version digest ' "$hash_order" \
  'InternalObjectId Hash consumes fields in declaration order; a reorder rebuckets every identity'

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
# Written as a full `if`, not `grep -q ... && var=...`: under `set -e` a failing
# grep at the tail of an AND-list takes the exit status of the whole list and
# aborts the script -- and "absent" is the EXPECTED result here, so the happy
# path would have been the one that killed the suite.
# Ord is not the only delegation: InternalObjectId's derived Hash and PartialEq
# route the `digest` field to DigestBytes' hand-written impls as well. All three
# are checked, because any one of them becoming derived moves authority-relevant
# semantics into generated code that this golden would not be covering.
digest_derived=""
if [ -s "$expanded" ]; then
  for tr in "cmp::Ord" "hash::Hash" "cmp::PartialEq"; do
    if grep -q "impl ::core::$tr for DigestBytes" "$expanded"; then
      digest_derived="$digest_derived$tr "
    fi
  done
fi
fge_assert_eq FG-069-EXPAND-008 '' "$digest_derived" \
  'DigestBytes Ord/Hash/PartialEq stay hand-written; if any becomes derived it must join the golden above'

fge_field trivial_clone_impls "$trivial_clone"
fge_field authority_types "$AUTHORITY_TYPES"
fge_note trivial-clone-ledger \
  "builtin Clone derive emits $trivial_clone 'unsafe impl TrivialClone' into a forbid(unsafe_code) crate; permitted via automatically_derived, recorded so the zero-unsafe claim keeps its asterisk"
