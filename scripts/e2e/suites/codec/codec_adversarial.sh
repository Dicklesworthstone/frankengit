#!/usr/bin/env bash
# e2e: the codec's adversarial evidence, run end to end.
#
# Three things have to hold together for the golden corpus to be worth
# anything, and this suite runs all three at one revision:
#
#   1. the encoder reproduces every committed vector byte for byte;
#   2. no mutant of any vector shares an identity with its canonical form;
#   3. a verifier that shares no code with the codec re-derives the same
#      identities from the same bytes.
#
# The third is the one that cannot be faked by the crate under test. A bug
# present in both an encoder and its checker is invisible, so `fgit-codec-verify`
# depends on std alone and re-implements the format from the written
# specification.
#
# Every vector gets its own NDJSON record carrying its digest, so a corpus
# change is visible in the log rather than only in a diff.
set -euo pipefail

CA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CA_REPO=$(cd "$CA_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CA_REPO/scripts/e2e/lib.sh"

fge_init fg002c-codec-adversarial
fge_context bead frankengit-fg002c-codec-adversarial-iwe
fge_context codec fgit-codec
fge_context verifier fgit-codec-verify

# The Rust campaign is exhaustive over every bit of every vector rather than
# sampled, so it needs no seed to be reproducible. The property tests that DO
# sample carry a fixed seed compiled into them; it is recorded here so a
# failure in the log can be traced to the run that produced it without opening
# the source.
readonly CA_PROPERTY_SEED="${FGE_CODEC_SEED:-0x0c0dec005eed0001}"
fge_context property_seed "$CA_PROPERTY_SEED"
fge_context harness_seed "$(fge_seed)"

readonly CA_CORPUS="$CA_REPO/crates/fgit-codec/tests/goldens"

fge_phase setup

fge_assert_dir FG-002C-E2E-001 "$CA_CORPUS" 'the golden corpus is present'

# ---------------------------------------------------------------- per-vector
# One NDJSON record per vector, each carrying that vector's digest. This is the
# evidence that the corpus the suite exercised is the corpus in the tree.
ca_valid=0
ca_invalid=0
ca_total=0
while IFS= read -r golden; do
  [ -n "$golden" ] || continue
  ca_total=$((ca_total + 1))
  name=$(basename "$golden" .golden)
  kind=$(sed -n 's/^kind = //p' "$golden" | head -n 1)
  case "$kind" in
    valid) ca_valid=$((ca_valid + 1)) ;;
    invalid) ca_invalid=$((ca_invalid + 1)) ;;
    *)
      fge_fail "FG-002C-E2E-KIND-$name" "vector $name declares neither valid nor invalid"
      continue
      ;;
  esac
  fge_field vector "$name"
  fge_field vector_kind "$kind"
  fge_artifact "$golden" golden-vector
done < <(find "$CA_CORPUS" -name '*.golden' -type f | sort)

fge_step corpus-counted "corpus: $ca_total vectors, $ca_valid canonical, $ca_invalid planted defects"

fge_assert_ne FG-002C-E2E-002 0 "$ca_valid" 'the corpus has canonical vectors'
fge_assert_ne FG-002C-E2E-003 0 "$ca_invalid" 'the corpus has planted defects'

# A corpus of canonical vectors with no planted defects would pass every test
# while proving nothing about refusal, so require a real ratio rather than a
# token one.
if [ "$ca_invalid" -lt "$((ca_valid * 3))" ]; then
  fge_fail FG-002C-E2E-004 \
    "only $ca_invalid planted defects for $ca_valid canonical vectors; the corpus requires at least three per vector"
fi

fge_phase action

# ---------------------------------------------------------------- the codec
fge_run codec-goldens \
  cargo test --locked -p fgit-codec --test goldens
ca_goldens_exit=$FGE_LAST_EXIT

fge_run codec-mutation \
  cargo test --locked -p fgit-codec --test mutation
ca_mutation_exit=$FGE_LAST_EXIT

fge_run codec-roundtrip \
  cargo test --locked -p fgit-codec --test roundtrip
ca_roundtrip_exit=$FGE_LAST_EXIT

fge_run codec-refusals \
  cargo test --locked -p fgit-codec --test refusals
ca_refusals_exit=$FGE_LAST_EXIT

fge_run codec-bridge \
  cargo test --locked -p fgit-codec --test bridge
ca_bridge_exit=$FGE_LAST_EXIT

# ------------------------------------------------------- independent verifier
fge_run verifier-corpus \
  cargo test --locked -p fgit-codec-verify
ca_verifier_exit=$FGE_LAST_EXIT

# The verifier must not have grown a dependency on the crate it checks. That is
# the entire basis of its independence, so it is asserted rather than trusted.
#
# Asserted two ways, because the obvious way is vacuous. Extracting a
# `[dependencies]` section and searching it proves nothing while the crate has
# no such section — and it would miss a `[dependencies.fgit-codec]` table form
# even once it did. So: scan the WHOLE manifest for any `fgit-` mention other
# than the crate's own name, and separately check the resolved lockfile entry,
# which is the closed-world truth rather than a statement of intent.
ca_manifest="$CA_REPO/crates/fgit-codec-verify/Cargo.toml"
ca_foreign=$(grep -n 'fgit-' "$ca_manifest" | grep -v 'name = "fgit-codec-verify"' || true)

# The lockfile entry for a package with no dependencies has no `dependencies`
# key at all; one that acquired any would gain the key and the names.
#
# Pure bash on purpose. The harness keeps the evidence-validating path to bash
# plus coreutils plus one sha-256 helper, so a suite reaching for awk would
# reintroduce exactly the dependency the harness exists to avoid
# (FG-000A-PORT-019). A line-oriented TOML stanza scan is a while/case loop.
ca_lock_entry=''
ca_inside=0
while IFS= read -r ca_line; do
  if [ "$ca_inside" = 1 ] && [ "$ca_line" = '[[package]]' ]; then
    break
  fi
  if [ "$ca_line" = 'name = "fgit-codec-verify"' ]; then
    ca_inside=1
  fi
  if [ "$ca_inside" = 1 ]; then
    ca_lock_entry="$ca_lock_entry$ca_line"$'\n'
  fi
done < "$CA_REPO/Cargo.lock"

fge_phase assert

fge_assert_exit FG-002C-E2E-010 0 "$ca_goldens_exit" \
  'every committed vector round-trips byte for byte'
fge_assert_exit FG-002C-E2E-011 0 "$ca_mutation_exit" \
  'no mutant of any vector shares an identity with its canonical form'
fge_assert_exit FG-002C-E2E-012 0 "$ca_roundtrip_exit" \
  'canonical ordering and both round-trip directions hold'
fge_assert_exit FG-002C-E2E-013 0 "$ca_refusals_exit" \
  'bounded decoding refuses with the recorded typed reasons'
fge_assert_exit FG-002C-E2E-014 0 "$ca_bridge_exit" \
  'identities this codec produces are the ones fgit-crypto verifies'
fge_assert_exit FG-002C-E2E-015 0 "$ca_verifier_exit" \
  'an implementation sharing no code re-derives the same identities'

fge_assert_eq FG-002C-E2E-016 '' "$ca_foreign" \
  'the verifier manifest names no fgit-* crate other than itself'
fge_assert_not_contains FG-002C-E2E-017 "$ca_lock_entry" 'dependencies' \
  'the resolved lockfile entry for the verifier has no dependencies at all'
fge_assert_contains FG-002C-E2E-018 "$ca_lock_entry" 'fgit-codec-verify' \
  'the lockfile entry examined is actually the verifier'

fge_assert_cmd FG-002C-E2E-019 'the verifier crate forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$CA_REPO/crates/fgit-codec-verify/src/lib.rs"
