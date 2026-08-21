#!/usr/bin/env bash
# e2e: the key lifecycle drills, run end to end.
#
# The bead asks for three drills, and they are only meaningful together:
#
#   1. rotation — data written under an old key stays readable through the key
#      history, while new writes use the new key;
#   2. revocation — issuance stops, the transition is receipted, and nothing
#      silently falls back to a retired epoch;
#   3. cryptographic erasure — the material is destroyed and dependent data is
#      permanently unrecoverable as a TYPED state, never as "unknown key".
#
# The third is the one worth running end to end rather than trusting. An
# erasure that reports "unknown" invites a caller to retry, resynchronise, or
# treat the data as corrupt, and every one of those is a way for deleted data
# to be quietly resurrected or a deletion obligation to be quietly dropped.
# This suite asserts the refusal is the erased one specifically.
#
# It also pins the two facts that make the primitives trustworthy at all: the
# published RFC vectors pass, and the key-purpose separation holds at both the
# type level and the serialized level.
set -euo pipefail

KL_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
KL_REPO=$(cd "$KL_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$KL_REPO/scripts/e2e/lib.sh"

fge_init fg057-key-lifecycle
fge_context bead frankengit-fg057-crypto-keys-q04
fge_context crate fgit-crypto
fge_context harness_seed "$(fge_seed)"

# The key tests are exhaustive or vector-driven rather than sampled: the RFC
# cases are fixed, the single-bit forgery test walks all 256 bits of a tag, and
# the purpose matrix walks all eight purposes. Nothing here samples, so there
# is no property seed to record.
fge_context sampling none

readonly KL_GOLDENS="$KL_REPO/crates/fgit-crypto/goldens"

fge_phase setup

fge_assert_dir FG-057-E2E-001 "$KL_GOLDENS" 'the crypto golden corpus is present'
fge_assert_file FG-057-E2E-002 "$KL_GOLDENS/mac_vectors.tsv" \
  'the RFC 4231 MAC vectors are checked in'
fge_assert_file FG-057-E2E-003 "$KL_GOLDENS/derive_vectors.tsv" \
  'the RFC 5869 derivation vectors are checked in'

# The vectors are only evidence if they came from somewhere other than the code
# they check. The derivation script is checked in beside them for that reason.
fge_assert_file FG-057-E2E-004 "$KL_GOLDENS/derive.py" \
  'the independent oracle that produced the vectors is checked in'
fge_assert_file FG-057-E2E-005 "$KL_GOLDENS/seal_vectors.tsv" \
  'the envelope-sealing vectors are checked in'
fge_assert_file FG-057-E2E-006 "$KL_GOLDENS/seal.py" \
  'the independent oracle that produced the sealing vectors is checked in'

fge_phase action

fge_run crypto-keyed-vectors \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-crypto --test keyed_vectors
kl_vectors_exit=$FGE_LAST_EXIT

fge_run crypto-key-purposes \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-crypto --test key_purposes
kl_purposes_exit=$FGE_LAST_EXIT

fge_run crypto-key-lifecycle \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-crypto --test key_lifecycle
kl_lifecycle_exit=$FGE_LAST_EXIT

fge_run crypto-signing \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-crypto --test signing
kl_signing_exit=$FGE_LAST_EXIT

fge_run crypto-sealing \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-crypto --test sealing
kl_sealing_exit=$FGE_LAST_EXIT

# The compile-time half of the purpose separation lives in compile_fail
# doctests, which only a doc-test run executes. Skipping it here would leave
# "cross-purpose use is unrepresentable" untested by this suite.
fge_run crypto-doctests \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-crypto --doc
kl_doctests_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-057-E2E-010 0 "$kl_vectors_exit" \
  'the published RFC 4231 and RFC 5869 vectors reproduce'
fge_assert_exit FG-057-E2E-011 0 "$kl_purposes_exit" \
  'key purposes separate at the type level and for serialized material'
fge_assert_exit FG-057-E2E-012 0 "$kl_lifecycle_exit" \
  'rotation, revocation and erasure behave as the drills require'
fge_assert_exit FG-057-E2E-013 0 "$kl_doctests_exit" \
  'every compile_fail boundary is rejected and its permitted twin compiles'
fge_assert_exit FG-057-E2E-018 0 "$kl_signing_exit" \
  'detached Ed25519 envelopes refuse cross-domain, relabelled and forged input'
fge_assert_exit FG-057-E2E-019 0 "$kl_sealing_exit" \
  'sealed envelopes reproduce the independent oracle and refuse misplacement'

# The eight purposes come from the threat model, not from this crate. If the
# enumeration drifts from the document, the separation is protecting a
# different set than the one that was reasoned about.
kl_purpose_rows=$(grep -c 'frankengit/key/' "$KL_REPO/crates/fgit-crypto/src/keys.rs" || true)
fge_assert_cmd FG-057-E2E-014 'the threat model still enumerates eight key purposes' \
  grep -qF 'identity, authority/admin, capsule, evidence, package/release, webhook, tenant encryption, and recovery' \
  "$KL_REPO/SECURITY_THREAT_MODEL.md"
fge_note 'purpose tag occurrences in keys.rs' "$kl_purpose_rows"

# Erasure has to be a state with evidence, which means a registry row for the
# receipt body rather than a log line.
fge_assert_cmd FG-057-E2E-015 'the key-lifecycle receipt has an identity-domain row' \
  grep -qF 'frankengit/key-lifecycle-receipt/v1' \
  "$KL_REPO/crates/fgit-crypto/goldens/domain_registry.tsv"

# This suite used to assert that fgit-crypto depends only on first-party
# fgit-* crates. ADR-0003 ended that: the crate now reuses Ed25519 and
# XChaCha20-Poly1305. The old assertion would still have PASSED -- it grepped
# for a line that is still there -- while its description claimed something no
# longer true, which is the worst shape a check can take.
#
# What replaces it is the check the ADR's Amendment 1 records as missing at the
# registry-check level: every external dependency this crate names must hold an
# active row that authorises DIRECT first-party use, not merely a transitive
# admission. Scoped to this crate because tools/registry-check is not mine.
kl_policy="$KL_REPO/registries/dependency_policy.tsv"
kl_external=$(sed -n '/^\[dependencies\]/,/^\[/p' "$KL_REPO/crates/fgit-crypto/Cargo.toml" \
  | grep -oE '^[a-z0-9-]+\.workspace = true$' \
  | sed 's/\.workspace = true//' \
  | grep -v '^fgit-' || true)
fge_note 'external dependencies declared by fgit-crypto' "$(echo "$kl_external" | tr '\n' ' ')"

kl_unadmitted=""
for kl_dep in $kl_external; do
  if ! awk -F'\t' -v dep="$kl_dep" \
      '$2 == dep && $4 == "allow_direct_first_party" && $10 == "active" { found = 1 }
       END { exit !found }' "$kl_policy"; then
    kl_unadmitted="$kl_unadmitted $kl_dep"
  fi
done
fge_assert_cmd FG-057-E2E-016 \
  'every external fgit-crypto dependency holds an active direct-admission row' \
  test -z "$kl_unadmitted"

# The two the ADR selected, named explicitly, so silently dropping one from the
# manifest cannot make the loop above vacuously pass.
fge_assert_cmd FG-057-E2E-020 'Ed25519 is the admitted signature primitive' \
  grep -qE '^ed25519-dalek\.workspace = true$' \
  "$KL_REPO/crates/fgit-crypto/Cargo.toml"
fge_assert_cmd FG-057-E2E-021 'XChaCha20-Poly1305 is the admitted AEAD primitive' \
  grep -qE '^chacha20poly1305\.workspace = true$' \
  "$KL_REPO/crates/fgit-crypto/Cargo.toml"

# The ADR is the reason those rows exist. If it ever reverts to proposed, the
# direct admissions above are unauthorised.
fge_assert_cmd FG-057-E2E-022 'ADR-0003 is accepted' \
  grep -qE '^- \*\*Status:\*\* \*\*accepted\*\*' \
  "$KL_REPO/docs/ADR-0003-CRYPTOGRAPHY-AND-KEY-POLICY.md"
fge_assert_cmd FG-057-E2E-017 'fgit-crypto forbids unsafe code' \
  grep -qF '#![forbid(unsafe_code)]' "$KL_REPO/crates/fgit-crypto/src/lib.rs"

