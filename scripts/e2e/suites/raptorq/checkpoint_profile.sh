#!/usr/bin/env bash
# e2e: proves checkpoint_segment_v1 protects both registered checkpoint classes
# and that DUR-014 acceptance is gated on AEAD rather than on digest agreement.
#
# PATH DEVIATION, DELIBERATE. FG-077a's acceptance names
# `scripts/e2e/raptorq_microsegment_checkpoint.sh` and says it is "registered in
# run_all.sh". Neither is possible as written: run_all.sh:36 states that
# anything outside `suites/` "IS NOT DISCOVERED AND RUNS NOWHERE", and the
# runner deliberately has no registration interface at all (see its SEAM FOR
# FG-091 note -- a manifest is FG-091's, and an allowlist generated from
# discovery is a documented false-green mechanism). A script at the named path
# would never execute while still reading as coverage on the bead; that exact
# failure already exists once in this tree and is filed as frankengit-osqi.
# This file therefore lives where discovery finds it. Reported on the bead.
#
# Companion to raptorq_drill.sh, which owns the DUR-016 microsegment adversary.
# This suite does not restate those drills; it covers the two classes that had
# no coding profile before FG-077a.
set -euo pipefail

CP_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CP_REPO=$(cd "$CP_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CP_REPO/scripts/e2e/lib.sh"

CP_SRC="$CP_REPO/crates/fgit-raptorq/src/checkpoint.rs"
CP_VECTORS="$CP_REPO/crates/fgit-raptorq/goldens/checkpoint_vectors.tsv"
CP_ORACLE="$CP_REPO/crates/fgit-raptorq/goldens/checkpoint_identity.py"

fge_init fg077a-checkpoint-profile
fge_context bead frankengit-fg077a-raptorq-microsegment-checkpoint-ko1i
fge_context profile checkpoint_segment_v1
fge_context durable_classes 'DUR-012 forge_event_checkpoint_segment; DUR-014 policy_key_format_checkpoint'
fge_context harness_seed "$(fge_seed)"
fge_context sampling none

fge_phase setup

fge_assert_file FG-077A-E2E-001 "$CP_SRC" \
  'the checkpoint_segment_v1 profile is checked in'
fge_assert_file FG-077A-E2E-002 "$CP_VECTORS" \
  'independently derived checkpoint identity vectors are checked in'
fge_assert_file FG-077A-E2E-003 "$CP_ORACLE" \
  'the independent hashlib checkpoint-identity derivation is checked in'

fge_phase action

fge_run checkpoint-profile-tests \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-raptorq --lib checkpoint || true
cp_tests_exit=$FGE_LAST_EXIT

# The DUR-016 microsegment profile shares this crate's symbol pool and decode
# budget. Extending the crate must not regress it.
fge_run raptorq-lib-regression \
  env RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test --locked -p fgit-raptorq --lib || true
cp_lib_exit=$FGE_LAST_EXIT

fge_phase assert

fge_assert_exit FG-077A-E2E-010 0 "$cp_tests_exit" \
  'both checkpoint classes round-trip and every malicious corpus entry is refused'
fge_assert_exit FG-077A-E2E-011 0 "$cp_lib_exit" \
  'adding the checkpoint profile did not regress the microsegment profile'

# --- structural pins -------------------------------------------------------
# The assertions above go green if the tests pass. These pin the SHAPE of the
# gate, because the cheapest way to make an AEAD test pass is to stop requiring
# AEAD, and a suite that only checks exit codes would not notice.

# The gate must be symmetric. Requiring a verifier for DUR-014 while silently
# accepting one for DUR-012 lets a caller believe plaintext was authenticated.
cp_required=$(grep -c 'AeadVerifierRequired' "$CP_SRC" || true)
cp_not_permitted=$(grep -c 'AeadVerifierNotPermitted' "$CP_SRC" || true)
fge_assert_cmd FG-077A-E2E-012 \
  'the AEAD gate refuses a missing verifier' \
  test "$cp_required" -ge 1
fge_assert_cmd FG-077A-E2E-013 \
  'the AEAD gate is symmetric and also refuses an unexpected verifier' \
  test "$cp_not_permitted" -ge 1
fge_note 'aead gate references' "required=$cp_required not_permitted=$cp_not_permitted"

# Acceptance must not be reachable on digest agreement alone. This is the
# property the whole class distinction exists for.
fge_assert_cmd FG-077A-E2E-014 \
  'a decoded candidate whose digest matches is still refused without AEAD' \
  grep -q 'a_matching_digest_does_not_authenticate' "$CP_SRC"

# Domain separation must be by registered identity domain, not by a positional
# tag a caller could supply. Both registry domains must be named in the source.
fge_assert_cmd FG-077A-E2E-015 \
  'DUR-012 binds the registered ForgeCheckpoint identity domain' \
  grep -q 'IdentityDomain::ForgeCheckpoint' "$CP_SRC"
fge_assert_cmd FG-077A-E2E-016 \
  'DUR-014 binds the registered PolicyCheckpoint identity domain' \
  grep -q 'IdentityDomain::PolicyCheckpoint' "$CP_SRC"

# The malicious corpus must assert its own denominator. "Zero acceptances" over
# a silently empty corpus is the failure this pins against, and it is the same
# shape as the counted-schedule-space discipline in NEG-021.
fge_assert_cmd FG-077A-E2E-017 \
  'the malicious-symbol corpus asserts a counted denominator, so an empty corpus cannot pass' \
  grep -q 'the corpus denominator is asserted' "$CP_SRC"

# Every refusal must be paired with a near-identical permitted case, or a rule
# that refuses everything would satisfy all of the above.
cp_twins=$(grep -c 'Permitted twin\|permitted twin\|must still reconstruct\|must be accepted when' "$CP_SRC" || true)
fge_assert_cmd FG-077A-E2E-018 \
  'refusals are paired with permitted twins rather than standing alone' \
  test "$cp_twins" -ge 3
fge_note 'permitted twins' "$cp_twins"

# The registry rows this profile claims must exist and name this profile.
fge_assert_cmd FG-077A-E2E-019 \
  'DUR-012 names checkpoint_segment_v1 in the durable-object registry' \
  grep -qE '^DUR-012\s.*checkpoint_segment_v1' "$CP_REPO/registries/durable_objects.tsv"
fge_assert_cmd FG-077A-E2E-020 \
  'DUR-014 names checkpoint_segment_v1 in the durable-object registry' \
  grep -qE '^DUR-014\s.*checkpoint_segment_v1' "$CP_REPO/registries/durable_objects.tsv"
