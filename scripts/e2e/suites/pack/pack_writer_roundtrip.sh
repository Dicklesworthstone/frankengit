#!/usr/bin/env bash
# FG-017b: pack-writer client-acceptance lane.
#
# The question this suite answers is the one no in-process test can: does REAL
# upstream Git accept the packs our writer produces? Everything else about the
# writer — determinism, receipts, round-tripping through our own reader — is
# evidence about FrankenGit agreeing with FrankenGit. Two components sharing one
# wrong assumption agree with each other and are both wrong. Only a foreign
# consumer settles it.
#
# Shape, and why it is this shape:
#
#   * The Rust side NEVER invokes Git. `cargo test -p fgit-pack --test
#     writer_roundtrip -- --ignored` is a pure producer: it writes packs and an
#     NDJSON manifest into an artifact directory. AGENTS.md 3.1 permits upstream
#     Git only as a pinned, sandboxed oracle outside production, so the process
#     boundary lives here in the suite, exactly as pack_differential.sh
#     establishes for the reader direction.
#   * Every Git invocation goes through scripts/e2e/oracle/oracle.sh, which
#     refuses anything that is not a checked-in pin executed under Bubblewrap.
#
# Before this lane existed, the claim "PackWriter passes real git index-pack
# --strict" lived only in fg017a's close reason, sourced to a one-off audit run,
# with nothing committed that would catch a regression. This makes it standing,
# replayable evidence instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOSITORY_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd -P)"
# shellcheck source=../../lib.sh
. "$REPOSITORY_ROOT/scripts/e2e/lib.sh"

readonly TEST_NAME='pack_writer_roundtrip'
readonly ORACLE="${REPOSITORY_ROOT}/scripts/e2e/oracle/oracle.sh"
readonly PIN_ID='git-2.54.0'

# The corpora the producer emits, in the order it emits them. Kept explicit
# rather than globbed so a corpus that silently stops being produced fails this
# lane instead of shrinking it.
readonly CORPORA=(single_blob one_commit history wide)

main() {
  local artifacts='' producer_exit=0 manifest='' corpus='' run_directory=''
  local pack_path='' index_exit=0 accepted=0 attempted=0

  fge_phase setup
  artifacts="$(fge_artifact_path pack-writer-corpus)"
  mkdir -p "${artifacts}"

  # The producer is captured rather than run through fge_run_ok: fge_run_ok
  # calls fge_die on failure, which would exit before a single assertion below
  # had run and would discard the evidence of WHICH corpus failed.
  fge_phase action
  fge_capture produce \
    env "FGIT_PACK_WRITER_ARTIFACT_DIR=${artifacts}" \
    RCH_CARGO_WRAPPER_BYPASS=1 \
    cargo test -p fgit-pack --test writer_roundtrip -- --ignored --nocapture \
    || producer_exit=$?
  producer_exit=${producer_exit:-0}

  fge_phase assert
  fge_assert_exit 'FG-017B-E2E-001' 0 "${producer_exit}" \
    'the pack producer completes'
  fge_assert_file 'FG-017B-E2E-002' "${artifacts}/manifest.ndjson" \
    'the producer emits a corpus manifest'

  if [[ ! -f "${artifacts}/manifest.ndjson" ]]; then
    # Without a manifest there is nothing to hand the oracle. Fail loudly here
    # rather than reporting a vacuous pass over zero corpora.
    fge_fail 'FG-017B-E2E-003' 'no manifest; the oracle lane cannot run'
    return 0
  fi

  manifest="$(<"${artifacts}/manifest.ndjson")"
  fge_assert_ndjson 'FG-017B-E2E-003' "${artifacts}/manifest.ndjson" \
    'the corpus manifest is parseable NDJSON'

  # Every declared corpus must actually be present. A lane that silently
  # narrowed to one tiny pack would satisfy "100% accepted" while proving far
  # less than it appears to.
  for corpus in "${CORPORA[@]}"; do
    fge_assert_contains "FG-017B-E2E-010-${corpus}" "${manifest}" "\"corpus\":\"${corpus}\"" \
      "the manifest declares the ${corpus} corpus"
    fge_assert_file "FG-017B-E2E-011-${corpus}" "${artifacts}/${corpus}.pack" \
      "the ${corpus} pack was emitted"
  done

  # The acceptance obligation itself: real Git, pinned and sandboxed, must
  # index every pack under --strict. --strict is the point; plain index-pack
  # would accept packs whose object CONTENT is malformed, which is exactly the
  # disagreement class this lane exists to detect.
  fge_phase action
  for corpus in "${CORPORA[@]}"; do
    pack_path="${artifacts}/${corpus}.pack"
    [[ -f "${pack_path}" ]] || continue
    attempted=$((attempted + 1))

    run_directory="$("${ORACLE}" create-run "${PIN_ID}" "writer-${corpus}")"
    mkdir -p "${run_directory}/work/pack"
    cp "${pack_path}" "${run_directory}/work/pack/${corpus}.pack"

    # Wrapped in fge_capture so the receipt publishes the EXACT argv, its
    # digest, and its exit code. Calling the oracle bare would leave the one
    # command the acceptance claim rests on invisible in the evidence, which is
    # how a claim ends up inherited rather than demonstrated.
    index_exit=0
    fge_capture "index-${corpus}" \
      "${ORACLE}" capture "${PIN_ID}" "${run_directory}" pack "index-${corpus}" -- \
      index-pack --strict "${corpus}.pack" || index_exit=$?

    fge_phase assert
    fge_assert_exit "FG-017B-E2E-020-${corpus}" 0 "${index_exit}" \
      "pinned ${PIN_ID} accepts the ${corpus} pack under index-pack --strict"
    if [[ "${index_exit}" -eq 0 ]]; then
      accepted=$((accepted + 1))
    fi

    # index-pack writes the index next to the pack only when it accepted it, so
    # the .idx is independent corroboration that acceptance was real rather
    # than a zero exit from a no-op.
    fge_assert_file "FG-017B-E2E-021-${corpus}" \
      "${run_directory}/work/pack/${corpus}.idx" \
      "pinned ${PIN_ID} produced an index for the ${corpus} pack"
    fge_phase action
  done

  # NEGATIVE CONTROL. Everything above asserts that the pinned client accepts
  # our packs. That is worth nothing unless the same client would REJECT a pack
  # it should reject: a wrong pin, a sandbox that silently no-ops, or an
  # invocation that never reached Git would make every acceptance assertion
  # above pass while proving nothing. So one pack is deliberately corrupted and
  # offered on the same path, and the lane fails if it is accepted.
  fge_phase action
  local corrupt_source="${artifacts}/history.pack"
  local corrupt_exit=0
  if [[ -f "${corrupt_source}" ]]; then
    run_directory="$("${ORACLE}" create-run "${PIN_ID}" 'writer-negative-control')"
    mkdir -p "${run_directory}/work/pack"
    # Flip every bit of one byte in the middle of the pack body. The trailer
    # checksum no longer matches and the entry stream is damaged, so a client
    # performing real validation must refuse.
    perl -e '
      my ($src, $dst) = @ARGV;
      open my $in, "<:raw", $src or die $!;
      local $/; my $bytes = <$in>; close $in;
      my $mid = int(length($bytes) / 2);
      substr($bytes, $mid, 1) = chr(ord(substr($bytes, $mid, 1)) ^ 0xFF);
      open my $out, ">:raw", $dst or die $!;
      print $out $bytes; close $out;
    ' "${corrupt_source}" "${run_directory}/work/pack/corrupt.pack"

    fge_capture 'index-negative-control' \
      "${ORACLE}" run "${PIN_ID}" "${run_directory}" pack -- \
      index-pack --strict corrupt.pack || corrupt_exit=$?

    fge_phase assert
    fge_assert_ne 'FG-017B-E2E-040' 0 "${corrupt_exit}" \
      'the pinned client REJECTS a corrupted pack, so acceptance above is discriminating'
    fge_assert_no_file 'FG-017B-E2E-041' \
      "${run_directory}/work/pack/corrupt.idx" \
      'a rejected pack leaves no index behind'
  else
    fge_fail 'FG-017B-E2E-040' 'no pack available to corrupt; the negative control could not run'
  fi

  fge_phase assert
  # 100% acceptance, stated as a count rather than as prose, and refusing the
  # degenerate case where nothing was attempted.
  fge_assert_ne 'FG-017B-E2E-030' 0 "${attempted}" \
    'at least one pack was offered to the pinned client'
  fge_assert_eq 'FG-017B-E2E-031' "${attempted}" "${accepted}" \
    'every offered pack was accepted by the pinned client'
  fge_assert_eq 'FG-017B-E2E-032' "${#CORPORA[@]}" "${attempted}" \
    'every declared corpus was offered, so the lane did not silently narrow'

  fge_artifact "${artifacts}/manifest.ndjson" pack-writer-manifest
}

fge_init fg017b-pack-writer-roundtrip
fge_context bead frankengit-fg017b-pack-writer-evidence-evd
fge_context evidence_class differential
fge_context method 'FrankenGit PackWriter emits packs; pinned upstream Git indexes them under index-pack --strict inside the Bubblewrap oracle sandbox'
fge_context oracle_pin "${PIN_ID}"
fge_context claim_scope 'client acceptance is evidenced for exactly the pins offered here; with one pin installed this is single-version evidence and must not be read as cross-version compatibility'
fge_context non_claim 'this lane says nothing about pack SIZE or SPEED relative to upstream git pack-objects; that is the separate benchmark artifact, and the frozen STORED_V1 profile uses stored DEFLATE blocks by design'
fge_context non_claim_reader 'our own reader round-trip lives in cargo test -p fgit-pack --test writer_roundtrip and is evidence of FrankenGit agreeing with FrankenGit; only this lane involves a foreign consumer'
fge_context client_command 'git index-pack --strict <corpus>.pack, executed by scripts/e2e/oracle/oracle.sh inside the Bubblewrap sandbox; every invocation is captured with its exact argv, digest and exit code in this run receipt rather than described in prose'
fge_context inherits_nothing 'this lane demonstrates client acceptance from its own captured commands; it does not inherit or restate the audit1 observation recorded in fg017a close reason'
fge_context discrimination 'a corrupted pack is offered on the same path as a negative control; if the pinned client accepted it, every acceptance assertion here would be meaningless and the lane fails'
main
