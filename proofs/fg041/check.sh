#!/usr/bin/env bash
# Fail-closed local checker for the verification-only FG-041 Lean lane.
set -euo pipefail

readonly toolchain='leanprover/lean4:v4.32.0'
readonly expected_version='Lean (version 4.32.0, x86_64-unknown-linux-gnu, commit 8c9756b28d64dab099da31a4c09229a9e6a2ef35, Release)'
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly proof_dir="${root}/proofs/fg041"

if (( $# > 1 )) || { (( $# == 1 )) && [[ $1 != --dpor ]]; }; then
  echo 'usage: bash proofs/fg041/check.sh [--dpor]' >&2
  exit 2
fi

if ! command -v elan >/dev/null 2>&1; then
  echo 'fg041 proof lane refusal: elan is unavailable; no alternate checker is accepted' >&2
  exit 2
fi

if ! elan toolchain list | rg -Fx -- "${toolchain}" >/dev/null; then
  echo "fg041 proof lane refusal: pinned toolchain ${toolchain} is not installed; refusing network installation" >&2
  exit 2
fi

actual_version="$(elan run "${toolchain}" lean --version)"
if [[ "${actual_version}" != "${expected_version}" ]]; then
  echo 'fg041 proof lane refusal: checker identity differs from toolchain.json' >&2
  printf 'expected: %s\nactual:   %s\n' "${expected_version}" "${actual_version}" >&2
  exit 2
fi

if rg -n -w '(sorry|admit)' "${proof_dir}/OrderedResidue.lean" >/dev/null; then
  echo 'fg041 proof lane refusal: proof artifact contains an admitted placeholder' >&2
  exit 2
fi

elan run "${toolchain}" lean "${proof_dir}/OrderedResidue.lean"

control_log="$(mktemp)"
trap 'rm -f -- "${control_log}"' EXIT
if elan run "${toolchain}" lean "${proof_dir}/FalseVariant.lean" >"${control_log}" 2>&1; then
  echo 'fg041 proof lane refusal: planted false theorem was accepted' >&2
  exit 2
fi
if ! rg -i 'tactic.*rfl.*failed' "${control_log}" >/dev/null; then
  echo 'fg041 proof lane refusal: planted control failed for an unexpected reason' >&2
  sed -n '1,120p' "${control_log}" >&2
  exit 2
fi

printf 'FG-041 Lean proof lane checked with %s\n' "${toolchain}"

if (( $# == 0 )); then
  exit 0
fi

if [[ $(cat "$proof_dir/lean-toolchain") != "$toolchain" ]]; then
  echo 'fg041 proof lane refusal: DPOR toolchain differs from the pinned model checker' >&2
  exit 2
fi
bridge=''
if [[ -n ${FGIT_PROOF_BRIDGE_BIN:-} ]]; then
  if [[ ! -f $FGIT_PROOF_BRIDGE_BIN || ! -x $FGIT_PROOF_BRIDGE_BIN ]]; then
    echo 'fg041 proof lane refusal: specified DPOR bridge is not executable' >&2
    exit 2
  fi
  bridge=$(realpath -- "$FGIT_PROOF_BRIDGE_BIN")
fi

# The replay owns its generated modules. The model's false-control log has
# a separate EXIT trap in the parent.
(
  dpor_dir=$(mktemp -d)
  trap 'rm -f -- "$dpor_dir"/{OrderedResidue,Vectors}.{lean,olean} "$dpor_dir"/{Refinement,DporRace}.lean; rmdir -- "$dpor_dir"' EXIT
  cp "$proof_dir"/{OrderedResidue,Refinement,DporRace}.lean "$dpor_dir/"
  cd "$dpor_dir"
  if rg -n -w '(sorry|admit)' Refinement.lean DporRace.lean; then
    echo 'fg041 proof lane refusal: refinement contains an admitted placeholder' >&2
    exit 2
  fi
  set -C
  if [[ -n $bridge ]]; then
    "$bridge" dpor "$root/crates/fgit-reference/tests/goldens/cas_loss_retry.fgtrace" >Vectors.lean
  else
    (cd "$root" && cargo run --locked --quiet -p fgit-proof-bridge --bin fgit-proof-bridge-gen -- dpor) >Vectors.lean
  fi
  export LEAN_PATH=.
  elan run "$toolchain" lean -o OrderedResidue.olean OrderedResidue.lean
  elan run "$toolchain" lean -o Vectors.olean Vectors.lean
  elan run "$toolchain" lean Refinement.lean
  elan run "$toolchain" lean DporRace.lean
  printf 'FG-041 replayed both competing head publications with %s\n' "$toolchain"
)
