#!/usr/bin/env bash
# Fail-closed local checker for the verification-only FG-041 Lean lane.
set -euo pipefail

readonly toolchain='leanprover/lean4:v4.32.0'
readonly expected_version='Lean (version 4.32.0, x86_64-unknown-linux-gnu, commit 8c9756b28d64dab099da31a4c09229a9e6a2ef35, Release)'
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
readonly root
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

if [[ $(cat "$proof_dir/lean-toolchain") != "$toolchain" ]]; then
  echo 'fg041 proof lane refusal: replay toolchain differs from the pinned model checker' >&2
  exit 2
fi

if [[ -n ${FGIT_PROOF_BRIDGE_BIN:-} ]]; then
  if [[ ! -f $FGIT_PROOF_BRIDGE_BIN || ! -x $FGIT_PROOF_BRIDGE_BIN ]]; then
    echo 'fg041 proof lane refusal: specified proof bridge is not executable' >&2
    exit 2
  fi
  bridge=$(realpath -- "$FGIT_PROOF_BRIDGE_BIN")
else
  # The verifier inspects caller-local golden files and a private Lean directory.
  cd "$root"
  # shellcheck source=../../scripts/verify_native_tools.sh
  source "$root/scripts/verify_native_tools.sh"
  bridge=$(verified_tool_path fgit-proof-bridge fgit-proof-bridge-gen)
fi

work=$(mktemp -d)
trap 'rm -f -- "$work"/{OrderedResidue,Vectors}.{lean,olean} "$work"/{Refinement,DporRace,FalseVariant}.lean "$work/control.log"; rmdir -- "$work"' EXIT
cp "$proof_dir"/{OrderedResidue,Refinement,FalseVariant}.lean "$work/"
cp "$proof_dir/generated/Vectors.lean" "$work/"
cd "$work"
export LEAN_PATH=.
sources=(OrderedResidue.lean Refinement.lean Vectors.lean)
if (( $# )); then
  cp "$proof_dir/DporRace.lean" .
  sources+=(DporRace.lean)
fi
if rg -n -w '(sorry|admit)' "${sources[@]}"; then
  echo 'fg041 proof lane refusal: proof artifact contains an admitted placeholder' >&2
  exit 2
fi

lean=(elan run "$toolchain" lean)
"${lean[@]}" -o OrderedResidue.olean OrderedResidue.lean
if "${lean[@]}" FalseVariant.lean >control.log 2>&1; then
  echo 'fg041 proof lane refusal: planted false theorem was accepted' >&2
  exit 2
fi
if ! rg -i 'tactic.*rfl.*failed' control.log >/dev/null; then
  echo 'fg041 proof lane refusal: planted control failed for an unexpected reason' >&2
  cat control.log >&2
  exit 2
fi

# Check the exact private copy the kernel imports, including fresh execution
# of every source history. The generator's check command never repairs drift.
goldens="$root/crates/fgit-reference/tests/goldens"
"$bridge" check "$goldens" "$work"
check_vectors() {
  "${lean[@]}" -o Vectors.olean Vectors.lean
  "${lean[@]}" Refinement.lean
}
check_vectors
printf 'FG-041 replayed the recorded reference histories with %s\n' "$toolchain"

if (( $# )); then
  "$bridge" dpor "$goldens/cas_loss_retry.fgtrace" >Vectors.lean
  if rg -n -w '(sorry|admit)' Vectors.lean; then
    echo 'fg041 proof lane refusal: scheduled vectors contain an admitted placeholder' >&2
    exit 2
  fi
  check_vectors
  "${lean[@]}" DporRace.lean
  printf 'FG-041 replayed both competing head publications with %s\n' "$toolchain"
fi
