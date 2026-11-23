#!/usr/bin/env bash
# Fail-closed local checker for the verification-only FG-041 Lean lane.
set -euo pipefail

readonly toolchain='leanprover/lean4:v4.32.0'
readonly expected_version='Lean (version 4.32.0, x86_64-unknown-linux-gnu, commit 8c9756b28d64dab099da31a4c09229a9e6a2ef35, Release)'
readonly root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
readonly proof_dir="${root}/proofs/fg041"

if [[ $# -gt 1 || ( $# -eq 1 && "$1" != --dpor ) ]]; then
  echo 'usage: proofs/fg041/check.sh [--dpor]' >&2
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

if [[ ${1:-} == --dpor ]]; then
  # Build fresh modules outside the checkout so imports cannot select a
  # precompiled vector module from an earlier campaign.
  dpor_dir=$(mktemp -d)
  trap 'rm -f -- "$control_log" "$dpor_dir"/{OrderedResidue,Vectors}.{lean,olean} "$dpor_dir/Refinement.lean"; rmdir -- "$dpor_dir"' EXIT
  cp "$proof_dir/OrderedResidue.lean" "$proof_dir/Refinement.lean" "$dpor_dir/"
  if rg -n -w '(sorry|admit)' "$dpor_dir/Refinement.lean"; then
    echo 'fg041 proof lane refusal: refinement contains an admitted placeholder' >&2
    exit 2
  fi
  (cd "$root" && cargo run --locked --quiet -p fgit-proof-bridge --bin fgit-proof-bridge-gen -- dpor) >"$dpor_dir/Vectors.lean"
  (
    cd "$dpor_dir"
    export LEAN_PATH=.
    elan run "$toolchain" lean -o OrderedResidue.olean OrderedResidue.lean
    elan run "$toolchain" lean -o Vectors.olean Vectors.lean
    elan run "$toolchain" lean Refinement.lean
  )
  printf 'FG-041 replayed both competing head publications with %s\n' "$toolchain"
fi
