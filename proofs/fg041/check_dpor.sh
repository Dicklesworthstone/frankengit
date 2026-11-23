#!/usr/bin/env bash
# Replay the scheduled reference histories in fresh Lean modules.
set -euo pipefail
readonly proof_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly root="$(cd "$proof_dir/../.." && pwd)"
bash "$proof_dir/check.sh"
readonly toolchain="$(cat "$proof_dir/lean-toolchain")"
dpor_dir=$(mktemp -d)
trap 'rm -f -- "$dpor_dir"/{OrderedResidue,Vectors}.{lean,olean} "$dpor_dir/Refinement.lean"; rmdir -- "$dpor_dir"' EXIT
cp "$proof_dir/OrderedResidue.lean" "$proof_dir/Refinement.lean" "$dpor_dir/"
cd "$dpor_dir"
if rg -n -w '(sorry|admit)' Refinement.lean; then
  echo 'fg041 proof lane refusal: refinement contains an admitted placeholder' >&2
  exit 2
fi
set -C
if [[ -n ${FGIT_PROOF_BRIDGE_BIN:-} ]]; then
  "$FGIT_PROOF_BRIDGE_BIN" dpor "$root/crates/fgit-reference/tests/goldens/cas_loss_retry.fgtrace" >Vectors.lean
else
  (cd "$root" && cargo run --locked --quiet -p fgit-proof-bridge --bin fgit-proof-bridge-gen -- dpor) >Vectors.lean
fi
export LEAN_PATH=.
elan run "$toolchain" lean -o OrderedResidue.olean OrderedResidue.lean
elan run "$toolchain" lean -o Vectors.olean Vectors.lean
elan run "$toolchain" lean Refinement.lean
printf 'FG-041 replayed both competing head publications with %s\n' "$toolchain"
