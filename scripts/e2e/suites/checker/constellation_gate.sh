#!/usr/bin/env bash
# e2e: proves the constellation gate accepts the exact admitted runtime closure
# and rejects each independently planted version-universe/admission violation.
set -euo pipefail

CG_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CG_REPO=$(cd "$CG_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CG_REPO/scripts/e2e/lib.sh"

fge_init fg001b-constellation-gate
fge_context bead frankengit-fg001b-checker-version-universe-hcs
fge_context checker fgit-registry-check
fge_phase setup

CG_WORK=$(fge_tempdir constellation-gate)

cg_fixture() {
  local name=$1
  local root="$CG_WORK/$name"
  mkdir -p "$root/tools"
  cp "$CG_REPO/Cargo.lock" "$root/Cargo.lock"
  cp "$CG_REPO/constellation.lock" "$root/constellation.lock"
  cp "$CG_REPO/LICENSE" "$root/LICENSE"
  # `cargo metadata --locked` is part of admission. Its fixture must therefore
  # retain the exact workspace membership represented by Cargo.lock; reducing
  # it to fgit-runtime lets Cargo legitimately request a lock rewrite before
  # the constellation checks can run.
  cp "$CG_REPO/Cargo.toml" "$root/Cargo.toml"
  cp -a "$CG_REPO/crates" "$root/crates"
  cp -a "$CG_REPO/tools/registry-check" "$root/tools/registry-check"
  printf '%s' "$root"
}

cg_replace_first() {
  local path=$1 before=$2 after=$3 content
  content=$(<"$path")
  [[ $content == *"$before"* ]] || return 1
  printf '%s' "${content/"$before"/"$after"}" >"$path"
}

cg_corrupt_transitive_unsafe_digest() {
  local path=$1 package=$2 replacement=$3 tmp changed=0 line
  tmp=$(mktemp "${path}.XXXXXX")
  while IFS= read -r line || [[ -n $line ]]; do
    if [[ $line != \#* && $line != package$'\t'* && $line != state$'\t'* ]]; then
      local -a fields
      IFS=$'\t' read -r -a fields <<<"$line"
      if [[ ${fields[0]:-} == "$package" ]]; then
        [[ ${#fields[@]} -eq 15 ]] || {
          rm -f "$tmp"
          return 1
        }
        fields[12]=$replacement
        (IFS=$'\t'; printf '%s\n' "${fields[*]}") >>"$tmp"
        changed=1
        continue
      fi
    fi
    printf '%s\n' "$line" >>"$tmp"
  done <"$path"
  [[ $changed -eq 1 ]] || {
    rm -f "$tmp"
    return 1
  }
  mv "$tmp" "$path"
}

cg_gate() {
  local fixture=$1 case_name=$2 expected=$3
  fge_field fixture "$case_name"
  fge_field expected_diagnostic "$expected"
  fge_field cargo_lock_digest "$(fge_digest_file "$fixture/Cargo.lock")"
  fge_field constellation_digest "$(fge_digest_file "$fixture/constellation.lock")"
  fge_capture "constellation-$case_name" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$CG_REPO/tools/registry-check/Cargo.toml" \
    -- constellation --root "$fixture" || true
  CG_GATE_EXIT=$FGE_LAST_EXIT
  CG_GATE_DIAGNOSTIC="$FGE_LAST_STDERR"$'\n'"$FGE_LAST_STDOUT"
}

fge_phase action
positive=$(cg_fixture positive)
cg_gate "$positive" positive 'FrankenGit constitutional verification passed'
positive_exit=$CG_GATE_EXIT
positive_diagnostic=$CG_GATE_DIAGNOSTIC

second_runtime=$(cg_fixture second-runtime)
printf '%s\n' \
  '' '[[package]]' 'name = "asupersync"' 'version = "0.3.9"' \
  'source = "registry+https://github.com/rust-lang/crates.io-index"' \
  'checksum = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"' \
  >>"$second_runtime/Cargo.lock"
cg_gate "$second_runtime" second-runtime 'multiple Asupersync 0.x type universes'
second_runtime_exit=$CG_GATE_EXIT
second_runtime_diagnostic=$CG_GATE_DIAGNOSTIC

tokio=$(cg_fixture tokio)
printf '%s\n' '' '[[package]]' 'name = "tokio"' 'version = "1.0.0"' >>"$tokio/Cargo.lock"
cg_gate "$tokio" tokio 'alternate async runtime `tokio`'
tokio_exit=$CG_GATE_EXIT
tokio_diagnostic=$CG_GATE_DIAGNOSTIC

patch=$(cg_fixture patch)
printf '%s\n' '' '[patch.crates-io]' 'asupersync = { path = "/absolute/unpublished" }' >>"$patch/Cargo.toml"
cg_gate "$patch" patch '[patch]/[replace]'
patch_exit=$CG_GATE_EXIT
patch_diagnostic=$CG_GATE_DIAGNOSTIC

backend=$(cg_fixture backend)
printf '%s\n' '' '[[package]]' 'name = "sqlmodel-postgres"' 'version = "0.1.0"' >>"$backend/Cargo.lock"
cg_gate "$backend" backend 'forbidden sqlmodel backend `sqlmodel-postgres`'
backend_exit=$CG_GATE_EXIT
backend_diagnostic=$CG_GATE_DIAGNOSTIC

codegen=$(cg_fixture codegen)
cg_replace_first "$codegen/constellation.lock" $'\tenabled\tdisabled\t' $'\tdisabled\tdisabled\t'
cg_gate "$codegen" codegen 'constellation build-script evidence drift'
codegen_exit=$CG_GATE_EXIT
codegen_diagnostic=$CG_GATE_DIAGNOSTIC

unsafe=$(cg_fixture unsafe)
cg_corrupt_transitive_unsafe_digest "$unsafe/constellation.lock" asupersync missing
cg_gate "$unsafe" unsafe 'transitive-unsafe evidence'
unsafe_exit=$CG_GATE_EXIT
unsafe_diagnostic=$CG_GATE_DIAGNOSTIC

feature=$(cg_fixture feature)
cg_replace_first "$feature/constellation.lock" $'\tnone\tdisabled\t' $'\tunsupported\tdisabled\t'
cg_gate "$feature" feature 'constellation feature closure drift'
feature_exit=$CG_GATE_EXIT
feature_diagnostic=$CG_GATE_DIAGNOSTIC

fge_phase assert
fge_assert_eq FG-001B-CONST-001 0 "$positive_exit" 'the exact admitted closure passes'
fge_assert_contains FG-001B-CONST-002 "$positive_diagnostic" \
  'FrankenGit constitutional verification passed' 'positive gate diagnosis'
fge_assert_ne FG-001B-CONST-003 0 "$second_runtime_exit" 'second Asupersync is rejected'
fge_assert_contains FG-001B-CONST-004 "$second_runtime_diagnostic" \
  'multiple Asupersync 0.x type universes' 'second runtime diagnostic is typed'
fge_assert_ne FG-001B-CONST-005 0 "$tokio_exit" 'Tokio is rejected'
fge_assert_contains FG-001B-CONST-006 "$tokio_diagnostic" \
  'alternate async runtime `tokio`' 'alternate runtime diagnostic is typed'
fge_assert_ne FG-001B-CONST-007 0 "$patch_exit" 'patch source is rejected'
fge_assert_contains FG-001B-CONST-008 "$patch_diagnostic" \
  '[patch]/[replace]' 'patch diagnostic is typed'
fge_assert_ne FG-001B-CONST-009 0 "$backend_exit" 'forbidden backend is rejected'
fge_assert_contains FG-001B-CONST-010 "$backend_diagnostic" \
  'forbidden sqlmodel backend `sqlmodel-postgres`' 'backend diagnostic is typed'
fge_assert_ne FG-001B-CONST-011 0 "$codegen_exit" 'build-script drift is rejected'
fge_assert_contains FG-001B-CONST-012 "$codegen_diagnostic" \
  'constellation build-script evidence drift' 'build-script diagnostic is typed'
fge_assert_ne FG-001B-CONST-013 0 "$unsafe_exit" 'unsafe evidence drift is rejected'
fge_assert_contains FG-001B-CONST-014 "$unsafe_diagnostic" \
  'transitive-unsafe evidence' 'unsafe evidence diagnostic is typed'
fge_assert_ne FG-001B-CONST-015 0 "$feature_exit" 'unsupported feature closure is rejected'
fge_assert_contains FG-001B-CONST-016 "$feature_diagnostic" \
  'constellation feature closure drift' 'feature diagnostic is typed'
