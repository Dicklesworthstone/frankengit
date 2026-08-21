#!/usr/bin/env bash
# e2e: proves the checker admits a real crate and refuses empty, placeholder,
# lint-relaxed, re-export-only, test-only, and unsafe-ledger-drifted variants.
set -euo pipefail

CG_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
CG_REPO=$(cd "$CG_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$CG_REPO/scripts/e2e/lib.sh"

fge_init fg001c-crate-graph-constitution
fge_context bead frankengit-fg001c-checker-crate-graph-vvr
fge_context checker fgit-registry-check
fge_phase setup

CG_WORK=$(fge_tempdir crate-graph-constitution)

cg_fixture() {
  local name=$1
  local root="$CG_WORK/$name"
  mkdir -p "$root/crates/fgit-probe/src" "$root/crates/asupersync/src" "$root/registries"
  cp "$CG_REPO/registries/dependency_policy.tsv" \
    "$root/registries/dependency_policy.tsv"
  printf '%s\n' \
    '[workspace]' \
    'resolver = "3"' \
    'members = ["crates/asupersync", "crates/fgit-probe"]' \
    'default-members = ["crates/asupersync", "crates/fgit-probe"]' \
    '' \
    '[workspace.package]' \
    'edition = "2024"' \
    'license-file = "LICENSE"' \
    'repository = "https://example.invalid/frankengit"' \
    '' \
    '[workspace.lints.rust]' \
    'unsafe_code = "forbid"' \
    '' \
    '[workspace.lints.clippy]' \
    'pedantic = "deny"' \
    'nursery = "deny"' >"$root/Cargo.toml"
  printf '%s\n' \
    '[package]' \
    'name = "fgit-probe"' \
    'version = "0.0.1"' \
    'edition.workspace = true' \
    'publish = false' \
    '' \
    '[lints]' \
    'workspace = true' >"$root/crates/fgit-probe/Cargo.toml"
  printf '%s\n' \
    '[package]' \
    'name = "asupersync"' \
    'version = "0.4.9"' \
    'edition.workspace = true' \
    'publish = false' \
    '' \
    '[lints]' \
    'workspace = true' >"$root/crates/asupersync/Cargo.toml"
  printf '%s\n' \
    'version = 4' \
    '' \
    '[[package]]' \
    'name = "asupersync"' \
    'version = "0.4.9"' \
    '' \
    '[[package]]' \
    'name = "fgit-probe"' \
    'version = "0.0.1"' >"$root/Cargo.lock"
  printf '%s\n' \
    '#![forbid(unsafe_code)]' \
    '' \
    '/// Minimal admitted runtime fixture for the closure ledger.' \
    'pub struct Runtime;' >"$root/crates/asupersync/src/lib.rs"
  printf '%s\n' \
    '#![forbid(unsafe_code)]' \
    '' \
    '/// A complete production capability, not an empty marker.' \
    'pub struct Probe {' \
    '    revision: u64,' \
    '}' \
    '' \
    'impl Probe {' \
    '    #[must_use]' \
    '    pub const fn revision(&self) -> u64 {' \
    '        self.revision' \
    '    }' \
    '}' >"$root/crates/fgit-probe/src/lib.rs"
  printf '%s' "$root"
}

cg_write_source() {
  local root=$1 source=$2
  printf '%s\n' "$source" >"$root/crates/fgit-probe/src/lib.rs"
}

cg_replace_first() {
  local path=$1 before=$2 after=$3 content
  content=$(<"$path")
  [[ $content == *"$before"* ]] || return 1
  printf '%s' "${content/"$before"/"$after"}" >"$path"
}

cg_gate() {
  local fixture=$1 case_name=$2 command=$3
  fge_field fixture "$case_name"
  fge_field command "$command"
  fge_field cargo_lock_digest "$(fge_digest_file "$fixture/Cargo.lock")"
  fge_capture "crate-graph-$case_name" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$CG_REPO/tools/registry-check/Cargo.toml" \
    -- "$command" --root "$fixture" || true
  CG_GATE_EXIT=$FGE_LAST_EXIT
  # Assertion inputs must use the full capture. Constitution intentionally
  # reports every independent finding, so the inline evidence preview may end
  # before the unsafe-policy mismatch this fixture is proving.
  CG_GATE_DIAGNOSTIC=$(<"$FGE_LAST_STDERR_FILE")
  CG_GATE_DIAGNOSTIC+=$'\n'
  CG_GATE_DIAGNOSTIC+=$(<"$FGE_LAST_STDOUT_FILE")
}

fge_phase action
positive=$(cg_fixture positive)
cg_gate "$positive" positive crate-graph
positive_exit=$CG_GATE_EXIT
positive_diagnostic=$CG_GATE_DIAGNOSTIC

empty=$(cg_fixture empty)
rm "$empty/crates/fgit-probe/src/lib.rs"
cg_gate "$empty" empty crate-graph
empty_exit=$CG_GATE_EXIT
empty_diagnostic=$CG_GATE_DIAGNOSTIC

placeholder=$(cg_fixture placeholder)
cg_write_source "$placeholder" $'#![forbid(unsafe_code)]\n\npub fn committed_path() {\n    todo!()\n}'
cg_gate "$placeholder" placeholder crate-graph
placeholder_exit=$CG_GATE_EXIT
placeholder_diagnostic=$CG_GATE_DIAGNOSTIC

test_only=$(cg_fixture test-only)
cg_write_source "$test_only" $'#![forbid(unsafe_code)]\n\n#[cfg(test)]\npub fn test_only_path() {}'
cg_gate "$test_only" test-only crate-graph
test_only_exit=$CG_GATE_EXIT
test_only_diagnostic=$CG_GATE_DIAGNOSTIC

reexport=$(cg_fixture reexport)
cg_write_source "$reexport" $'#![forbid(unsafe_code)]\n\npub use crate::missing_implementation;'
cg_gate "$reexport" reexport crate-graph
reexport_exit=$CG_GATE_EXIT
reexport_diagnostic=$CG_GATE_DIAGNOSTIC

lint=$(cg_fixture lint)
cg_write_source "$lint" $'#![forbid(unsafe_code)]\n\n#[allow(clippy::pedantic)]\npub fn complete_path() {}'
cg_gate "$lint" lint crate-graph
lint_exit=$CG_GATE_EXIT
lint_diagnostic=$CG_GATE_DIAGNOSTIC

ledger_positive=$(cg_fixture ledger-positive)
cg_gate "$ledger_positive" ledger-positive ledger-unsafe
ledger_positive_exit=$CG_GATE_EXIT
ledger_positive_diagnostic=$CG_GATE_DIAGNOSTIC

ledger_mismatch=$(cg_fixture ledger-mismatch)
cg_replace_first \
  "$ledger_mismatch/registries/dependency_policy.tsv" \
  'must_forbid_first_party_unsafe' \
  'ledgered_transitive'
cg_gate "$ledger_mismatch" ledger-mismatch constitution
ledger_mismatch_exit=$CG_GATE_EXIT
ledger_mismatch_diagnostic=$CG_GATE_DIAGNOSTIC

fge_phase assert
fge_assert_eq FG-001C-GRAPH-001 0 "$positive_exit" 'real production crate passes'
fge_assert_contains FG-001C-GRAPH-002 "$positive_diagnostic" \
  'FrankenGit constitutional verification passed' 'positive crate graph diagnosis'
fge_assert_ne FG-001C-GRAPH-003 0 "$empty_exit" 'empty crate is refused'
fge_assert_contains FG-001C-GRAPH-004 "$empty_diagnostic" \
  'has no production Rust target' 'empty crate diagnostic is typed'
fge_assert_ne FG-001C-GRAPH-005 0 "$placeholder_exit" 'placeholder path is refused'
fge_assert_contains FG-001C-GRAPH-006 "$placeholder_diagnostic" \
  'placeholder `todo!`' 'placeholder diagnostic is typed'
fge_assert_ne FG-001C-GRAPH-007 0 "$test_only_exit" 'test-only crate is refused'
fge_assert_contains FG-001C-GRAPH-008 "$test_only_diagnostic" \
  'contains only cfg(test)-gated behavior' 'test-only diagnostic is typed'
fge_assert_ne FG-001C-GRAPH-009 0 "$reexport_exit" 're-export-only library is refused'
fge_assert_contains FG-001C-GRAPH-010 "$reexport_diagnostic" \
  'lib.rs only re-exports symbols' 're-export-only diagnostic is typed'
fge_assert_ne FG-001C-GRAPH-011 0 "$lint_exit" 'forbidden lint relaxation is refused'
fge_assert_contains FG-001C-GRAPH-012 "$lint_diagnostic" \
  'clippy::pedantic' 'lint-relaxation diagnostic is typed'
fge_assert_eq FG-001C-GRAPH-013 0 "$ledger_positive_exit" \
  'unsafe ledger accepts a matching registry policy'
fge_assert_contains FG-001C-GRAPH-014 "$ledger_positive_diagnostic" \
  $'fgit-probe\t0.0.1' 'unsafe ledger records the resolved local package'
fge_assert_contains FG-001C-GRAPH-015 "$ledger_positive_diagnostic" \
  $'must_forbid_first_party_unsafe\tmust_forbid_first_party_unsafe\ttrue' \
  'unsafe ledger records the matching policy'
fge_assert_ne FG-001C-GRAPH-016 0 "$ledger_mismatch_exit" \
  'unsafe policy drift is refused by constitution'
fge_assert_contains FG-001C-GRAPH-017 "$ledger_mismatch_diagnostic" \
  'unsafe ledger policy mismatch for resolved package `fgit-probe 0.0.1`' \
  'unsafe-policy drift diagnostic is typed'
