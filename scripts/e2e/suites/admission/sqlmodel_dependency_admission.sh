#!/usr/bin/env bash
# e2e: FG-093a sqlmodel/FrankenSQLite runtime convergence and admission.
#
# Proves BOTH halves of the sqlmodel projection substrate admission story:
#
#   1. CONVERGED ADMISSION (positive path): published sqlmodel-frankensqlite
#      0.4.1 requests the fsqlite family with `default-features = false` and
#      the minimal `{native, async-api}` set, exactly the prerequisite named
#      by integration profile §3.2 and this bead's BOUNDARY clause. Resolution
#      against the admitted constellation must preserve the live `fsqlite`
#      pin, the §3.2 caller-profile rule must stay silent, the full
#      constellation lane must pass once the fixture's constellation.lock
#      records the newly resolved adopted packages, and a real member crate
#      must COMPILE under the pinned toolchain with `asupersync::Cx`
#      type-addressable alongside the engine.
#
#   2. HISTORICAL REFUSAL (planted negative): the pre-convergence 0.4.0 shape
#      is still refused, naming the exact upstream prerequisite. This is the
#      same refusal suites/checker/sqlmodel_admission_gate.sh pinned when the
#      bead was blocked upstream; it is restated here so this suite proves the
#      gate discriminates rather than admitting everything.
#
# MECHANICS: fixtures copy the live tree (so Cargo.lock version pins and the
# admitted dependency-policy rows are inherited verbatim), add one real member
# crate depending on the substrate exactly as a downstream integration would,
# re-resolve OFFLINE, regenerate the fixture constellation.lock through
# `ledger-constellation`, run the full constellation gate, and compile-check
# the member.
set -euo pipefail

DA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DA_REPO=$(cd "$DA_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$DA_REPO/scripts/e2e/lib.sh"

fge_init fg093a-sqlmodel-dependency-admission
fge_context bead frankengit-fg093a-sqlmodel-admission-cm7y
fge_context checker fgit-registry-check
fge_context subcommand constellation
fge_context profile_line "ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md §3.2"
fge_phase setup

DA_WORK=$(fge_tempdir sqlmodel-dependency-admission)

# Fixture builder: `$1` name, `$2` dependency lines inserted verbatim into the
# member's [dependencies] table, `$3` optional extra Rust body appended to the
# member's lib.rs so probes can name substrate/runtime types directly.
da_fixture() {
  local name=$1 dep_lines=$2 lib_extra=${3:-}
  local root="$DA_WORK/$name"
  mkdir -p "$root/tools"
  cp "$DA_REPO/Cargo.lock" "$root/Cargo.lock"
  cp "$DA_REPO/constellation.lock" "$root/constellation.lock"
  cp "$DA_REPO/LICENSE" "$root/LICENSE"
  cp "$DA_REPO/Cargo.toml" "$root/Cargo.toml"
  cp -a "$DA_REPO/crates" "$root/crates"
  cp -a "$DA_REPO/tools/registry-check" "$root/tools/registry-check"
  mkdir -p "$root/crates/sm-link-fixture/src"
  cat >"$root/crates/sm-link-fixture/Cargo.toml" <<EOF
[package]
name = "fgit-sm-link-fixture"
version = "0.0.1"
edition.workspace = true
license-file.workspace = true
repository.workspace = true
publish = false

[dependencies]
$dep_lines

[lints]
workspace = true
EOF
  {
    printf '#![forbid(unsafe_code)]\n'
    printf '%s\n' "$lib_extra"
  } >"$root/crates/sm-link-fixture/src/lib.rs"
  printf '%s' "$root"
}

# Offline lock re-resolution. cargo metadata without --locked rewrites the
# lock in place; the gate itself then runs --locked against the result. The
# offline flag is honest about the no-network constitution: the local registry
# cache must already hold the pinned crates or the case fails instead of skips.
da_resolve() {
  local root=$1 label=$2
  fge_capture "resolve-$label" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo metadata \
    --manifest-path "$root/Cargo.toml" --offline --format-version=1 >/dev/null || true
  DA_RESOLVE_EXIT=$FGE_LAST_EXIT
}

# Regenerate a fixture constellation.lock that records every resolved adopted
# package: keep the live header (marker comments, `state` line, column header)
# verbatim and replace only the row block with fresh `ledger-constellation`
# output computed against the fixture's own resolved closure.
da_regenerate_constellation() {
  local root=$1
  fge_capture "constellation-ledger-$(basename "$root")" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$DA_REPO/tools/registry-check/Cargo.toml" \
    -- ledger-constellation --root "$root" || true
  local rows=$FGE_LAST_STDOUT_FILE header_end
  header_end=$(grep -n '^package	' "$root/constellation.lock" | cut -d: -f1 | head -1)
  { head -n "$header_end" "$root/constellation.lock"; cat "$rows"; } \
    >"$root/constellation.lock.next"
  mv "$root/constellation.lock.next" "$root/constellation.lock"
}

# Run the full constellation gate against a fixture and capture diagnostics.
da_gate() {
  local fixture=$1 case_name=$2 expected=$3
  fge_field fixture "$case_name"
  fge_field expected_diagnostic "$expected"
  fge_field cargo_lock_digest "$(fge_digest_file "$fixture/Cargo.lock")"
  fge_capture "sqlmodel-$case_name" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$DA_REPO/tools/registry-check/Cargo.toml" \
    -- constellation --root "$fixture" || true
  DA_EXIT=$FGE_LAST_EXIT
  DA_DIAGNOSTIC="$(cat "$FGE_LAST_STDERR_FILE" 2>/dev/null)"$'\n'"$(cat "$FGE_LAST_STDOUT_FILE" 2>/dev/null)"
}

fge_phase action

# --- converged admission: the published 0.4.1 shape ---------------------------
# The dependency line below IS the converged contract: sqlmodel-frankensqlite
# 0.4.1 pinned exactly (a bare "0.4.1" would be a caret request) and requested
# with `default-features = false` - the §3.2 minimal caller profile this whole
# bead exists to admit - plus the runtime handle a downstream integration
# consumes. Nothing extra is planted.
converged=$(da_fixture converged \
  'sqlmodel-frankensqlite = { version = "=0.4.1", default-features = false }
asupersync = { version = "=0.4.9", default-features = false }' \
  '// The admission probe: the one-runtime context type must remain nameable
// from a substrate consumer without any second runtime entering the graph.
// This is a type-level statement, checked by compilation below.
#[allow(dead_code)]
fn cx_remains_addressable(cx: &asupersync::Cx) -> &asupersync::Cx {
    cx
}')
da_resolve "$converged" converged-substrate
converged_resolve_exit=$DA_RESOLVE_EXIT

# The live `fsqlite` pin must survive resolution: the substrate requests
# `^0.3.7`, the constellation admits exactly 0.3.7, and a drift here would
# mean the positive path silently upgraded the storage engine.
converged_fsqlite_line=$(grep -A1 '^name = "fsqlite"$' "$converged/Cargo.lock" | tail -1)

da_regenerate_constellation "$converged"
da_gate "$converged" converged-admitted 'no caller-profile diagnostic'
converged_exit=$DA_EXIT
converged_diagnostic=$DA_DIAGNOSTIC

# Compile probe: the member must typecheck under the pinned toolchain with the
# engine linked through its minimal profile.
fge_capture "compile-probe-converged" \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo check --quiet \
  --manifest-path "$converged/Cargo.toml" -p fgit-sm-link-fixture || true
compile_exit=$FGE_LAST_EXIT

# --- historical refusal: the pre-convergence 0.4.0 shape ----------------------
# The fixture drops crates/fgit-projection: the live tree's projection slice
# pins sqlmodel-frankensqlite =0.4.1, and exact-incompatible requirements
# (=0.4.0 here, =0.4.1 there) cannot coexist in one resolution graph. The
# refusal case tests the §3.2 rule against the historical closure shape and
# needs neither the projection crate nor live-lock inheritance beyond what
# the copied policy rows provide.
published=$(da_fixture published 'sqlmodel-frankensqlite = "=0.4.0"')
rm -rf "$published/crates/fgit-projection"
da_resolve "$published" published-substrate
published_resolve_exit=$DA_RESOLVE_EXIT
da_gate "$published" published-refused 'minimal FrankenSQLite caller profile'
published_exit=$DA_EXIT
published_diagnostic=$DA_DIAGNOSTIC

fge_phase assert

# Converged admission half.
fge_assert_eq FG-093A-DA-001 0 "$converged_resolve_exit" \
  'the converged-substrate fixture resolved offline into an exact lock'
fge_assert_contains FG-093A-DA-002 "$converged_fsqlite_line" '0.3.7' \
  'resolution preserved the admitted fsqlite pin instead of upgrading'
fge_assert_eq FG-093A-DA-003 0 "$converged_exit" \
  'the converged substrate passes the full constellation lane'
fge_assert_not_contains FG-093A-DA-004 "$converged_diagnostic" \
  'minimal FrankenSQLite caller profile' \
  'the caller-profile rule stays silent for default-features = false requests'
fge_assert_eq FG-093A-DA-005 0 "$compile_exit" \
  'the substrate member compiles with asupersync::Cx addressable'

# Historical refusal half.
fge_assert_eq FG-093A-DA-006 0 "$published_resolve_exit" \
  'the pre-convergence fixture also resolved offline into an exact lock'
fge_assert_ne FG-093A-DA-007 0 "$published_exit" \
  'wiring the pre-convergence substrate is still refused'
fge_assert_contains FG-093A-DA-008 "$published_diagnostic" \
  'sqlmodel projection substrate requires the minimal FrankenSQLite caller profile' \
  'the refusal names the caller-profile rule'
fge_assert_contains FG-093A-DA-009 "$published_diagnostic" \
  '`fsqlite` resolved with excluded feature `json`' \
  'the json extension surface is named as excluded'
fge_assert_contains FG-093A-DA-010 "$published_diagnostic" \
  'default-features = false' \
  'the refusal states the exact upstream prerequisite'

fge_phase teardown
