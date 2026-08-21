#!/usr/bin/env bash
# e2e: proves the constellation preflight refuses each gateway-transport surface
# FG-048c must exclude, and -- separately -- records why fastapi_rust 0.4.x is
# not admissible today.
#
# READ THIS BEFORE TREATING A GREEN RUN AS "FASTAPI IS ADMITTED": it is not.
# This suite proves the GATE behaves. fastapi_rust is absent from Cargo.lock and
# from constellation.lock, and FG-048c's admission half is blocked upstream (see
# FA-006 below). A pass here means the refusals are correctly typed, nothing more.
#
# Companion to constellation_gate.sh, which owns the second-Asupersync, Tokio,
# [patch], sqlmodel-backend and evidence-drift cases. This suite deliberately
# does not restate those; it covers the surfaces that had NO rule before
# FG-048c: alternate HTTP runtimes/reactors, native TLS, native compression
# backends, and fastapi demo/example packages.
#
# Every planted case here is preflight-class. `check_constellation` runs
# `check_runtime_universe` + `check_forbidden_constellation_surfaces` and returns
# early on any hit, BEFORE `cargo metadata --locked`. That is what keeps these
# fixtures honest: an orphan `[[package]]` in a fixture lock would otherwise make
# `cargo metadata --locked` demand a lock rewrite, and the case would go non-zero
# for a bookkeeping reason instead of the reason under test.
set -euo pipefail

FA_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FA_REPO=$(cd "$FA_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$FA_REPO/scripts/e2e/lib.sh"

fge_init fg048c-fastapi-admission-gate
fge_context bead frankengit-fg048c-fastapi-admission-hogb
fge_context checker fgit-registry-check
fge_context subcommand constellation
fge_phase setup

FA_WORK=$(fge_tempdir fastapi-admission)

# The fixture retains exact workspace membership on purpose: reducing it lets
# Cargo legitimately request a lock rewrite before the constellation checks run.
fa_fixture() {
  local name=$1
  local root="$FA_WORK/$name"
  mkdir -p "$root/tools"
  cp "$FA_REPO/Cargo.lock" "$root/Cargo.lock"
  cp "$FA_REPO/constellation.lock" "$root/constellation.lock"
  cp "$FA_REPO/LICENSE" "$root/LICENSE"
  cp "$FA_REPO/Cargo.toml" "$root/Cargo.toml"
  cp -a "$FA_REPO/crates" "$root/crates"
  cp -a "$FA_REPO/tools/registry-check" "$root/tools/registry-check"
  printf '%s' "$root"
}

# Append one or more resolved packages to a fixture lock.
fa_plant_packages() {
  local lock=$1
  shift
  local entry name version
  for entry in "$@"; do
    name=${entry%@*}
    version=${entry#*@}
    printf '\n[[package]]\nname = "%s"\nversion = "%s"\n' "$name" "$version" >>"$lock"
  done
}

fa_gate() {
  local fixture=$1 case_name=$2 expected=$3
  fge_field fixture "$case_name"
  fge_field expected_diagnostic "$expected"
  fge_field cargo_lock_digest "$(fge_digest_file "$fixture/Cargo.lock")"
  fge_field constellation_digest "$(fge_digest_file "$fixture/constellation.lock")"
  fge_capture "fastapi-$case_name" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$FA_REPO/tools/registry-check/Cargo.toml" \
    -- constellation --root "$fixture" || true
  FA_EXIT=$FGE_LAST_EXIT
  FA_DIAGNOSTIC="$FGE_LAST_STDERR"$'\n'"$FGE_LAST_STDOUT"
}

fge_phase action

# --- the permitted twin -------------------------------------------------------
# Without this, a rule that refused everything would satisfy every planted case
# below for entirely the wrong reason.
positive=$(fa_fixture positive)
fa_gate "$positive" positive 'FrankenGit constitutional verification passed'
positive_exit=$FA_EXIT
positive_diagnostic=$FA_DIAGNOSTIC

# --- alternate HTTP runtimes and reactors ------------------------------------
hyper=$(fa_fixture hyper)
fa_plant_packages "$hyper/Cargo.lock" 'hyper@1.4.0'
fa_gate "$hyper" hyper 'forbidden native transport `hyper`'
hyper_exit=$FA_EXIT
hyper_diagnostic=$FA_DIAGNOSTIC

# actix-rt is matched by prefix rather than by exact name; a rule built only
# from the `matches!` list would miss it.
actix=$(fa_fixture actix)
fa_plant_packages "$actix/Cargo.lock" 'actix-rt@2.9.0'
fa_gate "$actix" actix 'forbidden native transport `actix-rt`'
actix_exit=$FA_EXIT
actix_diagnostic=$FA_DIAGNOSTIC

# --- native TLS ---------------------------------------------------------------
tls=$(fa_fixture tls)
fa_plant_packages "$tls/Cargo.lock" 'openssl-sys@0.9.102'
fa_gate "$tls" tls 'forbidden native transport `openssl-sys`'
tls_exit=$FA_EXIT
tls_diagnostic=$FA_DIAGNOSTIC

# --- native compression -------------------------------------------------------
compression=$(fa_fixture compression)
fa_plant_packages "$compression/Cargo.lock" 'libz-sys@1.1.16'
fa_gate "$compression" compression 'forbidden native transport `libz-sys`'
compression_exit=$FA_EXIT
compression_diagnostic=$FA_DIAGNOSTIC

# --- pure-Rust compression is NOT a native backend ----------------------------
# The near-identical permitted case for the one above. flate2's default backend
# and miniz_oxide are pure Rust and must pass the transport rule. A rule that
# matched on "compression" instead of on the exact `-sys` backend names would
# refuse these, and this case is what catches that.
pure=$(fa_fixture pure-compression)
fa_plant_packages "$pure/Cargo.lock" 'flate2@1.0.30' 'miniz_oxide@0.7.3'
fa_gate "$pure" pure-compression 'no native transport diagnostic'
pure_diagnostic=$FA_DIAGNOSTIC

# --- fastapi demo/example packages -------------------------------------------
demo=$(fa_fixture demo)
fa_plant_packages "$demo/Cargo.lock" 'fastapi-demo@0.4.3'
fa_gate "$demo" demo 'forbidden fastapi demo/example package `fastapi-demo`'
demo_exit=$FA_EXIT
demo_diagnostic=$FA_DIAGNOSTIC

# --- why fastapi_rust 0.4.x is not admissible today ---------------------------
# This is not a hypothetical. Every published fastapi-core 0.4.x (0.4.0, 0.4.1,
# 0.4.2, 0.4.3 -- each inspected separately) declares a NON-optional dependency
# on futures-executor, and fastapi-rust depends non-optionally on fastapi-core.
# The three packages below are therefore the closure a real admission would
# produce. When upstream drops futures-executor this case stops reflecting
# reality and must be revisited rather than deleted.
executor=$(fa_fixture bundled-executor)
fa_plant_packages "$executor/Cargo.lock" \
  'fastapi-rust@0.4.3' 'fastapi-core@0.4.3' 'futures-executor@0.3.31'
fa_gate "$executor" bundled-executor 'alternate async runtime `futures-executor`'
executor_exit=$FA_EXIT
executor_diagnostic=$FA_DIAGNOSTIC

fge_phase assert

fge_assert_eq FG-048C-FA-001 0 "$positive_exit" \
  'the admitted closure passes with no fastapi rule firing'
fge_assert_not_contains FG-048C-FA-002 "$positive_diagnostic" \
  'forbidden native transport' \
  'the admitted closure carries no forbidden transport'

fge_assert_ne FG-048C-FA-003 0 "$hyper_exit" 'an alternate HTTP runtime is rejected'
fge_assert_contains FG-048C-FA-004 "$hyper_diagnostic" \
  'forbidden native transport `hyper`' 'alternate HTTP runtime diagnostic is typed'

fge_assert_ne FG-048C-FA-005 0 "$actix_exit" 'a prefix-matched reactor is rejected'
fge_assert_contains FG-048C-FA-006 "$actix_diagnostic" \
  'forbidden native transport `actix-rt`' 'reactor diagnostic is typed'

fge_assert_ne FG-048C-FA-007 0 "$tls_exit" 'native TLS is rejected'
fge_assert_contains FG-048C-FA-008 "$tls_diagnostic" \
  'forbidden native transport `openssl-sys`' 'native TLS diagnostic is typed'

fge_assert_ne FG-048C-FA-009 0 "$compression_exit" 'a native compression backend is rejected'
fge_assert_contains FG-048C-FA-010 "$compression_diagnostic" \
  'forbidden native transport `libz-sys`' 'native compression diagnostic is typed'

# Asserted as absence-of-diagnostic rather than exit 0: planting an orphan
# package makes `cargo metadata --locked` legitimately demand a lock rewrite, so
# a zero exit is not available here. The claim under test is narrower than the
# exit status and is stated exactly.
fge_assert_not_contains FG-048C-FA-011 "$pure_diagnostic" \
  'forbidden native transport `flate2`' 'pure-Rust flate2 is not a native backend'
fge_assert_not_contains FG-048C-FA-012 "$pure_diagnostic" \
  'forbidden native transport `miniz_oxide`' 'pure-Rust miniz_oxide is not a native backend'

fge_assert_ne FG-048C-FA-013 0 "$demo_exit" 'a fastapi demo package is rejected'
fge_assert_contains FG-048C-FA-014 "$demo_diagnostic" \
  'forbidden fastapi demo/example package `fastapi-demo`' 'fastapi demo diagnostic is typed'

fge_assert_ne FG-048C-FA-015 0 "$executor_exit" \
  'the real fastapi 0.4.x closure is refused'
fge_assert_contains FG-048C-FA-016 "$executor_diagnostic" \
  'alternate async runtime `futures-executor` resolved in Cargo.lock' \
  'the bundled executor is refused as a second runtime, by name'
