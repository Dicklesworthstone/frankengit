#!/usr/bin/env bash
# e2e: proves the constellation lane refuses the sqlmodel projection substrate
# wired while its published manifest violates the minimal FrankenSQLite caller
# profile, and records precisely why FG-093a admission is blocked upstream.
#
# READ THIS BEFORE TREATING A GREEN RUN AS "SQLMODEL IS ADMITTED": it is not.
# Every published sqlmodel-frankensqlite 0.4.x requests the fsqlite family
# WITHOUT `default-features = false`, so resolving the substrate unions
# json/fts5/rtree/icu/misc/extensions plus the unconditional Linux io_uring
# profile into EVERY workspace consumer -- including the authority adapter
# pinned at DEP-176..218. Cargo has no consumer-side feature downgrade. The
# checker's check_sqlmodel_substrate_feature_profile turns that widening into
# a typed refusal naming the upstream prerequisite (integration profile §3.2);
# this suite proves the refusal fires for the right reason and stays silent on
# the admitted tree.
#
# RELATIONSHIP TO COMPANION SUITES: constellation_gate.sh owns second-
# Asupersync, Tokio, [patch], sqlmodel-backend and evidence-drift cases;
# fastapi_admission_gate.sh owns the gateway transport surfaces. This suite
# deliberately does not restate those; it covers the feature-profile widening
# that had NO rule before FG-093a.
#
# MECHANICS NOTE: unlike the orphan-package fixtures in the companion suites,
# these cases must survive `cargo metadata --locked --offline`, because the
# rule under test reads RESOLVED feature closures from metadata nodes. Each
# fixture therefore adds a real member crate depending on the published
# substrate and re-resolves its lock OFFLINE from the local registry cache
# before running the gate. If the cache lacks the pinned crates the suite
# fails rather than skips: an unexercised cell is a non-pass, not a pass.
set -euo pipefail

SM_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SM_REPO=$(cd "$SM_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$SM_REPO/scripts/e2e/lib.sh"

fge_init fg093a-sqlmodel-admission-gate
fge_context bead frankengit-fg093a-sqlmodel-admission-cm7y
fge_context checker fgit-registry-check
fge_context subcommand constellation
fge_context profile_line "ASUPERSYNC_AND_FRANKENSQLITE_INTEGRATION_PROFILE.md §3.2"
fge_phase setup

SM_WORK=$(fge_tempdir sqlmodel-admission)

# Fixture with one real member crate linking the substrate exactly as a
# downstream integration would. `$1` is appended to the member's dependency
# line so the same builder expresses both the published shape and variants.
sm_fixture() {
  local name=$1 dep_line=$2
  local root="$SM_WORK/$name"
  mkdir -p "$root/tools"
  cp "$SM_REPO/Cargo.lock" "$root/Cargo.lock"
  cp "$SM_REPO/constellation.lock" "$root/constellation.lock"
  cp "$SM_REPO/LICENSE" "$root/LICENSE"
  cp "$SM_REPO/Cargo.toml" "$root/Cargo.toml"
  cp -a "$SM_REPO/crates" "$root/crates"
  cp -a "$SM_REPO/tools/registry-check" "$root/tools/registry-check"
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
$dep_line

[lints]
workspace = true
EOF
  printf '#![forbid(unsafe_code)]\n' >"$root/crates/sm-link-fixture/src/lib.rs"
  printf '%s' "$root"
}

# Re-resolve a fixture lock offline. cargo metadata without --locked rewrites
# the lock in place; the gate itself then runs --locked against the result.
sm_resolve() {
  local root=$1 label=$2
  fge_capture "resolve-$label" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo metadata \
    --manifest-path "$root/Cargo.toml" --offline --format-version=1 >/dev/null || true
  SM_RESOLVE_EXIT=$FGE_LAST_EXIT
}

sm_gate() {
  local fixture=$1 case_name=$2 expected=$3
  fge_field fixture "$case_name"
  fge_field expected_diagnostic "$expected"
  fge_field cargo_lock_digest "$(fge_digest_file "$fixture/Cargo.lock")"
  fge_capture "sqlmodel-$case_name" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$SM_REPO/tools/registry-check/Cargo.toml" \
    -- constellation --root "$fixture" || true
  SM_EXIT=$FGE_LAST_EXIT
  SM_DIAGNOSTIC="$FGE_LAST_STDERR"$'\n'"$FGE_LAST_STDOUT"
}

fge_phase action

# --- the permitted twin: today's admitted tree --------------------------------
# Without this, a rule that refused everything would satisfy every planted case
# below for entirely the wrong reason. Run against the LIVE tree: the substrate
# is absent from Cargo.lock there, and the constellation lane must stay green.
sm_gate "$SM_REPO" live-tree-clean 'no substrate diagnostic'
live_exit=$SM_EXIT
live_diagnostic=$SM_DIAGNOSTIC

# --- the published shape is refused, naming the prerequisite ------------------
# The dependency line below IS the published contract of sqlmodel-frankensqlite
# 0.4.x: nothing extra planted. Resolution unions fsqlite's defaults into the
# graph, and the gate must refuse that with the typed §3.2 diagnostic.
published=$(sm_fixture published 'sqlmodel-frankensqlite = "0.4.0"')
sm_resolve "$published" published-substrate
resolve_exit=$SM_RESOLVE_EXIT
sm_gate "$published" published-substrate \
  'minimal FrankenSQLite caller profile'
published_exit=$SM_EXIT
published_diagnostic=$SM_DIAGNOSTIC

fge_phase assert

fge_assert_eq FG-093A-SM-001 0 "$live_exit" \
  'the admitted tree passes the constellation lane'
fge_assert_not_contains FG-093A-SM-002 "$live_diagnostic" \
  'minimal FrankenSQLite caller profile' \
  'the substrate feature-profile rule stays silent while no substrate resolves'

fge_assert_eq FG-093A-SM-003 0 "$resolve_exit" \
  'the published-substrate fixture resolved offline into an exact lock'

fge_assert_ne FG-093A-SM-004 0 "$published_exit" \
  'wiring the published substrate is refused'
fge_assert_contains FG-093A-SM-005 "$published_diagnostic" \
  'sqlmodel projection substrate requires the minimal FrankenSQLite caller profile' \
  'the refusal names the caller-profile rule'
fge_assert_contains FG-093A-SM-006 "$published_diagnostic" \
  '`fsqlite` resolved with excluded feature `json`' \
  'the json extension surface is named as excluded'
fge_assert_contains FG-093A-SM-007 "$published_diagnostic" \
  '`fsqlite` resolved with excluded feature `linux-asupersync-uring`' \
  'the unconditional io_uring profile is named as excluded'
fge_assert_contains FG-093A-SM-008 "$published_diagnostic" \
  'default-features = false' \
  'the refusal states the exact upstream prerequisite'
