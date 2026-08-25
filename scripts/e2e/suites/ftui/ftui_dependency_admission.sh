#!/usr/bin/env bash
# e2e: FG-094a FrankenTUI kernel admission lane.
#
# Proves the constellation lane admits the PUBLISHED ftui kernel closure in its
# exact admitted shape and refuses the planted drift shapes for typed reasons:
#
#   permitted twin      the live tree, where no ftui package resolves, stays
#                       green -- a rule that refused everything would satisfy
#                       every planted case for the wrong reason;
#   admitted shape      one real member crate depending on published
#                       ftui-runtime 0.6.0 (features: asupersync-executor,
#                       native-backend; default-features = false), ftui-a11y
#                       0.6.0, asupersync 0.4.9 resolves offline and passes the
#                       gate once this bead's dependency_policy rows are
#                       applied, with `cargo tree -i asupersync` proving ONE
#                       0.4.9 across fgit-runtime + ftui-runtime + member;
#   second major        pinning ftui-runtime 0.5.0 (executor gated on
#                       asupersync ^0.3.4) drags a second Asupersync major into
#                       resolution and is refused;
#   alternate runtime   a planted tokio dependency is refused by name;
#   forbidden surface   ftui-runtime's telemetry feature (the OpenTelemetry
#                       exporter family) is refused per the FG-094a closure.
#
# RELATIONSHIP TO COMPANION SUITES: checker/fastapi_admission_gate.sh owns the
# gateway transport surfaces; checker/sqlmodel_admission_gate.sh owns the
# FrankenSQLite caller profile. This suite deliberately does not restate those.
#
# MECHANICS: identical to the companion gates -- fixtures copy the repo, add a
# real member crate, re-resolve OFFLINE from the local registry cache, then run
# tools/registry-check constellation with --locked semantics over the result.
# If the local registry cache lacks the pinned crates the suite fails rather
# than skips: an unexercised cell is a non-pass, not a pass.
set -euo pipefail

FT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
FT_REPO=$(cd "$FT_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$FT_REPO/scripts/e2e/lib.sh"

fge_init fg094a-ftui-dependency-admission
fge_context bead frankengit-fg094a-ftui-admission-xxnu
fge_context checker fgit-registry-check
fge_context subcommand constellation
fge_context probe_workspace /data/projects/fgit-ftui-probe-staging

fge_phase setup

FT_WORK=$(fge_tempdir ftui-admission)

ft_fixture() {
  local name=$1 dep_lines=$2
  local root="$FT_WORK/$name"
  mkdir -p "$root/tools"
  cp "$FT_REPO/Cargo.lock" "$root/Cargo.lock"
  cp "$FT_REPO/constellation.lock" "$root/constellation.lock"
  cp "$FT_REPO/LICENSE" "$root/LICENSE"
  cp "$FT_REPO/Cargo.toml" "$root/Cargo.toml"
  cp -a "$FT_REPO/crates" "$root/crates"
  cp -a "$FT_REPO/registries" "$root/registries"
  cp -a "$FT_REPO/tools/registry-check" "$root/tools/registry-check"
  mkdir -p "$root/crates/ftui-link-fixture/src"
  cat >"$root/crates/ftui-link-fixture/Cargo.toml" <<EOF
[package]
name = "fgit-ftui-link-fixture"
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
  printf '#![forbid(unsafe_code)]\n' >"$root/crates/ftui-link-fixture/src/lib.rs"
  printf '%s' "$root"
}

ft_resolve() {
  local root=$1 label=$2
  fge_capture "resolve-$label" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo metadata \
    --manifest-path "$root/Cargo.toml" --offline --format-version=1 >/dev/null || true
  FT_RESOLVE_EXIT=$FGE_LAST_EXIT
}

ft_gate() {
  local fixture=$1 case_name=$2 expected=$3
  fge_field fixture "$case_name"
  fge_field expected_diagnostic "$expected"
  fge_capture "ftui-$case_name" \
    env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
    --manifest-path "$FT_REPO/tools/registry-check/Cargo.toml" \
    -- constellation --root "$fixture" || true
  FT_EXIT=$FGE_LAST_EXIT
  FT_DIAGNOSTIC="$(cat "$FGE_LAST_STDERR_FILE" 2>/dev/null)"$'\n'"$(cat "$FGE_LAST_STDOUT_FILE" 2>/dev/null)"
}

fge_phase action

# --- the permitted twin: today's live tree -----------------------------------
# No ftui package resolves there yet; the gate must stay green and silent on
# every ftui-specific rule.
ft_gate "$FT_REPO" live-tree-clean 'no ftui diagnostic'
live_exit=$FT_EXIT
live_diagnostic=$FT_DIAGNOSTIC

# --- the admitted shape ------------------------------------------------------
# The exact dependency lines a first consumer (FG-094b) will write. Resolution
# must succeed OFFLINE from the pinned lock plus local registry cache, and the
# gate must admit it once this bead's rows are applied.
admitted=$(ft_fixture admitted-shape 'asupersync = { version = "0.4.9", default-features = false }
ftui-a11y = { version = "0.6.0", default-features = false }
ftui-runtime = { version = "0.6.0", features = ["asupersync-executor", "native-backend"], default-features = false }')
ft_resolve "$admitted" admitted-shape
admitted_resolve_exit=$FT_RESOLVE_EXIT

# Regenerate the fixture's constellation ledger from its OWN resolution, so
# gate parity reflects a workspace that wired the kernel exactly as FG-094b
# will. The generator prints rows only; the file header is preserved verbatim.
fge_capture "constellation-regen-admitted" \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo run --quiet \
  --manifest-path "$FT_REPO/tools/registry-check/Cargo.toml" \
  -- ledger-constellation --root "$admitted" || true
admitted_regen_exit=$FGE_LAST_EXIT
awk '/^(#|state)/{print; next} /^package\t/{print; exit}' "$FT_REPO/constellation.lock" \
  > "$admitted/constellation.lock"
cat "$FGE_LAST_STDOUT_FILE" >> "$admitted/constellation.lock"
fge_capture "single-asupersync-universe" \
  env RCH_CARGO_WRAPPER_BYPASS=1 cargo tree --manifest-path "$admitted/crates/ftui-link-fixture/Cargo.toml" -i asupersync || true
tree_exit=$FGE_LAST_EXIT
tree_output="$(cat "$FGE_LAST_STDERR_FILE" 2>/dev/null)"$'\n'"$(cat "$FGE_LAST_STDOUT_FILE" 2>/dev/null)"
universe_version_count=$(printf '%s\n' "$tree_output" | grep -cE '^asupersync v[0-9]' || true)

ft_gate "$admitted" admitted-shape 'no refusal'
admitted_exit=$FT_EXIT
admitted_diagnostic=$FT_DIAGNOSTIC

# --- second Asupersync major -------------------------------------------------
# ftui-runtime 0.5.0 gates its executor on asupersync ^0.3.4. Resolving it next
# to this workspace's 0.4.9 either fails or splits the universe; both are
# refusals and the diagnostic must say why.
second_major=$(ft_fixture second-major 'asupersync = { version = "0.4.9", default-features = false }
ftui-runtime = { version = "=0.5.0", features = ["asupersync-executor"], default-features = false }')
ft_resolve "$second_major" second-major
second_resolve_exit=$FT_RESOLVE_EXIT
ft_gate "$second_major" second-major 'asupersync'
second_exit=$FT_EXIT
second_diagnostic=$FT_DIAGNOSTIC

# --- planted alternate runtime -----------------------------------------------
tokio_planted=$(ft_fixture tokio-planted 'tokio = "1"')
ft_resolve "$tokio_planted" tokio-planted
tokio_resolve_exit=$FT_RESOLVE_EXIT
ft_gate "$tokio_planted" tokio-planted 'runtime'
tokio_exit=$FT_EXIT
tokio_diagnostic=$FT_DIAGNOSTIC

# --- forbidden telemetry surface ---------------------------------------------
# The exporter family is excluded from the FG-094a kernel closure; enabling the
# feature that pulls opentelemetry must be refused at the manifest level.
telemetry=$(ft_fixture telemetry-feature 'ftui-runtime = { version = "0.6.0", features = ["telemetry"], default-features = false }')
ft_gate "$telemetry" telemetry-feature 'telemetry'
telemetry_exit=$FT_EXIT
telemetry_diagnostic=$FT_DIAGNOSTIC

fge_phase assert

# permitted twin
fge_assert_eq FG-094A-FTUI-001 0 "$live_exit" \
  'the live tree without any ftui package passes the constellation lane'
fge_assert_not_contains FG-094A-FTUI-002 "$live_diagnostic" 'ftui-runtime' \
  'ftui rules stay silent while no ftui package resolves'

# admitted shape
fge_assert_eq FG-094A-FTUI-010 0 "$admitted_resolve_exit" \
  'the admitted-shape fixture resolved offline into an exact lock'
fge_assert_eq FG-094A-FTUI-011 0 "$tree_exit" \
  'cargo tree resolved the single-asupersync inventory'
fge_assert_eq FG-094A-FTUI-016 0 "$admitted_regen_exit" \
  'the fixture constellation ledger regenerated from its own resolution'
fge_assert_contains FG-094A-FTUI-012 "$tree_output" 'asupersync v0.4.9' \
  'the inverted tree names exactly our resolved asupersync version'
fge_assert_eq FG-094A-FTUI-013 1 "$universe_version_count" \
  'exactly one asupersync version appears in the inverted tree: no second major'
fge_assert_eq FG-094A-FTUI-014 0 "$admitted_exit" \
  'the admitted kernel closure passes the constellation gate'
fge_assert_not_contains FG-094A-FTUI-015 "$admitted_diagnostic" 'missing from the dependency policy registry' \
  'every closure package carries an active allow row'
fge_assert_contains FG-094A-FTUI-021 "$second_diagnostic" 'multiple Asupersync' \
  'the refusal names the split Asupersync type universes'
fge_assert_ne FG-094A-FTUI-020 0 "$second_exit" \
  'resolving the 0.5.0 executor beside asupersync 0.4.9 is refused'

# alternate runtime
fge_assert_ne FG-094A-FTUI-030 0 "$tokio_exit" \
  'a planted tokio dependency is refused'
fge_assert_contains FG-094A-FTUI-031 "$tokio_diagnostic" 'tokio' \
  'the refusal names the planted alternate runtime'

# forbidden telemetry surface
fge_assert_ne FG-094A-FTUI-040 0 "$telemetry_exit" \
  'enabling the exporter-pulling telemetry feature is refused'
fge_assert_contains FG-094A-FTUI-041 "$telemetry_diagnostic" 'forbidden ftui' \
  'the refusal names the forbidden feature surface'

fge_phase teardown
