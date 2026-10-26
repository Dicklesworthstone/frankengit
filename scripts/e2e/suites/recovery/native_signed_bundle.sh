#!/usr/bin/env bash
# e2e: signed file-backed operator verification through an actual native fg.
set -euo pipefail
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
ROOT="$(cd "$E2E_ROOT/../.." && pwd -P)"
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"
fge_init native-signed-bundle
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.59
fge_context non_claim 'One real signed-bundle entrypoint; generated packs, no Git differential oracle, whole-operator coverage, new Rust build or forge restore.'
fge_phase setup
FG_BIN="${FG_BIN:-}"
NODE="${FGE_NODE:-$(command -v node || true)}"
fge_assert_cmd SIGNED-BUNDLE-001 'FG_BIN names a qualified prebuilt executable' test -x "$FG_BIN"
[[ -x "$FG_BIN" && "$FG_BIN" = /* ]] || fge_die 'FG_BIN must be an absolute prebuilt executable'
[[ "${FG_SIGNED_BUNDLE_SOURCE_CUT:-}" =~ ^[0-9a-f]{40}$ ]] || fge_die 'FG_SIGNED_BUNDLE_SOURCE_CUT must name the qualified binary source, not a guessed checkout revision'
[[ -x "$NODE" ]] || fge_die 'Node executable is unavailable'
pin="$(cat "$ROOT/tests/node-version")"
actual="$("$NODE" --version)"
fge_assert_eq SIGNED-BUNDLE-002 "v$pin" "$actual" 'Node matches the single repository test pin'
[[ "$actual" = "v$pin" ]] || fge_die 'pinned Node is required for this native operator campaign'
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context fg_source_cut "$FG_SIGNED_BUNDLE_SOURCE_CUT"
fge_context node_version "$actual"
work="$(fge_tempdir native-signed-bundle)"
fge_phase action
fge_run_timeout 240 signed-campaign "$NODE" "$E2E_ROOT/helpers/native_signed_bundle.mjs" \
  --fg "$FG_BIN" --fg-source-cut "$FG_SIGNED_BUNDLE_SOURCE_CUT" --work "$work" || true
fge_assert_exit SIGNED-BUNDLE-003 0 "$FGE_LAST_EXIT" 'real signed/native success and refusal campaign completes'
fge_assert_file SIGNED-BUNDLE-004 "$work/summary.json" 'campaign retains raw commands and facts'
rows="$("$NODE" -e 'const fs=require("node:fs");const x=JSON.parse(fs.readFileSync(process.argv[1]));for(const [k,v] of Object.entries(x.checks))console.log(k+"="+v)' "$work/summary.json")"
result() {
  local row
  while IFS= read -r row; do
    if [[ "$row" = "$1="* ]]; then printf '%s\n' "${row#*=}"; return; fi
  done <<< "$rows"
  printf 'not-executed\n'
}
fge_phase assert
fge_assert_eq SIGNED-BUNDLE-101 pass "$(result sha1.default)" 'SHA1 default input allowance refuses'
fge_assert_eq SIGNED-BUNDLE-102 pass "$(result sha1.file_backed)" 'SHA1 explicit allowance verifies real signed large content'
fge_assert_eq SIGNED-BUNDLE-103 pass "$(result sha1.rust_read)" 'SHA1 direct Rust read agrees and removes scratch'
fge_assert_eq SIGNED-BUNDLE-104 pass "$(result sha1.wrong_signer)" 'SHA1 wrong signer refuses'
fge_assert_eq SIGNED-BUNDLE-105 pass "$(result sha1.wrong_ref)" 'SHA1 independent ref mismatch refuses'
fge_assert_eq SIGNED-BUNDLE-106 pass "$(result sha1.expanded)" 'SHA1 expansion budget refuses'
fge_assert_eq SIGNED-BUNDLE-107 pass "$(result sha1.signed_invalid)" 'SHA1 authenticated invalid content refuses in Rust'
fge_assert_eq SIGNED-BUNDLE-108 pass "$(result sha1.tampered)" 'SHA1 signed artifact mismatch refuses'
fge_assert_eq SIGNED-BUNDLE-109 pass "$(result sha1.expired)" 'SHA1 expired approval refuses'
fge_assert_eq SIGNED-BUNDLE-201 pass "$(result sha256.default)" 'SHA256 default input allowance refuses'
fge_assert_eq SIGNED-BUNDLE-202 pass "$(result sha256.file_backed)" 'SHA256 explicit allowance verifies real signed large content'
fge_assert_eq SIGNED-BUNDLE-203 pass "$(result sha256.rust_read)" 'SHA256 direct Rust read agrees and removes scratch'
fge_assert_eq SIGNED-BUNDLE-204 pass "$(result sha256.wrong_signer)" 'SHA256 wrong signer refuses'
fge_assert_eq SIGNED-BUNDLE-205 pass "$(result sha256.wrong_ref)" 'SHA256 independent ref mismatch refuses'
fge_assert_eq SIGNED-BUNDLE-206 pass "$(result sha256.expanded)" 'SHA256 expansion budget refuses'
fge_assert_eq SIGNED-BUNDLE-207 pass "$(result sha256.signed_invalid)" 'SHA256 authenticated invalid content refuses in Rust'
fge_assert_eq SIGNED-BUNDLE-208 pass "$(result sha256.tampered)" 'SHA256 signed artifact mismatch refuses'
fge_assert_eq SIGNED-BUNDLE-209 pass "$(result sha256.expired)" 'SHA256 expired approval refuses'
fge_artifact "$work/summary.json" json
