#!/usr/bin/env bash
# e2e: the JavaScript bundle verifier (scripts/verify_git_bundle.mjs, the decoder
# the browser's transfer pages share) and the Rust `fg bundle verify` agree on
# one corpus of valid and adversarial Git bundles, SHA-1 and SHA-256, with
# upstream Git as the validity oracle.
# Bead: frankengit-root-doctrine-x2mv.4.44 (acceptance 2)
#
# scripts/e2e/helpers/bundle_verify_differential.py builds the corpus with stock
# git (the pinned oracle when installed) plus byte-assembled packs, runs all
# three verifiers per bundle, and records one check per verdict, agreement and
# accepted-bundle facts. Checks the helper marks as a known divergence (pending
# the owner's ruling on the JavaScript engine, x2mv.4.14 D2/D10) are reported as
# unsupported while they still diverge, and fail once they stop diverging, so
# the list cannot go stale. Every other check must pass.
set -euo pipefail

E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_ROOT="$(cd "$E2E_ROOT/../.." && pwd)"
# shellcheck source=../../lib.sh
. "${FGE_LIB:-$E2E_ROOT/lib.sh}"

fge_init bundle-verify-differential
fge_kind e2e-binary
fge_context bead frankengit-root-doctrine-x2mv.4.44
fge_context evidence_class differential_two_implementations_plus_upstream_oracle
fge_context non_claim 'Verdict agreement on one bounded corpus; not a proof that either decoder is correct, and accepted bundles are compared by references, head and object count, not by every reported field.'

fge_phase setup
FG_BIN="${FG_BIN:-}"
NODE="${FGE_NODE:-$(command -v node || true)}"
fge_assert_cmd BUNDLE-DIFF-001 'FG_BIN names a prebuilt fg binary' test -n "$FG_BIN"
[ -x "$FG_BIN" ] || fge_die 'FG_BIN must name a prebuilt executable'
fge_assert_cmd BUNDLE-DIFF-002 'a node executable runs the JavaScript verifier' test -n "$NODE"
fge_context fg_digest "$(fge_digest_file "$FG_BIN")"
fge_context node_version "$("$NODE" --version 2>&1)"
ORACLE_ROOT=${FGIT_ORACLE_ROOT:-$HOME/.cache/frankengit/git-oracle}
PINNED="$ORACLE_ROOT/installs/git-2.54.0"
GIT_ARGS=()
if [ -x "$PINNED/bin/git" ]; then
  GIT_ARGS=(--git-bin "$PINNED/bin" --git-exec-path "$PINNED/libexec/git-core")
else
  fge_note BUNDLE-DIFF-pinned "pinned oracle not installed at $PINNED; the host git is the oracle"
fi

fge_phase action
WORK="$(fge_tempdir bundle-verify-differential)"
SUMMARY="$WORK/summary.json"
fge_run_timeout 1800 campaign python3 "$E2E_ROOT/helpers/bundle_verify_differential.py" \
  --fg "$FG_BIN" --node "$NODE" --js-verifier "$REPO_ROOT/scripts/verify_git_bundle.mjs" \
  --summary "$SUMMARY" "${GIT_ARGS[@]}" || true
fge_assert_exit BUNDLE-DIFF-003 0 "$FGE_LAST_EXIT" 'the corpus was built, verified three ways, and summarized'

fge_phase assert
rows=$(python3 -c '
import json, sys
summary = json.load(open(sys.argv[1]))
print("versions\x1f" + summary.get("git", "unknown") + " / node " + summary.get("node", "unknown"))
for check, row in sorted(summary.get("checks", {}).items()):
    state = "true" if row["ok"] else "false"
    detail = row["detail"].replace("\x1f", " ").replace("\n", " / ")[:300]
    print("\x1f".join([check, state, row.get("known", ""), detail]))
' "$SUMMARY" 2>/dev/null || true)
[ -n "$rows" ] || fge_assert_eq BUNDLE-DIFF-summary present absent 'the summary is readable'
# Fields are joined by the unit separator: a tab is IFS whitespace and would collapse an empty column.
while IFS=$'\x1f' read -r check ok known detail; do
  if [ "$check" = versions ]; then
    fge_context oracle_and_node "$ok"
    continue
  fi
  if [ -n "$known" ] && [ "$ok" = false ]; then
    fge_unsupported "BUNDLE-DIFF-$check" "known divergence: $known ($detail)"
  elif [ -n "$known" ]; then
    fge_assert_eq "BUNDLE-DIFF-$check" 'still diverging' 'no longer diverging' "listed divergence resolved; remove it from the helper: $known"
  else
    fge_assert_eq "BUNDLE-DIFF-$check" true "$ok" "$check ($detail)"
  fi
done <<< "$rows"
fge_artifact "$SUMMARY" json

fge_phase teardown
