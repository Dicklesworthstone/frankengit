#!/usr/bin/env bash
# ./scripts/verify.sh tier-a (frankengit-root-doctrine-x2mv.4.60).
#
# Builds fg once, runs every suite that owns a row of
# registries/compatibility_tiers.tsv against the pinned upstream Git oracle,
# and writes tier_a_receipt.json: one status per declared row, bound to the
# source revision, the fg binary digest, the registry digest and the oracle's
# install receipt. FG-090 turns that receipt into public compatibility wording.
#
# Exit 0: every declared row passed.
# Exit 3: the pinned oracle is unavailable, so no row ran (typed, never a pass).
# Exit 1: a row failed, or produced no result.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
readonly REGISTRY=registries/compatibility_tiers.tsv
readonly ORACLE=scripts/e2e/oracle/oracle.sh
readonly ORACLE_ROOT="${FGIT_ORACLE_ROOT:-${HOME}/.cache/frankengit/git-oracle}"

pins=$(awk -F'\t' '!/^#/ && $1 != "id" && NF == 11 { print $9 }' "$REGISTRY" | LC_ALL=C sort -u)
[ "$(printf '%s\n' "$pins" | grep -c .)" -eq 1 ] || {
  printf 'verify: tier-a: %s must name exactly one oracle pin, found: %s\n' "$REGISTRY" "$pins" >&2
  exit 1
}
if ! "$ORACLE" verify "$pins" >&2; then
  printf 'verify: tier-a: pinned oracle %s is unavailable; build it with %s build %s.\n' "$pins" "$ORACLE" "$pins" >&2
  printf 'This is a typed unavailable result, not a passing gate.\n' >&2
  exit 3
fi

printf '==> Building the release fg binary once for the Tier A rows\n' >&2
cargo build --release --locked -p fgit-cli --bin fg
target_dir=$(cargo metadata --locked --no-deps --format-version 1 |
  grep -o '"target_directory":"[^"]*"' | cut -d'"' -f4)
fg="$target_dir/release/fg"
[ -x "$fg" ] || { printf 'verify: tier-a: no fg binary at %s\n' "$fg" >&2; exit 1; }

out="${FGIT_TIER_A_OUT:-$target_dir/tier-a/$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$out"
mapfile -t suites < <(awk -F'\t' '!/^#/ && $1 != "id" && NF == 11 { print $10 }' "$REGISTRY" | LC_ALL=C sort -u)
printf '==> Running %d Tier A suite(s) against %s with %s\n' "${#suites[@]}" "$pins" "$fg" >&2
run_status=0
FG_BIN="$fg" FGIT_ORACLE_PIN="$pins" "$ROOT/scripts/e2e/run_all.sh" --out "$out/run" \
  --timeout "${FGE_TIER_A_TIMEOUT:-7200}" "${suites[@]}" || run_status=$?

receipt_status=0
python3 -I scripts/e2e/helpers/tier_a_receipt.py "$REGISTRY" "$out/run/receipt.ndjson" "$fg" \
  "$ORACLE_ROOT/installs/$pins/receipt.tsv" > "$out/tier_a_receipt.json" || receipt_status=$?
printf '==> Tier A receipt: %s (run_all exit %s)\n' "$out/tier_a_receipt.json" "$run_status" >&2
python3 -I -c 'import json, sys
receipt = json.load(open(sys.argv[1]))
print("tier-a: verdict=%s %s" % (receipt["verdict"], " ".join("%s=%d" % kv for kv in sorted(receipt["counts"].items()))))
for row in receipt["rows"]:
    if row["status"] != "pass":
        print("  %-24s %-12s %s" % (row["id"], row["status"], row["detail"]))' "$out/tier_a_receipt.json" >&2
exit "$receipt_status"
