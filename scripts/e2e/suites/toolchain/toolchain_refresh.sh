#!/usr/bin/env bash
# =============================================================================
# e2e: FG-068 toolchain-refresh lane  --  suites/toolchain/toolchain_refresh.sh
# Owner bead: frankengit-fg068-toolchain-refresh-x5y3
#
# ADR-0010 (D15, accepted 2026-08-21) sets the cadence policy for advancing the
# dated nightly. `scripts/toolchain_refresh.sh` is the lane that EXECUTES that
# policy, and this suite is what keeps the lane honest. Three failure modes
# matter, and none is visible in a diff review:
#
#   1. the lane emits an evidence pack for a candidate that regressed a gate,
#      which would authorise exactly the bump the policy exists to stop;
#   2. the lane attributes gate results to a toolchain that did not produce
#      them, which is the most damaging thing an evidence artifact can do
#      because it is indistinguishable from a real one;
#   3. a pin moves with no pack at all, which makes the whole policy advisory.
#
# Every refusal below is paired with the near-identical permitted case, because
# a lane observed only refusing might refuse unconditionally, and a lane
# observed only passing has never been shown to have a floor.
#
# NON-CLAIMS, stated rather than implied:
#   - the gate runner is INJECTED here. This suite proves the lane's logic
#     (fingerprinting, identity, comparison, refusal, pack emission). It proves
#     nothing about docs/constitution/fast themselves, which have their own
#     lanes, and a green run here never means "the toolchain is good".
#   - no toolchain is installed and no candidate other than the active one is
#     really evaluated. Installing a nightly is a networked, shared-machine
#     action outside this suite's remit; the identity guard is exercised by
#     naming a candidate that is deliberately NOT active.
# =============================================================================
set -euo pipefail

TC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TC_REPO=$(cd "$TC_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$TC_REPO/scripts/e2e/lib.sh"

fge_init fg068-toolchain-refresh
fge_context bead frankengit-fg068-toolchain-refresh-x5y3
fge_context scope 'scripts/toolchain_refresh.sh rust-toolchain.toml'

LANE="$TC_REPO/scripts/toolchain_refresh.sh"
PIN_FILE="$TC_REPO/rust-toolchain.toml"

fge_phase setup
fge_step lane-present

[ -f "$LANE" ] || fge_die "the toolchain-refresh lane is missing: $LANE"
[ -f "$PIN_FILE" ] || fge_die "rust-toolchain.toml is missing"

tc_pin=$(LC_ALL=C grep -m1 -E '^channel[[:space:]]*=' "$PIN_FILE" |
  sed -E 's/^channel[[:space:]]*=[[:space:]]*"([^"]*)".*/\1/')
fge_field current_pin "$tc_pin"

# The lane's whole premise is a DATED pin; if the repository ever floated the
# channel, every assertion below would be testing a situation that cannot occur.
tc_dated=0
case "$tc_pin" in
  nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) tc_dated=1 ;;
  *) tc_dated=0 ;;
esac
fge_assert_eq fg068-pin-is-dated 1 "$tc_dated" \
  "rust-toolchain.toml pins a dated nightly, as AGENTS.md 3.4 requires"

tc_work="$(fge_tempdir lane)"
tc_pass="$tc_work/gate-pass.sh"
tc_fail="$tc_work/gate-fail.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tc_pass"
printf '#!/usr/bin/env bash\n[ "$1" = constitution ] && exit 1\nexit 0\n' > "$tc_fail"
chmod +x "$tc_pass" "$tc_fail"

# -----------------------------------------------------------------------------
fge_phase action
fge_step dry-run-against-the-current-pin
# -----------------------------------------------------------------------------
# The no-op pass the bead's test plan calls for: evaluating the pin the
# repository already uses must succeed and must produce a pack.
tc_ok_out="$tc_work/ok"
tc_ok_exit=0
"$LANE" --dry-run --gate-runner "$tc_pass" --out "$tc_ok_out" >/dev/null 2>&1 || tc_ok_exit=$?
fge_assert_eq fg068-dry-run-passes 0 "$tc_ok_exit" \
  "a dry run against the current pin with passing gates is a no-op pass"

tc_pack="$tc_ok_out/$tc_pin.pack"
fge_assert_file fg068-pack-written "$tc_pack" \
  "the passing run writes an evidence pack named for the candidate"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step pack-records-what-a-reader-needs
# -----------------------------------------------------------------------------
# A pack that omits the compiler identity cannot support a reproducibility
# claim, and one that omits its own limits invites over-reading.
tc_missing=""
for field in schema current_pin candidate rustc_release rustc_commit rustc_host \
  llvm_version gate_runner toolchain_identity not_covered; do
  LC_ALL=C grep -qE "^$field	" "$tc_pack" || tc_missing="$tc_missing $field"
done
if [ -n "$tc_missing" ]; then
  fge_fail fg068-pack-is-complete "evidence pack is missing fields:$tc_missing"
else
  fge_pass fg068-pack-is-complete \
    "the pack records schema, pin, candidate, compiler fingerprint, identity and its own limits"
fi

# The pack must say what it did NOT measure. This lane runs no benchmarks, and
# a reader who assumes otherwise would treat it as a performance clearance.
fge_assert_contains fg068-pack-states-perf-non-claim "$(<"$tc_pack")" \
  'no benchmark delta was measured' \
  'the pack states that no performance delta was measured'

# -----------------------------------------------------------------------------
fge_phase assert
fge_step seeded-regression-refuses-and-emits-nothing
# -----------------------------------------------------------------------------
# The acceptance line: a seeded regression must refuse the bump with typed
# evidence. Identical to the passing case except the gate runner.
tc_bad_out="$tc_work/bad"
tc_bad_exit=0
"$LANE" --dry-run --gate-runner "$tc_fail" --out "$tc_bad_out" >/dev/null 2>&1 || tc_bad_exit=$?
fge_assert_eq fg068-regression-refuses 3 "$tc_bad_exit" \
  "a seeded gate regression refuses the advancement with a typed exit"

# ...and refuses SILENTLY in the artifact sense: no pack at all. A pack that
# recorded its own failure could still be cited by a bump, and a reader would
# reasonably assume that citing evidence meant being authorised by it.
tc_bad_packs=$(find "$tc_bad_out" -name '*.pack' 2>/dev/null | LC_ALL=C grep -c . || true)
fge_assert_eq fg068-regression-writes-no-pack 0 "$tc_bad_packs" \
  "a refused candidate leaves no evidence pack that a bump could cite"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step results-are-not-attributed-to-the-wrong-compiler
# -----------------------------------------------------------------------------
# Naming a candidate that is not the active toolchain must refuse BEFORE any
# gate runs, because the alternative is a pack describing a compiler that never
# produced the results in it.
tc_wrong_out="$tc_work/wrong"
tc_wrong_exit=0
"$LANE" --candidate nightly-2099-01-01 --gate-runner "$tc_pass" --out "$tc_wrong_out" \
  >/dev/null 2>&1 || tc_wrong_exit=$?
fge_assert_eq fg068-identity-mismatch-refuses 3 "$tc_wrong_exit" \
  "a candidate that is not the active toolchain is refused before any gate runs"

tc_wrong_packs=$(find "$tc_wrong_out" -name '*.pack' 2>/dev/null | LC_ALL=C grep -c . || true)
fge_assert_eq fg068-identity-mismatch-writes-no-pack 0 "$tc_wrong_packs" \
  "a misattributed candidate leaves no evidence pack"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step a-gate-that-never-answers-is-inconclusive-not-passing
# -----------------------------------------------------------------------------
# Found by running the lane against the real verify.sh on this host: 40+ cargo
# processes were live and the gate sat queued behind the shared build lock. An
# evidence lane that can hang produces neither evidence nor a refusal, so nobody
# learns anything and the run merely looks slow -- the worst outcome available
# to it.
#
# "The gate said no" and "the gate never answered" are kept distinct on purpose.
# Collapsing them would send a reader chasing a toolchain regression that was
# really lock contention. Both block the pack; only an affirmative pass
# authorises a bump.
tc_hang="$tc_work/gate-hang.sh"
printf '#!/usr/bin/env bash\nsleep 30\n' > "$tc_hang"
chmod +x "$tc_hang"

tc_hang_out="$tc_work/hang"
tc_hang_exit=0
"$LANE" --dry-run --gate-runner "$tc_hang" --gate-timeout 2 --out "$tc_hang_out" \
  >"$tc_work/hang.log" 2>&1 || tc_hang_exit=$?
fge_assert_eq fg068-hanging-gate-refuses 3 "$tc_hang_exit" \
  "a gate that exceeds its ceiling refuses rather than hanging the lane"

tc_hang_packs=$(find "$tc_hang_out" -name '*.pack' 2>/dev/null | LC_ALL=C grep -c . || true)
fge_assert_eq fg068-hanging-gate-writes-no-pack 0 "$tc_hang_packs" \
  "an inconclusive candidate leaves no evidence pack"

fge_assert_contains fg068-inconclusive-is-not-a-regression "$(<"$tc_work/hang.log")" \
  'This is NOT a regression' \
  'a timed-out gate is reported as inconclusive, distinctly from a regression'

# -----------------------------------------------------------------------------
fge_phase assert
fge_step pin-bump-without-evidence-is-flagged
# -----------------------------------------------------------------------------
# The checker hook. Paired directly: the same pin is refused against an empty
# evidence directory and accepted against the one the passing run just wrote.
tc_hook_bad=0
"$LANE" --verify-bump --out "$tc_work/empty" >/dev/null 2>&1 || tc_hook_bad=$?
fge_assert_eq fg068-unevidenced-pin-flagged 3 "$tc_hook_bad" \
  "a checked-in pin with no evidence pack is flagged"

tc_hook_ok=0
"$LANE" --verify-bump --out "$tc_ok_out" >/dev/null 2>&1 || tc_hook_ok=$?
fge_assert_eq fg068-evidenced-pin-accepted 0 "$tc_hook_ok" \
  "the same pin backed by its pack is accepted"

# A pack for a DIFFERENT candidate must not satisfy the hook, or the check
# degrades into "some pack exists".
tc_decoy="$tc_work/decoy"
mkdir -p "$tc_decoy"
sed 's/^candidate	.*/candidate	nightly-2099-01-01/' "$tc_pack" > "$tc_decoy/$tc_pin.pack"
tc_hook_decoy=0
"$LANE" --verify-bump --out "$tc_decoy" >/dev/null 2>&1 || tc_hook_decoy=$?
fge_assert_eq fg068-decoy-pack-rejected 3 "$tc_hook_decoy" \
  "a pack naming a different candidate does not satisfy the hook"

fge_phase teardown
fge_note "the gate runner is injected: this suite proves the lane's logic, never that any gate passes"
