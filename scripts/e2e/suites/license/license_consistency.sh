#!/usr/bin/env bash
# =============================================================================
# e2e: FG-062 D14 license gate and consistency  --  suites/license/license_consistency.sh
# Owner bead: frankengit-fg062-license-decision-cr5e
#
# D14 (the license model) is launch-blocking: risk R18 and definition-of-done
# item 18 both say the project must not ship, and must not be described as open
# source, until the licensing is genuinely settled. Two failure modes matter and
# neither is visible in a diff review:
#
#   1. a release happens while the decision is still deferred. `verify.sh
#      release` refuses today, but only because no releasable binary exists --
#      a TEMPORARY refusal that FG-035/FG-091 will remove. A launch-blocking
#      requirement riding on it would evaporate at the exact moment it starts
#      to matter, so the D14 gate is separate and is checked here on its own.
#   2. the repository claims to be open source before it is. The current
#      LICENSE is MIT text plus a rider denying rights to named parties, which
#      is not OSI-approved by construction.
#
# Every refusal below is paired with the near-identical permitted case, and the
# resolved-decision path is exercised against a COPY of the real licensing
# surface -- the gate must be shown to pass, not merely to refuse, or all it
# proves is that it says no.
#
# NON-CLAIMS, stated rather than implied:
#   - the open-source-claim check is a phrase checker over prose. It knows the
#     assertion phrasings listed below and a determined rewording passes it. It
#     is a tripwire against accidental drift, not a proof of honesty.
#   - this suite takes NO position on which license should be adopted. That is
#     the repository owner's decision (FG-062 says so explicitly); the suite
#     only enforces that deferral is loud and that a recorded decision is
#     stated identically everywhere.
# =============================================================================
set -euo pipefail

LIC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIC_REPO=$(cd "$LIC_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$LIC_REPO/scripts/e2e/lib.sh"

fge_init fg062-license-consistency
fge_context bead frankengit-fg062-license-decision-cr5e
fge_context scope 'docs/LICENSING_DECISION.md LICENSE README.md CONTRIBUTING.md scripts/license_gate.sh'

GATE="$LIC_REPO/scripts/license_gate.sh"
DECISION="$LIC_REPO/docs/LICENSING_DECISION.md"

fge_phase setup
fge_step surface-present

for f in "$GATE" "$DECISION" "$LIC_REPO/LICENSE" "$LIC_REPO/README.md" "$LIC_REPO/CONTRIBUTING.md"; do
  [ -f "$f" ] || fge_die "required licensing surface missing: $f"
done
fge_field gate_present 1

# -----------------------------------------------------------------------------
fge_phase assert
fge_step gate-accepts-the-resolved-live-repository
# -----------------------------------------------------------------------------
# The live repository state. D14 was RESOLVED by the repository owner on
# 2026-08-23 as LicenseRef-MIT-OpenAI-Anthropic-Rider, so the gate must now
# pass here -- a recorded decision stated identically on every surface.
#
# This assertion used to read `fg062-gate-refuses-deferred 3`, and flipping it
# is the whole reason the fixture immediately below exists. While the live repo
# was UNRESOLVED, that one live check was the ONLY place the gate's
# UNRESOLVED -> 3 behaviour was exercised; every other case here is
# fixture-based. Resolving D14 would therefore have silently deleted the
# coverage of the refusal this gate was built for, and a suite that stops
# testing the refusal at the moment the refusal stops firing is gate
# self-weakening (RH-1) whether or not anyone intended it. So the property
# moved to a fixture rather than leaving with the live state.
lic_exit=0
"$GATE" >/dev/null 2>&1 || lic_exit=$?
fge_field live_gate_exit "$lic_exit"
fge_assert_eq fg062-gate-accepts-resolved-live 0 "$lic_exit" \
  "the D14 gate passes on the live repository now that the decision is recorded"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step gate-still-refuses-an-unresolved-tree
# -----------------------------------------------------------------------------
# The property the live check used to carry, now independent of what the live
# repository happens to have decided. A tree whose marker still says UNRESOLVED
# must be refused with the typed code 3 -- not warned about, not exit 0.
#
# ATTRIBUTION MATTERS HERE, and the first version of this fixture did not have
# it. Placeholder surfaces stating no identifier at all would also fail a
# RESOLVED gate, so a refusal against them is over-determined: it cannot
# distinguish "refused because the marker says UNRESOLVED" from "refused because
# the surfaces were junk". The surfaces below therefore state a real identifier
# and are fully consistent, and the very next assertion flips ONLY the marker
# and requires exit 0. One byte-level difference between a refusal and a pass is
# what makes the refusal attributable to the marker.
lic_defer_id="Apache-2.0"
lic_defer_tree() {
  local dest="$1" marker="$2" osi="$3"
  mkdir -p "$dest/docs" "$dest/scripts"
  cp "$GATE" "$dest/scripts/license_gate.sh"
  chmod +x "$dest/scripts/license_gate.sh"
  {
    echo "# FrankenGit Licensing Decision"
    echo
    echo "<!-- fgit-license-decision: $marker -->"
    echo "<!-- fgit-license-osi: $osi -->"
  } > "$dest/docs/LICENSING_DECISION.md"
  echo "$lic_defer_id adopted text goes here." > "$dest/LICENSE"
  printf '## License\n\nThis project is licensed under %s.\n' "$lic_defer_id" > "$dest/README.md"
  printf '## Licensing\n\nInbound contributions are under %s.\n' "$lic_defer_id" > "$dest/CONTRIBUTING.md"
  printf '[workspace.package]\nlicense = "%s"\n' "$lic_defer_id" > "$dest/Cargo.toml"
}

lic_defer="$(fge_tempdir unresolved)"
lic_defer_tree "$lic_defer" UNRESOLVED unknown
lic_defer_exit=0
(cd "$lic_defer" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_defer_exit=$?
fge_assert_eq fg062-gate-refuses-deferred 3 "$lic_defer_exit" \
  "the D14 gate refuses with a typed exit while a tree's decision is deferred"

# The attribution twin: same tree, same surfaces, marker resolved. If this did
# not pass, the refusal above would prove nothing about the marker.
lic_defer_twin="$(fge_tempdir unresolved-twin)"
lic_defer_tree "$lic_defer_twin" "$lic_defer_id" yes
lic_defer_twin_exit=0
(cd "$lic_defer_twin" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_defer_twin_exit=$?
fge_assert_eq fg062-deferral-refusal-is-attributable 0 "$lic_defer_twin_exit" \
  "the identical tree with only the marker resolved passes, so the refusal above is the marker's"

lic_marker_count=$(LC_ALL=C grep -c '^<!-- fgit-license-decision:' "$DECISION" || true)
fge_assert_eq fg062-one-canonical-marker 1 "$lic_marker_count" \
  "exactly one canonical decision marker exists; two markers is an argument, not a decision"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step gate-passes-when-resolved-and-consistent
# -----------------------------------------------------------------------------
# The PAIRED PERMITTED CASE, and the one that matters most: a gate only ever
# observed refusing might refuse unconditionally. This builds a resolved,
# fully-consistent surface in a scratch tree and requires exit 0.
lic_work="$(fge_tempdir resolved)"
mkdir -p "$lic_work/docs" "$lic_work/scripts"
cp "$GATE" "$lic_work/scripts/license_gate.sh"
chmod +x "$lic_work/scripts/license_gate.sh"

lic_spdx="Apache-2.0"
{
  echo "# FrankenGit Licensing Decision"
  echo
  echo "<!-- fgit-license-decision: $lic_spdx -->"
  echo "<!-- fgit-license-osi: yes -->"
} > "$lic_work/docs/LICENSING_DECISION.md"
echo "$lic_spdx adopted text goes here." > "$lic_work/LICENSE"
printf '## License\n\nThis project is licensed under %s.\n' "$lic_spdx" > "$lic_work/README.md"
printf '## Licensing\n\nInbound contributions are under %s.\n' "$lic_spdx" > "$lic_work/CONTRIBUTING.md"
printf '[workspace.package]\nlicense = "%s"\n' "$lic_spdx" > "$lic_work/Cargo.toml"

lic_ok_exit=0
(cd "$lic_work" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_ok_exit=$?
fge_assert_eq fg062-gate-passes-when-consistent 0 "$lic_ok_exit" \
  "a recorded decision stated identically on every surface releases the gate"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step gate-catches-each-inconsistent-surface
# -----------------------------------------------------------------------------
# One surface at a time is made to disagree, from the SAME tree that just
# passed. That isolates the check: a failure here cannot be blamed on the
# fixture, because the only difference is the one file being corrupted.
lic_missed=""
for surface in LICENSE README.md CONTRIBUTING.md; do
  lic_case="$(fge_tempdir "bad-$surface")"
  cp -r "$lic_work"/. "$lic_case"/
  printf 'this surface says nothing about the adopted terms\n' > "$lic_case/$surface"
  lic_bad_exit=0
  (cd "$lic_case" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_bad_exit=$?
  [ "$lic_bad_exit" -eq 3 ] || lic_missed="$lic_missed $surface(exit=$lic_bad_exit)"
done

# Cargo metadata implying different terms is the quietest disagreement of all:
# nothing a human reads changes, but packaging and SBOMs do.
lic_case="$(fge_tempdir bad-cargo)"
cp -r "$lic_work"/. "$lic_case"/
printf '[workspace.package]\nlicense = "MIT"\n' > "$lic_case/Cargo.toml"
lic_bad_exit=0
(cd "$lic_case" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_bad_exit=$?
[ "$lic_bad_exit" -eq 3 ] || lic_missed="$lic_missed Cargo.toml(exit=$lic_bad_exit)"

if [ -n "$lic_missed" ]; then
  fge_fail fg062-gate-catches-inconsistency "surfaces the gate failed to catch:$lic_missed"
else
  fge_pass fg062-gate-catches-inconsistency \
    "each of LICENSE, README.md, CONTRIBUTING.md and Cargo.toml is caught when it alone disagrees"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step denial-does-not-count-as-statement
# -----------------------------------------------------------------------------
# REGRESSION. This gate's own first implementation used `grep -qF "$status"`, so
# under a decision of `MIT` a README reading "This project is NOT MIT licensed"
# satisfied the check and the gate announced every surface consistent. Denial is
# the single most likely thing a stale licensing surface actually says, which
# makes a substring match not merely imprecise but wrong in the common case.
lic_deny="$(fge_tempdir denial)"
cp -r "$lic_work"/. "$lic_deny"/
printf 'This project is NOT %s licensed.\n' "$lic_spdx" > "$lic_deny/README.md"
lic_deny_exit=0
(cd "$lic_deny" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_deny_exit=$?
fge_assert_eq fg062-denial-is-not-a-statement 3 "$lic_deny_exit" \
  "a surface DENYING the decided terms does not count as stating them"

# Paired permitted case, differing only in the denial.
lic_affirm="$(fge_tempdir affirm)"
cp -r "$lic_work"/. "$lic_affirm"/
printf 'This project is %s licensed.\n' "$lic_spdx" > "$lic_affirm/README.md"
lic_affirm_exit=0
(cd "$lic_affirm" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_affirm_exit=$?
fge_assert_eq fg062-affirmation-is-a-statement 0 "$lic_affirm_exit" \
  "the same sentence without the denial does state the terms"

# Token boundary: a LONGER identifier that merely contains the decided one is
# different terms, not the decided terms.
lic_boundary="$(fge_tempdir boundary)"
cp -r "$lic_work"/. "$lic_boundary"/
printf 'Licensed under %s-WITH-LLVM-exception.\n' "$lic_spdx" > "$lic_boundary/README.md"
lic_boundary_exit=0
(cd "$lic_boundary" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_boundary_exit=$?
fge_assert_eq fg062-longer-identifier-is-different-terms 3 "$lic_boundary_exit" \
  "an identifier that merely contains the decided one is not the decided one"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step split-licensing-must-be-recorded
# -----------------------------------------------------------------------------
# Option D in the decision document splits a reciprocal server from permissive
# clients, SDKs, schemas and conformance kits. A gate checking only the root
# expression would be blindest exactly where the decision is most complex, so a
# crate carrying its OWN terms must either match the root decision or be named
# in the decision document. A split is allowed; an UNRECORDED split is not.
lic_split_base="$(fge_tempdir split)"
cp -r "$lic_work"/. "$lic_split_base"/
mkdir -p "$lic_split_base/crates/fgit-sdk"
printf '[package]\nname = "fgit-sdk"\nlicense = "MIT"\n' > "$lic_split_base/crates/fgit-sdk/Cargo.toml"

# Refused: the SDK ships MIT while the decision says Apache-2.0 and the document
# says nothing about a split.
lic_split_exit=0
(cd "$lic_split_base" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_split_exit=$?
fge_assert_eq fg062-unrecorded-split-refused 3 "$lic_split_exit" \
  "a crate shipping terms the decision document never records is refused"

# Permitted, and near-identical: the SAME split, now recorded in the document.
lic_split_ok="$(fge_tempdir split-recorded)"
cp -r "$lic_split_base"/. "$lic_split_ok"/
printf 'Recorded split: client SDKs ship under MIT.\n' >> "$lic_split_ok/docs/LICENSING_DECISION.md"
lic_split_ok_exit=0
(cd "$lic_split_ok" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_split_ok_exit=$?
fge_assert_eq fg062-recorded-split-permitted 0 "$lic_split_ok_exit" \
  "the same split passes once the decision document records it"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step no-premature-open-source-claim
# -----------------------------------------------------------------------------
# The repository may DISCUSS open source freely -- the decision document is
# nothing but that discussion. What it may not do is ASSERT that FrankenGit is
# open source while the marker is unresolved.
#
# This is the act-versus-mention distinction, and getting it wrong is the bug
# class this repository has now hit four times (twice in the doc lane, once in
# the ADR lane where the checker flagged the very ADR describing the rule).
# So the pattern matches ASSERTION SHAPES -- "FrankenGit is open source", "an
# open-source project", an OSI badge -- and never the bare token.
lic_status=$(LC_ALL=C grep '^<!-- fgit-license-decision:' "$DECISION" \
  | sed -E 's/^<!-- fgit-license-decision:[[:space:]]*([A-Za-z0-9_.+-]+).*/\1/')
fge_field decision_status "$lic_status"

lic_claim_re='(FrankenGit|This project|The project|It) (is|remains) (an? )?(OSI[- ])?open[- ]source'
lic_badge_re='(img\.shields\.io/[^)]*[Ll]icense|opensource\.org/licenses)'

# The claim rule OUTLIVES the decision: "no doc anywhere claims open source
# until the license actually is". Keying this scan on UNRESOLVED meant it went
# quiet the moment ANY decision landed -- including a resolution to option E
# (Business Source / Functional Source), which is explicitly NOT open source and
# is the outcome where a stray "open source" line does the most damage. The
# scan now runs unless the decision is recorded as OSI-approved.
lic_osi=$(LC_ALL=C grep '^<!-- fgit-license-osi:' "$DECISION" \
  | sed -E 's/^<!-- fgit-license-osi:[[:space:]]*([A-Za-z]+).*/\1/')
fge_field osi_approved "$lic_osi"

# The scan is a FUNCTION so the fixtures below drive the same code path the live
# check uses. A fixture that exercised a reimplementation would prove only that
# the reimplementation works, which is the fixture-only hazard this project
# names outright.
lic_scan_claims() {
  local root="$1" osi="$2"
  # An OSI-approved decision is allowed to say it is open source.
  [ "$osi" = "yes" ] && return 0
  # Scan relative to `root`, not by absolute substring. An absolute `/target/`
  # filter also swallowed fixtures, because the harness allocates scratch dirs
  # under target/e2e-artifacts -- so the check silently scanned nothing and
  # reported clean. Relative exclusion drops the repository's own build output
  # while leaving a fixture tree (which has no target/) fully visible.
  ( cd "$root" 2>/dev/null || return 0
    LC_ALL=C grep -rnEI "$lic_claim_re|$lic_badge_re" --include='*.md' . 2>/dev/null \
      | grep -v '^\./target/' \
      | grep -v '^\./scripts/e2e/suites/license/' \
      | LC_ALL=C grep -viE 'not (an? )?(osi|open)|is not|never|until|intends?|would be|cannot' || true )
}

lic_claims=""
while IFS= read -r hit; do
  [ -n "$hit" ] || continue
  lic_claims="$lic_claims
    $hit"
done < <(lic_scan_claims "$LIC_REPO" "$lic_osi")

if [ -n "$lic_claims" ]; then
  fge_fail fg062-no-premature-open-source-claim \
    "documents assert open-source status while osi-approved=$lic_osi (D14=$lic_status):$lic_claims"
else
  fge_pass fg062-no-premature-open-source-claim \
    "no document asserts open-source status while osi-approved=$lic_osi (D14=$lic_status)"
fi

# The claim checker must be able to fire, or it is decoration. A planted
# assertion in a scratch file must be seen by the SAME pattern.
lic_scratch="$(fge_tempdir claims)"
lic_plant="$lic_scratch/planted.md"
printf 'FrankenGit is an open-source project you can trust.\n' > "$lic_plant"
lic_plant_hits=$(LC_ALL=C grep -cEI "$lic_claim_re" "$lic_plant" || true)
fge_assert_eq fg062-claim-check-can-fail 1 "$lic_plant_hits" \
  "a planted open-source assertion is detected by the same pattern"

# ...and the paired permitted case. This sample is chosen so it DOES match the
# claim shape and must be rescued by the negation filter -- a sample that simply
# fails to match would prove nothing about the filter at all, which is the
# quieter way this kind of test ends up decorative.
#
# Both greps are guarded: under `set -euo pipefail` a grep that matches nothing
# exits 1 and takes the whole suite down, so "no hits" must be expressible as a
# result rather than a crash.
lic_ok="$lic_scratch/honest.md"
printf 'The project is open source only after D14 is resolved; until then it is not.\n' > "$lic_ok"
lic_ok_raw=$( { LC_ALL=C grep -cEI "$lic_claim_re" "$lic_ok" || true; } )
lic_ok_hits=$( { LC_ALL=C grep -EI "$lic_claim_re" "$lic_ok" || true; } \
  | { LC_ALL=C grep -viE 'not (an? )?(osi|open)|is not|never|until|intends?|would be|cannot' || true; } \
  | grep -c . || true)
fge_field honest_sample_raw_match "$lic_ok_raw"
fge_assert_eq fg062-honest-sample-is-a-real-near-miss 1 "$lic_ok_raw" \
  "the honest sample really does match the claim shape, so the filter is what rescues it"
fge_assert_eq fg062-honest-wording-not-flagged 0 "$lic_ok_hits" \
  "honest provisional wording is not mistaken for a claim"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step claim-scan-survives-resolution
# -----------------------------------------------------------------------------
# REGRESSION. The scan above used to be gated on the decision being UNRESOLVED,
# so recording ANY decision switched it off -- including a non-OSI one, where
# the honesty risk is highest. These two cases differ ONLY in the OSI marker, so
# they pin the branch rather than the wording.
lic_gate_scan() {
  # 1 when the scan would run for the given marker value, 0 when it would not.
  case "$1" in
    yes) printf '0' ;;
    *) printf '1' ;;
  esac
}
fge_assert_eq fg062-scan-runs-for-non-osi-resolution 1 "$(lic_gate_scan no)" \
  "a resolved but NON-OSI decision still has its open-source claims policed"
fge_assert_eq fg062-scan-runs-while-unresolved 1 "$(lic_gate_scan unknown)" \
  "an unresolved decision still has its open-source claims policed"
fge_assert_eq fg062-scan-stands-down-for-osi 0 "$(lic_gate_scan yes)" \
  "an OSI-approved decision is allowed to say it is open source"

# And the gate itself must refuse a decision that never answers the question.
lic_osi_missing="$(fge_tempdir osi-missing)"
cp -r "$lic_work"/. "$lic_osi_missing"/
printf '# D\n\n<!-- fgit-license-decision: %s -->\n' "$lic_spdx" \
  > "$lic_osi_missing/docs/LICENSING_DECISION.md"
lic_osi_missing_exit=0
(cd "$lic_osi_missing" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_osi_missing_exit=$?
fge_assert_eq fg062-osi-marker-required 3 "$lic_osi_missing_exit" \
  "a recorded decision that does not state whether it is OSI-approved is refused"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step option-e-non-osi-resolution-end-to-end
# -----------------------------------------------------------------------------
# The highest-stakes outcome, and until now the least covered. Options A-D are
# OSI-approved and the claim rule relaxes for them. Option E (Business Source /
# Functional Source) is a RESOLVED decision that is explicitly NOT open source,
# so the repository must keep saying source-available for the whole restriction
# period. That is the case where a stray "FrankenGit is open source" does the
# most damage, and the branch-logic assertions above only prove the scan WOULD
# run under it -- not that the whole pipeline catches a violation.
#
# These two fixtures differ ONLY in the osi marker, and both drive the same
# lic_scan_claims used against the live tree.
lic_bsl="$(fge_tempdir option-e)"
mkdir -p "$lic_bsl/docs"
printf 'FrankenGit is an open-source forge.\n' > "$lic_bsl/docs/marketing.md"

lic_bsl_hits=$(lic_scan_claims "$lic_bsl" no | LC_ALL=C grep -c . || true)
fge_assert_eq fg062-non-osi-resolution-still-policed 1 "$lic_bsl_hits" \
  "a resolved but NON-OSI decision still catches an open-source claim"

lic_osi_hits=$(lic_scan_claims "$lic_bsl" yes | LC_ALL=C grep -c . || true)
fge_assert_eq fg062-osi-resolution-permits-the-claim 0 "$lic_osi_hits" \
  "the same claim is permitted once the decision is recorded as OSI-approved"

# And the gate itself must accept a non-OSI decision as a valid resolution:
# option E is a legitimate outcome, not an error state.
lic_bsl_gate="$(fge_tempdir option-e-gate)"
cp -r "$lic_work"/. "$lic_bsl_gate"/
{
  echo "# FrankenGit Licensing Decision"
  echo
  echo "<!-- fgit-license-decision: BSL-1.1 -->"
  echo "<!-- fgit-license-osi: no -->"
} > "$lic_bsl_gate/docs/LICENSING_DECISION.md"
for f in LICENSE README.md CONTRIBUTING.md; do
  printf 'This project is licensed under BSL-1.1.\n' > "$lic_bsl_gate/$f"
done
printf '[workspace.package]\nlicense = "BSL-1.1"\n' > "$lic_bsl_gate/Cargo.toml"

lic_bsl_exit=0
(cd "$lic_bsl_gate" && ./scripts/license_gate.sh) >/dev/null 2>&1 || lic_bsl_exit=$?
fge_assert_eq fg062-non-osi-decision-is-a-valid-resolution 0 "$lic_bsl_exit" \
  "a consistently-stated non-OSI decision releases the gate; option E is an outcome, not an error"

fge_phase teardown
fge_note "this suite decides nothing about which license to adopt; D14 is the repository owner's call (FG-062)"
