#!/usr/bin/env bash
# =============================================================================
# e2e: FG-061 ADR contract checks  --  suites/adr/adr_contracts.sh
# Owner bead: frankengit-fg061-adr-sweep-hx4o
#
# The ADRs in docs/ are load-bearing: each one gates implementation beads that
# cannot start until the decision is made. That makes two failure modes worth
# detecting mechanically, because neither is visible in a diff review:
#
#   1. an ADR drifts into contradicting a settled constitutional position
#      (a first-party unsafe exception, a second runtime, a local path
#      admission, a projection treated as authority, a canvas or terminal
#      primary UI, or dropping the TypeScript/React no-loss guarantee);
#   2. an ADR claims a status it has not earned, or binds a bead that does
#      not exist, which turns a decision record into unattached prose.
#
# Every planted-contradiction check below is paired with a proof that the
# checker can actually fail, because a gate nobody has watched fail is not
# known to work.
#
# NON-CLAIM, stated here rather than implied: this is a phrase checker over
# prose. It detects the drift phrasings it knows, and a determined rewording
# will pass it. It is a tripwire against accidental drift, not a proof that the
# ADRs are consistent with the constitution -- that judgement is the reviewer's
# and the decision owner's, and the bead says so.
# =============================================================================
set -euo pipefail

ADR_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ADR_REPO=$(cd "$ADR_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$ADR_REPO/scripts/e2e/lib.sh"

fge_init fg061-adr-contracts
fge_context bead frankengit-fg061-adr-sweep-hx4o
fge_context scope docs/ADR-*.md

ADR_DOCS="$ADR_REPO/docs"

fge_phase setup
ADR_WORK=$(fge_tempdir adr-contracts)

adr_files=()
while IFS= read -r path; do
  adr_files+=("$path")
done < <(find "$ADR_DOCS" -maxdepth 1 -name 'ADR-*.md' | LC_ALL=C sort)
fge_field adr_count "${#adr_files[@]}"

# -----------------------------------------------------------------------------
# Forbidden positions. Each is a phrase an ADR would only contain if it had
# drifted into contradicting a settled rule. Matched case-insensitively.
# -----------------------------------------------------------------------------
adr_contradiction() {
  local file=$1 lowered
  lowered=$(LC_ALL=C tr 'A-Z' 'a-z' <"$file")
  # A first-party unsafe exception. The pattern matches ADOPTION phrasing, not
  # the bare token: ADR-0015 exists to describe this exception and refuse it, so
  # a substring scan for the token flags the document defending the rule. That
  # is the same mistake as scanning rendered HTML for 'javascript:' and hitting
  # escaped text -- a checker must distinguish the act from the mention.
  case $lowered in
    *'carries #[allow(unsafe_code)]'* | *'add #[allow(unsafe_code)]'* | \
      *'adds #[allow(unsafe_code)]'* | *'unsafe exception is permitted'* | \
      *'grant a first-party unsafe exception'* | *'we allow unsafe'*)
      printf 'first-party unsafe exception'
      return 0
      ;;
  esac
  # A second async runtime admitted into production.
  case $lowered in
    *'tokio is permitted'* | *'admit tokio'* | *'second runtime is acceptable'*)
      printf 'second runtime admitted'
      return 0
      ;;
  esac
  # An unpublished local path dependency admitted for a release-facing crate.
  case $lowered in
    *'admit the path patch'* | *'local path dependency is acceptable'*)
      printf 'local path admission'
      return 0
      ;;
  esac
  # A projection promoted to authority.
  case $lowered in
    *'projection is authoritative'* | *'projections are authoritative'* | \
      *'read model is the source of truth'*)
      printf 'projection-as-authority'
      return 0
      ;;
  esac
  # The primary UI drifting to canvas or the terminal skin.
  case $lowered in
    *'canvas is the primary'* | *'terminal-style web surface is the primary'* | \
      *'ftui is the primary web ui'*)
      printf 'canvas or terminal primary UI'
      return 0
      ;;
  esac
  return 0
}

# -----------------------------------------------------------------------------
fge_phase assert
fge_step adr-inventory
# -----------------------------------------------------------------------------
if [ "${#adr_files[@]}" -ge 15 ]; then
  fge_pass fg061-adr-inventory "${#adr_files[@]} ADRs present"
else
  fge_fail fg061-adr-inventory "only ${#adr_files[@]} ADRs present, expected at least 15"
fi

fge_step no-contradictions
adr_bad=""
for file in "${adr_files[@]}"; do
  found=$(adr_contradiction "$file")
  [ -z "$found" ] || adr_bad="$adr_bad ${file##*/}:$found"
done
if [ -z "$adr_bad" ]; then
  fge_pass fg061-adr-no-contradictions "no ADR contradicts a settled constitutional position"
else
  fge_fail fg061-adr-no-contradictions "settled positions contradicted:$adr_bad"
fi

fge_step contradiction-checker-can-fail
adr_missed=""
adr_plant() {
  local label=$1 text=$2 verdict
  printf '%s\n' "$text" >"$ADR_WORK/planted-$label.md"
  verdict=$(adr_contradiction "$ADR_WORK/planted-$label.md")
  [ -n "$verdict" ] || adr_missed="$adr_missed $label"
}
adr_plant unsafe 'The glue crate carries #[allow(unsafe_code)] for wasm-bindgen.'
adr_plant runtime 'For this surface a second runtime is acceptable.'
adr_plant path 'We admit the path patch until upstream publishes.'
adr_plant projection 'For dashboards the projection is authoritative.'
adr_plant ui 'The terminal-style web surface is the primary UI.'
if [ -z "$adr_missed" ]; then
  fge_pass fg061-contradiction-checker-can-fail "every planted contradiction was detected"
else
  fge_fail fg061-contradiction-checker-can-fail "planted contradictions NOT detected:$adr_missed"
fi

fge_step no-loss-guarantee
# WEB-3 may not quietly drop the supported alternative front end.
if LC_ALL=C grep -qi 'typescript' "$ADR_DOCS/ADR-0013-WEB3-PRIMARY-WEB-UI.md" &&
  LC_ALL=C grep -qi 'react' "$ADR_DOCS/ADR-0013-WEB3-PRIMARY-WEB-UI.md"; then
  fge_pass fg061-no-loss-guarantee "the TypeScript client and React reference alternative is still recorded"
else
  fge_fail fg061-no-loss-guarantee "WEB-3 no longer records the TypeScript/React no-loss guarantee"
fi

fge_step decision-status
# A planning bead may not mark its own decisions accepted; acceptance is the
# owner's ruling, one by one.
adr_selfaccepted=""
for file in "${adr_files[@]}"; do
  case ${file##*/} in
    ADR-0001-* | ADR-0002-* | ADR-0003-*) continue ;;
  esac
  LC_ALL=C grep -qE '^- \*\*Status:\*\* *proposed' "$file" ||
    adr_selfaccepted="$adr_selfaccepted ${file##*/}"
done
if [ -z "$adr_selfaccepted" ]; then
  fge_pass fg061-adrs-not-self-accepted "every swept ADR is still proposed, not self-accepted"
else
  fge_fail fg061-adrs-not-self-accepted "ADRs claiming a status this bead may not grant:$adr_selfaccepted"
fi

fge_step binds-resolve
# An ADR that binds a bead which does not exist is unattached prose.
adr_unknown=""
adr_bind_count=0
while IFS= read -r bead; do
  [ -n "$bead" ] || continue
  adr_bind_count=$((adr_bind_count + 1))
  LC_ALL=C grep -qF "\"id\":\"$bead\"" "$ADR_REPO/.beads/issues.jsonl" ||
    adr_unknown="$adr_unknown $bead"
done < <(LC_ALL=C grep -h '^- \*\*Binds:\*\*' "${adr_files[@]}" 2>/dev/null |
  LC_ALL=C grep -oE 'frankengit-[a-z0-9-]+' | LC_ALL=C sort -u)
fge_field bound_beads "$adr_bind_count"
if [ "$adr_bind_count" -lt 10 ]; then
  fge_fail fg061-binds-resolve "only $adr_bind_count bound beads found; the extraction is broken"
elif [ -z "$adr_unknown" ]; then
  fge_pass fg061-binds-resolve "all $adr_bind_count bound beads exist in the tracker"
else
  fge_fail fg061-binds-resolve "ADRs bind beads that do not exist:$adr_unknown"
fi

fge_phase teardown
fge_note "planning-bead lane: no implementation, benchmark, or performance claim is made here"
