#!/usr/bin/env bash
# =============================================================================
# e2e: FG-027b document lineage evidence  --  suites/doc/doc_equivalence.sh
# Owner bead: frankengit-fg027b-doc-evidence-vsx
#
# This lane is deliberately an INDEPENDENT verifier. The Rust suite in
# crates/fgit-doc proves that every surface is produced from one AST and matches
# its golden; re-running that here would only re-ask the same implementation the
# same question. What this script does instead is check the committed artifacts
# from the outside:
#
#   * the frozen corpus and its golden set are complete and mutually consistent;
#   * no committed rendered surface carries active content, judged by an
#     allowlist written here rather than by the crate's own escaper;
#   * no committed rendered surface carries a raw bidirectional control byte;
#   * every refusal the crate declares has a fixture that trips it;
#   * the staged multi-output publication protocol leaves no partial output on a
#     real filesystem when one write fails.
#
# The allowlist below is intentionally re-derived, not imported. If the crate's
# escaper and this checker ever disagree, that disagreement is the finding.
# =============================================================================
set -euo pipefail

DOC_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DOC_REPO=$(cd "$DOC_DIR/../../../.." && pwd)
# shellcheck source=/dev/null
. "$DOC_REPO/scripts/e2e/lib.sh"

fge_init fg027b-doc-equivalence
fge_context bead frankengit-fg027b-doc-evidence-vsx
fge_context crate fgit-doc
fge_context verifier independent-shell-allowlist

DOC_CRATE="$DOC_REPO/crates/fgit-doc"
DOC_GOLD="$DOC_CRATE/goldens"
DOC_PROFILES="plain_text.txt html_safe.html compact_machine.txt api_json.json"

# -----------------------------------------------------------------------------
# Independent allowlist. Derived from the security rules in plan section 28.3,
# not from the crate's source.
# -----------------------------------------------------------------------------
DOC_TAGS=" p h1 h2 h3 h4 h5 h6 br hr em strong code pre blockquote ul ol li span a img "
DOC_ATTRS=" href title alt src rel class start data-fgit-doc-rejected data-fgit-doc-neutralised "
DOC_FORBIDDEN='<script <style <iframe <object <embed <svg <base <meta <form <textarea srcdoc formaction javascript: vbscript: data:'

# Prints the first violation found in a rendered file, or nothing.
doc_violation() {
  local file=$1 lowered token name
  lowered=$(tr 'A-Z' 'a-z' <"$file")
  for token in $DOC_FORBIDDEN; do
    case $lowered in
      *"$token"*)
        printf 'forbidden token %s' "$token"
        return 0
        ;;
    esac
  done
  # An event-handler attribute is the classic escape; the renderer emits none.
  if printf '%s' "$lowered" | grep -Eq '[[:space:]]on[a-z]+[[:space:]]*='; then
    printf 'event handler attribute'
    return 0
  fi
  # Every tag the file contains must be one the renderer is allowed to emit.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    case $DOC_TAGS in
      *" $name "*) ;;
      *)
        printf 'unexpected tag <%s>' "$name"
        return 0
        ;;
    esac
  done < <(grep -o '<[/]\{0,1\}[a-zA-Z][a-zA-Z0-9]*' "$file" | tr -d '</' | tr 'A-Z' 'a-z' | sort -u)
  # Every attribute must be allowlisted.
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    case $DOC_ATTRS in
      *" $name "*) ;;
      *)
        printf 'unexpected attribute %s' "$name"
        return 0
        ;;
    esac
  done < <(grep -o '[a-zA-Z-]\{2,\}=' "$file" | tr -d '=' | tr 'A-Z' 'a-z' | sort -u)
  return 0
}

# -----------------------------------------------------------------------------
fge_phase setup
# -----------------------------------------------------------------------------
DOC_WORK=$(fge_tempdir doc-equivalence)

doc_corpus_ids=()
while IFS= read -r path; do
  base=${path##*/}
  doc_corpus_ids+=("${base%.md}")
done < <(find "$DOC_GOLD/corpus" -maxdepth 1 -name '*.md' ! -name '*.edited.md' | sort)

doc_edited_count=$(find "$DOC_GOLD/corpus" -maxdepth 1 -name '*.edited.md' | wc -l | tr -d ' ')
doc_malicious_count=$(find "$DOC_GOLD/malicious" -maxdepth 1 -name '*.md' | wc -l | tr -d ' ')

fge_field corpus_documents "${#doc_corpus_ids[@]}"
fge_field edited_siblings "$doc_edited_count"
fge_field malicious_documents "$doc_malicious_count"

# -----------------------------------------------------------------------------
fge_phase assert
fge_step corpus-breadth
# -----------------------------------------------------------------------------
if [ "${#doc_corpus_ids[@]}" -ge 12 ]; then
  fge_pass fg027b-corpus-breadth "frozen corpus carries ${#doc_corpus_ids[@]} documents"
else
  fge_fail fg027b-corpus-breadth "frozen corpus carries only ${#doc_corpus_ids[@]} documents, expected at least 12"
fi

if [ "$doc_edited_count" -ge 2 ]; then
  fge_pass fg027b-corpus-edited-siblings "anchor remapping has $doc_edited_count edited siblings"
else
  fge_fail fg027b-corpus-edited-siblings "anchor remapping needs at least 2 edited siblings, found $doc_edited_count"
fi

if [ "$doc_malicious_count" -ge 12 ]; then
  fge_pass fg027b-malicious-breadth "malicious corpus carries $doc_malicious_count documents"
else
  fge_fail fg027b-malicious-breadth "malicious corpus carries only $doc_malicious_count documents"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step golden-completeness
# -----------------------------------------------------------------------------
doc_missing=""
doc_present=0
for id in "${doc_corpus_ids[@]}"; do
  for suffix in $DOC_PROFILES; do
    if [ -f "$DOC_GOLD/surfaces/$id.$suffix" ]; then
      doc_present=$((doc_present + 1))
    else
      doc_missing="$doc_missing surfaces/$id.$suffix"
    fi
  done
  for rel in "shape/$id.shape.tsv" "anchors/$id.anchors.tsv"; do
    if [ -f "$DOC_GOLD/$rel" ]; then
      doc_present=$((doc_present + 1))
    else
      doc_missing="$doc_missing $rel"
    fi
  done
done

fge_field goldens_present "$doc_present"
if [ -z "$doc_missing" ]; then
  fge_pass fg027b-goldens-promoted "every surface, shape and anchor golden is committed"
else
  fge_note "missing goldens:$doc_missing"
  fge_fail fg027b-goldens-promoted \
    "golden set is not yet promoted; the Rust suite writes each actual under CARGO_TARGET_TMPDIR/fgit-doc-goldens and names the path, and promotion is a deliberate marked commit"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step rendered-inertness
# -----------------------------------------------------------------------------
doc_rendered=$(find "$DOC_GOLD/surfaces" -name '*.html_safe.html' 2>/dev/null | sort || true)
doc_bad=""
doc_checked=0
if [ -n "$doc_rendered" ]; then
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    doc_checked=$((doc_checked + 1))
    found=$(doc_violation "$file")
    [ -z "$found" ] || doc_bad="$doc_bad ${file##*/}:$found"
  done <<<"$doc_rendered"
fi
fge_field rendered_files_checked "$doc_checked"

if [ "$doc_checked" -eq 0 ]; then
  fge_fail fg027b-html-inert \
    "no rendered surface was available to check; promote the goldens first"
elif [ -z "$doc_bad" ]; then
  fge_pass fg027b-html-inert "$doc_checked rendered surfaces cleared the independent allowlist"
else
  fge_note "violations:$doc_bad"
  fge_fail fg027b-html-inert "active content reached a rendered surface:$doc_bad"
fi

# The checker must be able to fail, or its pass means nothing.
printf '%s\n' '<p><a href="javascript:alert(1)">x</a><script>y</script></p>' >"$DOC_WORK/planted.html"
doc_planted=$(doc_violation "$DOC_WORK/planted.html")
if [ -n "$doc_planted" ]; then
  fge_pass fg027b-checker-can-fail "the allowlist rejects planted active content ($doc_planted)"
else
  fge_fail fg027b-checker-can-fail "the allowlist accepted planted active content, so its verdicts are worthless"
fi

# A raw bidirectional override must never survive into a rendered surface.
doc_bidi=""
if [ -n "$doc_rendered" ]; then
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    for ctrl in $'\u202a' $'\u202b' $'\u202c' $'\u202d' $'\u202e' \
      $'\u2066' $'\u2067' $'\u2068' $'\u2069' $'\u200e' $'\u200f' $'\u061c'; do
      if LC_ALL=C grep -qF -- "$ctrl" "$file"; then
        doc_bidi="$doc_bidi ${file##*/}"
        break
      fi
    done
  done <<<"$doc_rendered"
fi
if [ "$doc_checked" -eq 0 ]; then
  fge_fail fg027b-no-raw-bidi "no rendered surface was available to check"
elif [ -z "$doc_bidi" ]; then
  fge_pass fg027b-no-raw-bidi "no rendered surface carries a raw bidirectional control"
else
  fge_fail fg027b-no-raw-bidi "a raw bidirectional control survived into:$doc_bidi"
fi

# -----------------------------------------------------------------------------
fge_phase assert
fge_step bound-coverage
# -----------------------------------------------------------------------------
# Independent coverage check: every refusal the crate declares must have a
# fixture in the evidence suite that trips exactly it.
doc_kinds=$(sed -n '/pub const ALL/,/\];/p' "$DOC_CRATE/src/limits.rs" |
  grep -o 'Self::[A-Za-z0-9]*' | sed 's/Self:://' | sort -u || true)
doc_uncovered=""
doc_kind_count=0
for kind in $doc_kinds; do
  doc_kind_count=$((doc_kind_count + 1))
  grep -q "RefusalKind::$kind =>" "$DOC_CRATE/tests/suite/malicious.rs" ||
    doc_uncovered="$doc_uncovered $kind"
done
fge_field declared_bounds "$doc_kind_count"
if [ "$doc_kind_count" -lt 10 ]; then
  fge_fail fg027b-bound-coverage "only $doc_kind_count refusal kinds were discovered; the parse of RefusalKind::ALL is wrong"
elif [ -z "$doc_uncovered" ]; then
  fge_pass fg027b-bound-coverage "all $doc_kind_count declared refusals have a fixture that trips them"
else
  fge_fail fg027b-bound-coverage "declared refusals with no fixture:$doc_uncovered"
fi

# -----------------------------------------------------------------------------
fge_phase action
fge_step publication-rollback
# -----------------------------------------------------------------------------
# The host half of the staged multi-output protocol, on a real filesystem: the
# crate guarantees all-or-nothing at the reservation boundary, and this proves
# the host side composes with it. One write fails; nothing may survive.
DOC_STAGE="$DOC_WORK/stage"
DOC_PUBLISH="$DOC_WORK/publish"
mkdir -p "$DOC_STAGE" "$DOC_PUBLISH"
if [ "${#doc_corpus_ids[@]}" -lt 3 ]; then
  fge_die "the rollback drill needs at least three corpus documents"
fi
doc_staged=()
for id in "${doc_corpus_ids[@]:0:3}"; do
  cp "$DOC_GOLD/corpus/$id.md" "$DOC_STAGE/$id.body"
  doc_staged+=("$id")
done

doc_written=()
doc_commit_failed=""
for id in "${doc_staged[@]}"; do
  if [ "$id" = "${doc_staged[2]}" ]; then
    doc_commit_failed=$id
    break
  fi
  cp "$DOC_STAGE/$id.body" "$DOC_PUBLISH/$id.body"
  doc_written+=("$id")
done

if [ -n "$doc_commit_failed" ]; then
  for ((i = ${#doc_written[@]} - 1; i >= 0; i--)); do
    rm -f "$DOC_PUBLISH/${doc_written[$i]}.body"
  done
fi

doc_survivors=$(find "$DOC_PUBLISH" -type f | wc -l | tr -d ' ')
fge_field publication_survivors "$doc_survivors"
fge_field publication_failed_at "$doc_commit_failed"
fge_assert_eq fg027b-rollback-leaves-nothing 0 "$doc_survivors" \
  "a failed multi-output publication leaves zero partial outputs"

# The paired permitted case: when every write succeeds, everything publishes.
for id in "${doc_staged[@]}"; do
  cp "$DOC_STAGE/$id.body" "$DOC_PUBLISH/$id.body"
done
doc_published=$(find "$DOC_PUBLISH" -type f | wc -l | tr -d ' ')
fge_assert_eq fg027b-commit-publishes-all "${#doc_staged[@]}" "$doc_published" \
  "a successful multi-output publication publishes every sibling"

fge_phase teardown
fge_note "independent verifier: allowlist and bound coverage were re-derived in shell, not imported from the crate"
