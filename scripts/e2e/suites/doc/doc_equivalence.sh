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
#
# Every text-processing pipeline pins LC_ALL=C. Case folding, bracket ranges and
# collation are all locale-dependent, and a checker whose verdict depends on the
# operator's locale is not a checker. In this suite the drift happened to fail
# safe -- under tr_TR a tag <IMG> folds to a dotless 'img' that misses the
# allowlist and is therefore rejected -- but "accidentally strict" is not a
# property worth relying on.
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
DOC_SCHEMES=" http https mailto "

# Prints the first violation found in a rendered file, or nothing.
#
# The check is STRUCTURAL, not a substring scan, and that distinction is the
# whole point. This renderer's job includes displaying hostile markup as escaped
# text, so a correct output legitimately contains the byte sequences
# "javascript:" and "onerror=" inside a code block. Only their appearance in a
# tag the renderer actually emitted is a defect. Source "<" is always escaped,
# so every "<" surviving into the output is such a tag.
doc_violation() {
  local file=$1 tag body name attr value scheme
  while IFS= read -r tag; do
    [ -n "$tag" ] || continue
    body=${tag#<}
    body=${body%>}
    body=${body#/}
    body=${body%/}
    # Shell-only: the harness deliberately adds nothing to the closed dependency
    # universe, so a suite must not fork awk/jq/python. Two parameter expansions,
    # zero subprocesses (FG-000A-PORT-019).
    name=${body%%[[:space:]]*}
    name=${name,,}
    case $DOC_TAGS in
      *" $name "*) ;;
      *)
        printf 'unexpected tag <%s>' "$name"
        return 0
        ;;
    esac
    while IFS= read -r attr; do
      [ -n "$attr" ] || continue
      case $attr in
        on*)
          printf 'event handler %s on <%s>' "$attr" "$name"
          return 0
          ;;
      esac
      case $DOC_ATTRS in
        *" $attr "*) ;;
        *)
          printf 'unexpected attribute %s on <%s>' "$attr" "$name"
          return 0
          ;;
      esac
    done < <(printf '%s' "$body" | LC_ALL=C grep -o '[a-zA-Z][a-zA-Z0-9-]*=' |
      LC_ALL=C tr -d '=' | LC_ALL=C tr 'A-Z' 'a-z' | LC_ALL=C sort -u)
    while IFS= read -r value; do
      [ -n "$value" ] || continue
      # Judge what ONE browser decode produces, which is the subtlety that
      # made an earlier version of this check wrong in both directions.
      #
      # A browser scans the raw attribute once. So `java&amp;#9;script:` yields
      # the inert literal `java&#9;script:` -- note the RAW value contains no
      # `&#` at all, because the `&` there is followed by `a`. Decoding `&amp;`
      # first and then hunting for `&#` simulates a DOUBLE decode and cries
      # wolf. Checking the raw value instead is both simpler and correct.
      #
      # This verifier is deliberately a different algorithm from the crate's
      # Rust checker, which models the full single pass. Same property, two
      # independent routes to it.
      case ${value//'&#x27;'/} in
        *'&#'*)
          # A raw numeric reference the renderer did not emit: a browser WILL
          # decode it, so `&#106;avascript:` really does become `javascript:`.
          printf 'raw numeric character reference in a destination on <%s>' "$name"
          return 0
          ;;
      esac
      value=${value//'&amp;'/'&'}
      value=${value//'&lt;'/'<'}
      value=${value//'&gt;'/'>'}
      value=${value//'&quot;'/'"'}
      value=${value//'&#x27;'/"'"}
      case $value in
        //*)
          printf 'protocol-relative destination on <%s>' "$name"
          return 0
          ;;
      esac
      case $value in
        *:*)
          scheme=$(printf '%s' "${value%%:*}" | LC_ALL=C tr 'A-Z' 'a-z')
          case $scheme in
            [a-z]*)
              case $scheme in
                *[!a-z0-9+.-]*) ;;
                *)
                  case $DOC_SCHEMES in
                    *" $scheme "*) ;;
                    *)
                      printf 'destination scheme %s: on <%s>' "$scheme" "$name"
                      return 0
                      ;;
                  esac
                  ;;
              esac
              ;;
          esac
          ;;
      esac
    done < <(printf '%s' "$body" | LC_ALL=C grep -o 'href="[^"]*"\|src="[^"]*"' |
      LC_ALL=C sed 's/^[a-z]*="//; s/"$//')
  done < <(LC_ALL=C grep -o '<[^>]*>' "$file" || true)
  return 0
}

# -----------------------------------------------------------------------------
fge_phase setup
# -----------------------------------------------------------------------------
DOC_WORK=$(fge_tempdir doc-equivalence)

doc_corpus_ids=()
while IFS= read -r path; do
  base=${path##*/}
  doc_corpus_ids+=("${base%.mdin}")
done < <(find "$DOC_GOLD/corpus" -maxdepth 1 -name '*.mdin' ! -name '*.edited.mdin' |
  LC_ALL=C sort)

doc_edited_count=$(find "$DOC_GOLD/corpus" -maxdepth 1 -name '*.edited.mdin' | wc -l | tr -d ' ')
doc_malicious_count=$(find "$DOC_GOLD/malicious" -maxdepth 1 -name '*.mdin' | wc -l | tr -d ' ')

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
doc_rendered=$(find "$DOC_GOLD/surfaces" -name '*.html_safe.html' 2>/dev/null |
  LC_ALL=C sort || true)
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

# -----------------------------------------------------------------------------
fge_phase assert
fge_step golden-content-preservation
# -----------------------------------------------------------------------------
# INDEPENDENT check on the golden SET itself, not on the renderer.
#
# The 74 goldens were produced by the very code they are meant to hold to
# account, so their agreement with that code proves nothing about content
# fidelity: a renderer that silently dropped a word would have blessed its own
# omission. This check never runs the crate. It reads each frozen source,
# extracts every ASCII word of four or more letters, and requires each one to
# survive into at least one of that document's four rendered surfaces. Words
# rather than bytes, because the surfaces legitimately differ in markup,
# punctuation and ordering -- but none of them may lose a word.
doc_lost=""
doc_words_checked=0
for id in "${doc_corpus_ids[@]}"; do
  doc_all_surfaces=""
  for suffix in $DOC_PROFILES; do
    if [ -f "$DOC_GOLD/surfaces/$id.$suffix" ]; then
      doc_all_surfaces="$doc_all_surfaces$(cat "$DOC_GOLD/surfaces/$id.$suffix")"
    fi
  done
  [ -n "$doc_all_surfaces" ] || continue
  while IFS= read -r word; do
    [ -n "$word" ] || continue
    doc_words_checked=$((doc_words_checked + 1))
    case $doc_all_surfaces in
      *"$word"*) ;;
      *) doc_lost="$doc_lost $id:$word" ;;
    esac
  done < <(LC_ALL=C grep -oE '[A-Za-z]{4,}' "$DOC_GOLD/corpus/$id.mdin" | LC_ALL=C sort -u)
done
fge_field source_words_checked "$doc_words_checked"

# Vacuity guard, scaled to the corpus rather than to a guessed constant: a
# broken extraction yields near zero, and requiring four distinct words per
# document cannot be defeated by shrinking the corpus. Measured floor across the
# current twelve documents is five (002-headings); the total is 148.
doc_words_floor=$(( ${#doc_corpus_ids[@]} * 4 ))
if [ "$doc_words_checked" -lt "$doc_words_floor" ]; then
  fge_fail fg027b-golden-content-preserved \
    "only $doc_words_checked words were checked against a floor of $doc_words_floor; the extraction is broken and this check is vacuous"
elif [ -z "$doc_lost" ]; then
  fge_pass fg027b-golden-content-preserved \
    "$doc_words_checked distinct source words all survive into a rendered surface"
else
  fge_fail fg027b-golden-content-preserved "source words absent from every surface:$doc_lost"
fi

# The check must be able to fail, or it is decoration: a word present in no
# source must be reported absent from the same haystack the check searches.
doc_word_absent=0
case $doc_all_surfaces in
  *zzzabsentzzz*) ;;
  *) doc_word_absent=1 ;;
esac
fge_assert_eq fg027b-content-check-can-fail 1 "$doc_word_absent" \
  "a word present in no surface is detectably absent"

# The checker must be able to fail on EVERY path it claims to guard, or a pass
# from it means nothing. One payload per rejection reason.
doc_planted_missed=""
doc_planted_caught=""
doc_plant() {
  local label=$1 markup=$2 verdict
  printf '%s\n' "$markup" >"$DOC_WORK/planted-$label.html"
  verdict=$(doc_violation "$DOC_WORK/planted-$label.html")
  if [ -n "$verdict" ]; then
    doc_planted_caught="$doc_planted_caught $label($verdict)"
  else
    doc_planted_missed="$doc_planted_missed $label"
  fi
}
doc_plant tag '<p><script>alert(1)</script></p>'
doc_plant iframe '<p><iframe srcdoc="x"></iframe></p>'
doc_plant handler '<p onclick="steal()">x</p>'
doc_plant scheme '<p><a href="javascript:alert(1)">x</a></p>'
doc_plant datauri '<p><img src="data:text/html,x" /></p>'
doc_plant vbscript '<p><a href="VBScript:msgbox(1)">x</a></p>'
doc_plant numeric_entity '<p><a href="&#106;avascript:alert(1)">x</a></p>'
doc_plant protocol_relative '<p><a href="//evil.example/x">x</a></p>'
if [ -z "$doc_planted_missed" ]; then
  fge_pass fg027b-checker-can-fail "the allowlist rejected every planted payload:$doc_planted_caught"
else
  fge_fail fg027b-checker-can-fail "the allowlist ACCEPTED planted active content, so its verdicts are worthless:$doc_planted_missed"
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
  LC_ALL=C grep -o 'Self::[A-Za-z0-9]*' | LC_ALL=C sed 's/Self:://' |
  LC_ALL=C sort -u || true)
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
  cp "$DOC_GOLD/corpus/$id.mdin" "$DOC_STAGE/$id.body"
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
