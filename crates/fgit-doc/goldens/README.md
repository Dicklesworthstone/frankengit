# `fgit-doc` evidence corpus

Frozen inputs and pinned outputs for FG-027b. Nothing here is generated during
a normal test run; the suite only ever *compares* against these files.

## Layout

| path | what it pins |
|---|---|
| `corpus/NNN-name.md` | a frozen source document |
| `corpus/NNN-name.edited.md` | an edited sibling, for anchor remapping |
| `surfaces/NNN-name.<profile>.<ext>` | one render profile's exact output |
| `shape/NNN-name.shape.tsv` | the AST: kind, depth, byte span, codepoint span, leaf literal |
| `anchors/NNN-name.anchors.tsv` | every input the anchor identity is derived from |
| `remap/NNN-name.remap.tsv` | how each anchor resolves against the edited sibling |
| `malicious/mNN-name.md` | a hostile input that must end bounded and inert, or refused |

Every artifact under `surfaces/`, `shape/`, `anchors/` and `remap/` is derived
from **one** parse of its corpus document. That is the property the set exists
to pin: if a surface ever re-parsed its input, its spans would drift from
`shape/`, and `the_api_and_shape_surfaces_report_the_same_spans` would say so.

Fixture inputs deliberately carry the `.mdin` extension rather than `.md`.
They are hostile *inputs* — an unbalanced code fence, a deliberately broken
relative link, `javascript:` destinations — and the repository-wide Markdown
checker is right to reject those in a real document. Keeping them out of the
`*.md` namespace lets that checker stay strict instead of growing an exclusion.

## Changing a golden

A golden change is a change in observable behaviour, so it is never a cleanup
and never a step taken to make a lane green.

1. Run the suite. `every_surface_matches_its_golden` writes each actual under
   the test target directory and names the exact path in its failure.
2. Read the diff. Decide whether the new behaviour is correct. If it is not,
   the fix belongs in the crate, not here.
3. Copy the actuals over the goldens and commit them **alone**, in a commit
   whose message states the semantic reason for the change and the bead that
   authorised it.

Regenerating a golden to silence a failing lane is the `RH-3` pathology named
in `AGENTS.md` §16.3. The suite's failure message says so too, deliberately.

## Independent verification

`scripts/e2e/suites/doc/doc_equivalence.sh` re-derives the active-content
allowlist and the refusal-coverage check in shell rather than importing them
from the crate. If that checker and the crate's escaper ever disagree, the
disagreement is the finding — which is the whole reason it is not shared code.
