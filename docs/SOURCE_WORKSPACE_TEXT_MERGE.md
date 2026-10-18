# Merge disjoint text edits during reviewed workspace refresh

The existing trusted-local workspace commands accept an explicit
`--merge-profile bounded-line-merge-v1`. It combines non-overlapping line edits
inside a selected file instead of requiring a whole-file choice whenever both
local and independently selected source contents changed. This advances the
FG-026 workspace refresh consumer, not native Git merge, TreeFS, or forge merge
admission. The default whole-file comparison is unchanged.

```sh
node scripts/fg_source_workspace.mjs refresh-preview \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --merge-profile bounded-line-merge-v1

node scripts/fg_source_workspace.mjs refresh \
  --workspace /srv/editing --sha256 "$ORIGINAL_WORKSPACE_SHA256" \
  --package /srv/review/next-source.json --expect /srv/review/next-expectation.json \
  --merge-profile bounded-line-merge-v1 \
  --approve-refresh-sha256 "$REVIEWED_REFRESH_SHA256" \
  --output /srv/refreshed-editing
```

The API option is `mergeProfile: 'bounded-line-merge-v1'` on
`previewSourceWorkspaceRefresh` and `refreshSourceWorkspace`. Null, unknown and
explicitly undefined profiles refuse. Both commands must use the same profile.
The selected profile and deterministic work witness enter the preview hash even
when no textual merge was needed. An old whole-file approval cannot approve a
new algorithm, and changing local bytes, modes, source or choices still invalidates
approval. The source commit and selected path population remain independently
chosen; there is no implicit branch lookup or ancestry assertion.

## Exact behavior

Whole-file equality and independent executable-mode reconciliation run first,
including their existing binary and deletion handling. Only files whose contents
changed differently on both sides enter the new line algorithm. All three images
must be NUL-free valid UTF-8; unsupported bytes remain a visible conflict, not a
lossy decode or silent selection of one side.

The bounded Myers comparison produces exact base-relative insertion, deletion
and replacement spans for each side. Its fixed tie policy prefers deletion.
Complete byte-identical lines are compared, including CRLF, LF, blank lines,
UTF-8 BOMs and missing final newlines. No whitespace normalization, fuzzy patch
application, conflict marker insertion, rename inference or external Git occurs.
The two span sets are combined only when they are disjoint or describe the same
replacement at the same interval. Identical edits occur once, not twice.

Different insertions at the same boundary conflict. An insertion touching either
edge of a replacement/deletion also conflicts unless both edits are identical;
ordering is not invented. Adjacent nonempty replacement ranges are disjoint.
Other overlaps remain conflicts even when a more sophisticated merge might find
a resolution. Repeated lines follow the deterministic alignment policy; a clean
textual result is not proof of author intent or semantic compatibility.

Successful entries have `disposition: "text_merged"` and a complete result image
hash/length/mode. Per-file `text_merge` diagnostics report status, reason and work.
Reasons include `not_text`, `overlapping_changes`, `distance_limit`, `line_limit`,
`work_limit` and `output_limit`. No failed attempt returns a partial file image.
All conflicts are collected; a ready prefix cannot cause partial materialization.

Existing `--resolutions` choices remain available for unresolved files. They bind
the original profile-specific conflict preview. Preview the choices and approve
the new resolved plan before creating output, exactly as described in
[SOURCE_WORKSPACE_REFRESH.md](SOURCE_WORKSPACE_REFRESH.md). Neither this choice
nor a successful textual merge authorizes a repository mutation or reuses an old
publication/recovery key. Review the resulting source before subsequent capture.

## Bounds and cancellation

One merger instance covers the complete sorted refresh population. It shares
131,072 input-line slots and 4,194,304 deterministic work units across all textual
attempts, with no per-file reset. Work units account for line processing,
frontier visits, equality/backtracking work, span comparisons and 64-byte scanning
or output blocks; they are not elapsed time or a CPU-instruction measurement.
The per-comparison edit-distance ceiling is 256; its retained frontier trace is
bounded independently of input length. Limits select typed conflict rather than
an approximate merge. Global line/work exhaustion stays latched for later text
attempts, while ordinary whole-file reconciliation still runs.

Each input and result file remains bounded to 1 MiB, and the existing complete
workspace result stays bounded to 8 MiB. Individually valid inputs cannot combine
into an oversized output. Allocation checks precede line growth and output
concatenation. Inputs are copied before caller checkpoints; shared-memory inputs
refuse. Diagnostic snapshots do not expose mutable budget state.

All comparisons, backtracking and output assembly use the existing shared
operation checkpoint. Cancellation/deadline exceptions propagate unchanged;
they never become a success or an ordinary content conflict. The existing writer
still creates a separate directory, rechecks original observations and writes
its manifest last. Output failure retains the original result/pins; no retry,
overwrite or cleanup of an uncertain workspace is automatic.

## Validation boundary

Run `bash scripts/verify_source_workspace_refresh.sh`.
`source_workspace_merge.test.mjs` imports the entire production merge module,
with no fixture replacement. It checks exact reconstruction over all 961 pairs
of short repeated-line sequences, 3,000 generated disjoint edit cases, supported
byte details, boundary conflicts, capacity neighbors, cancellation and ownership.
Installed Git is a test-only oracle for a separated-edit corpus, not production
code or a pinned conformance claim. Its version is emitted in test diagnostics.

`source_workspace_refresh_merge.test.mjs` executes the real merger, workspace
and CLI bodies against real private POSIX files, covering both hash domains,
mode composition, profile consent, explicit resolutions, shared exhaustion,
editor races and lost output. The pre-existing source/codec services use the
same explicit contract fixtures as the earlier refresh tests; these tests do
not run native membership verification, Rust fg/admission/CAS or the complete
workspace. They do not claim native Git merge compatibility, semantic safety,
hostile-same-user confinement or hardware power-loss durability.
