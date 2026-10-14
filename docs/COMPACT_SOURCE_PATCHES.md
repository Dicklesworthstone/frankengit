# Compact exact source patches

The source authoring CLI accepts an explicit `patch_profile` in the changes JSON:

```json
{
  "schema": "frankengit-source-changes-v1",
  "patch_profile": "trim-common-lines-v1",
  "changes": [
    {
      "path_hex": "7372632f6d61696e2e7273",
      "operation": "replace-once",
      "before_utf8": "old_call()",
      "after_utf8": "new_call()"
    }
  ]
}
```

Use this with the existing `fg_source_changes.mjs draft`, `prepare`,
`inspect-candidate` and `stage` commands. There is no new network endpoint,
publication operation or journal format. The independent source package, target
selection, draft/candidate consent and original-key recovery rules still apply.

## What is encoded

The default encoder replaces the full file. For a small change in a large file,
that can exceed the 1 MiB operator patch limit despite a permitted source file.
`trim-common-lines-v1` removes byte-identical complete leading and trailing lines
from each file's hunk, retaining up to three unchanged context lines at each edge.
It keeps the original exact line positions and full old/new native blob IDs.
The new root tree and intended file effects remain exactly the same as those of
the default full-file patch.

The scans are linear in the before/after byte lengths, with no array per unchanged
line. Only the bounded output is split into patch rows. Cancellation/deadline
checks cover scanning, comparison, encoding and the existing asynchronous hashes.
Blank lines, CRLF, empty files and missing final newlines are preserved exactly.
Mode-only operations and empty-file creation/deletion keep their header-only form.

This is deterministic edge trimming, not a minimal diff, a multi-hunk diff,
fuzzy application, three-way merge or semantic conflict resolution. Widely
separated changes retain the intervening bytes. A large changed line or a large
middle region can still exceed the patch limit and is refused. No automatic
fallback silently changes the selected profile or review commitment.

## Consent and compatibility

Omitting `patch_profile` keeps the existing full-file patch bytes and draft
manifest hashes unchanged. Only the exact string `trim-common-lines-v1` is
accepted when the field is present. Null, booleans and unknown profiles refuse.
The chosen profile is included in the normalized change request and draft,
so selecting it requires a new reviewed draft hash even when a short file happens
to produce identical patch bytes. Old consent does not approve a new profile.

Binary source needs the separate explicit `byte_profile: "binary-safe-v1"` from
`BINARY_SOURCE_AUTHORING.md`. The two choices compose; neither selects the other.
Without binary consent, NUL-bearing edits still refuse. A compact binary patch
uses counted byte hunks, not a compressed Git binary-patch codec.

Original source verification, proved absence, full expected-tree derivation,
32 file effects, 1 MiB per-file/patch and 4 MiB retained before/after limits remain.
The shared encoded-patch line ceiling is unchanged. Trimming reduces transported
patch bytes, not the source bytes needed for verification or the operator's
responsibility to review the complete effects. Explicit base replay preserves
the profile and exact patch, and still requires fresh consent for the new base.
Workspace capture continues to use its existing selection grammar and default
patch form; this profile is selected in the source-change request, not inferred
from local files or automatically enabled by capture.

## Executable checks

Run `bash scripts/verify_source_changes.sh`; the broader
`bash scripts/verify_source_replay.sh` includes it. The compact tests use full
production imports, installed Git as a test-only patch/tree oracle, actual CLI
processes, private files and native-schema HTTP peers. They cover large-file
edits formerly refused by the patch ceiling, blank-line boundaries, binary opt-in,
raw byte preservation, creation/deletion, profile consent, cancellation, exact
output limits, selected-base replay and staged original-key recovery.
Forward and reverse Git application must reproduce independently built trees.
HTTP peers are not a running Rust `fg` server. This lane does not establish native
admission/authorization/CAS, semantic correctness, complete candidate pack closure
or full-workspace correctness.
