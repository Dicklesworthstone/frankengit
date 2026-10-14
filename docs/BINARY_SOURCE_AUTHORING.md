# Binary-safe verified source authoring

The operator source-change workflow supports exact arbitrary regular-file bytes,
including NUL, non-UTF-8 contents, CRLF and missing final newlines. Opt in explicitly
in the reviewed changes JSON:

```json
{
  "schema": "frankengit-source-changes-v1",
  "byte_profile": "binary-safe-v1",
  "changes": [
    {"operation": "replace", "path_hex": "696d6167652e62696e", "content_hex": "00ff0d0a0100"}
  ]
}
```

The optional `byte_profile` accepts only `binary-safe-v1`. Omitting it preserves
the original NUL-free profile and byte-identical old draft manifests. A string
such as `binary`, a boolean, null or an unknown profile is refused. Neither file
extensions, imported success flags nor inspected native reports select it.

Use the existing `scripts/fg_source_changes.mjs draft`, `prepare`,
`inspect-candidate` and `stage` commands from `SOURCE_CHANGE_AUTHORING.md` and
`VERIFIED_SOURCE_STAGING.md`. The normalized change request and resulting draft
bind the profile into their hashes even when the actual files contain no NUL.
An old text-profile review hash cannot approve a binary-profile request.

## Supported effects

Every existing regular-file operation supports this profile: replace, create,
delete, executable-mode change, explicit copy/rename, exact `replace-once`, and
original-byte-coordinate splices. Hexadecimal is the lossless input spelling for
arbitrary bytes. UTF-8 fields still encode exactly the supplied Unicode text;
there is no locale conversion or replacement of invalid UTF-8. Splices check
all original byte ranges before constructing results; ambiguous or overlapping
matches are still refusals. Empty files and conversions to/from empty content
remain distinct from absent files.

Creation and relocation destinations still need independently verified absence.
Before-blob commitments, file modes and complete original source membership are
checked, and the expected whole-tree root is independently derived. Opting in
never permits overwrites, unselected reads, symlinks, gitlinks, path traversal,
unrelated candidate changes or a new publication target.

The profile deliberately reuses the existing byte-exact, counted full-file hunk
encoder, including full native old/new object IDs and missing-newline markers.
It does not implement a JavaScript pack, delta, DEFLATE or compressed `GIT binary
patch` codec. The native exact-patch service still applies the patch and owns
admission. Binary bytes stay bytes throughout hashing, MIME transport and saved
patches; do not open/resave patch.diff with a text-normalizing editor. Never
execute a binary file merely because its executable bit is set.

## Bounds and trust

All existing ceilings remain: 32 native file effects (a rename costs two), 1 MiB
per file, 4 MiB retained before/after bytes, 1 MiB final operator patch, and the
shared 160,000-line encoded-patch limit. Full-file patches are not compressed;
a pair of large incompressible files may exceed the patch ceiling even when
each file fits its individual ceiling. Binary opt-in does not bypass any bound,
shorten cancellation checks or enable partial output. The shared encoder owns
Buffer-backed inputs before asynchronous hashing as well as Uint8Array inputs.

The standard candidate, journal, idempotency key, separate publication consent
and original-key outcome-recovery formats are unchanged. Native report matching
and expected-root verification do not independently verify every object in a
candidate pack, signatures, current authority, policy or semantic correctness.
Native `binary_bodies_included: false` reports may remain false: the operator's
original and constructed bytes plus expected object identities, not body prose
from an inspection report, define the intended effect.

Run `bash scripts/verify_source_changes.sh`. The binary tests apply complete
mixed patches with installed Git in both SHA-1 and SHA-256 repositories and
compare the exact expected trees and bytes. They cover all byte values, raw path
bytes, patch-looking contents, empty files, moves/copies, mode-only edits,
splices, ambiguity, preserved defaults, profile-bound consent, corruption,
caller-owned buffers, cancellation and exact finite budgets. Installed Git is a
test-only oracle, not a production fallback or the pinned native conformance lane.
These tests do not establish Rust fg execution or full-workspace correctness.

## Ordinary local editing, capture and replay

For a workspace created by `fg_source_workspace.mjs`, include the profile with
the exact paths to capture:

```json
{"paths_hex":["696d6167652e62696e"],"byte_profile":"binary-safe-v1"}
```

The existing `capture --paths PRIVATE_JSON` and `inspect-capture` commands handle
this selection; no new credential, network or execution option is introduced.
Capture reads only those paths and writes complete hexadecimal after-images for
changed files, or a deletion for a removed original. It does not inspect names
outside the selection, infer file types or run executable contents. The selected
profile must exactly match the saved changes profile when inspecting a capture.
Rewriting local hashes cannot widen that consent. An unchanged binary file may
be skipped even in the default profile; a mode-only change is still a change and
requires binary opt-in when its verified original bytes contain NUL.

`fg_source_replay.mjs` preserves this same normalized change request and profile
across its two independently selected source packages. All original selected
bytes and modes must still match, and the new base still requires fresh draft
consent. Full-binary patch transport uses the unchanged preparation/inspection
client; binary effect summaries need not disclose the bodies. Verified staging
returns the profile as context alongside the draft hash, without altering the
standard candidate or publication journal format.

The integration tests invoke actual CLI create/capture/inspect/prepare/stage and
lost-reply apply/recover with real files and HTTP/TLS native-schema peers. They
remove external workspace/capture inputs before recovery and require one upload
and the original key. They also reject an internally coherent extra-change
candidate, profile downgrades, rewritten profile bindings, changed replay inputs
and competing capture writers. The peers are fixtures, not a running Rust fg.
