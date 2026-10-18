# Separate exact hunks for distant source edits

`patch_profile: "bounded-line-hunks-v1"` extends the existing verified authoring
encoder. It avoids retransmitting large unchanged regions BETWEEN edits, not
only at the edges of a file. For example, two one-line modifications near
opposite ends of a 982,500-byte file exceed the existing 1 MiB patch budget with
`trim-common-lines-v1`. The multi-hunk profile represents the same after-image
with two small hunks and the same full old/new blob commitments.

Use it directly in changes JSON:

```json
{
  "schema": "frankengit-source-changes-v1",
  "patch_profile": "bounded-line-hunks-v1",
  "changes": [{
    "path_hex": "7372632f6d61696e2e7273",
    "operation": "replace-once",
    "before_utf8": "old exact text",
    "after_utf8": "new exact text"
  }]
}
```

Ordinary local-editor workflows select the same profile in the file passed to
`fg_source_workspace.mjs capture --paths`:

```json
{"paths_hex":["7372632f6d61696e2e7273"],"patch_profile":"bounded-line-hunks-v1"}
```

The existing capture, offline inspection, prepare, verified stage and explicit
base-replay paths preserve this choice. Both the path selection and captured
changes must agree on it. The encoding is part of the reviewed draft; another
profile's consent hash cannot authorize this draft. Binary input still requires
the separate `byte_profile: "binary-safe-v1"` selection. No profile is inferred
from file extensions or selected automatically after a failure.

## Exact behavior and bounded work

The encoder owns the original and resulting byte arrays before asynchronous
work. It compares complete byte lines including their LF, CR and missing-final-LF
state. Matching edges are fixed first; a deterministic insertion/deletion
frontier search identifies remaining changed spans. Three context lines surround
each group. Groups separated by at most six common lines merge; larger gaps
produce separate hunks. The encoder retains full native old/new blob IDs and
reports the actual number of hunks for every file effect. It performs no fuzzy
application, character decoding, semantic merge, rename detection, network or
production Git subprocess call.

The profile has fixed additional bounds:

- 1,048,576 input lines across all before/after file pairs;
- 16,777,216 charged scan/comparison/frontier work units per patch;
- 256 inserted/deleted lines in each modified file's changed middle, retaining
  at most 66,049 signed 32-bit frontier cells at once;
- 4,096 emitted hunks across the complete patch.

Creation/deletion or a whole-file empty transition requires no frontier search;
line, byte, work and output limits still apply. All existing 1 MiB file/operator
patch, 4 MiB retained authoring bytes, 32-effect and source-proof limits remain.
The new algorithm yields to the event loop during large scans and search, and
checks the caller's cancellation/deadline throughout. No partial patch is
returned on budget exhaustion. An explicit choice of the older whole-file or
edge-trim profile remains available for high-distance rewrites; it does not
raise their existing output limits or transfer previous consent.

Default full-file encoding and the earlier `trim-common-lines-v1` bytes remain
unchanged. Multi-hunk encoding is not promised to minimize serialized patch size
or match another diff tool's choice among equivalent alignments.

## Verification boundary

Run `bash scripts/verify_source_replay.sh`. New tests include forward/reverse
installed-Git application in SHA-1 and SHA-256, raw path/content bytes, a tiny
independent dynamic-programming reference, seeded repeated-line cases, exact
line/distance/hunk limits, byte-work exhaustion, asynchronous cancellation and
actual private-file CLI capture/prepare/stage/apply/recovery composition. The
HTTP/TLS peers are native-schema fixtures using Git only as a test oracle, not a
running Rust `fg` server. They do not establish Rust admission/authorization/CAS,
complete candidate-pack closure, semantic compatibility or whole-repository
correctness. Root/target checks and original-key recovery remain unchanged.
