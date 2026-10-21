# Independent intended results for remote source edits

`plan-results` and the result-selection profile extend the existing
`prepare-verified` workflow. The caller prescribes the exact after-blob identity,
regular/executable mode, or deletion for every changed path independently of the
native preparation response. This prevents an internally consistent but unwanted
same-path edit from being accepted merely because its review replays correctly.

This is **result verification, not independent patch application**. No package,
plan, candidate, or locally saved receipt authorizes publication. The native
server still owns patch semantics, bundle/object validation, current policy,
expected-old admission, sealed requests, and the authority-head conditional write.
See [remote source editing](REMOTE_SOURCE_EDITING.md) for that unchanged lifecycle.

## Plan from explicit desired files, offline

Keep files and output in an owner-private 0700 directory. Inputs must be private
regular single-link files with normalized absolute paths, without symlink aliases.
Start with the independently retained positive source expectation already used
for the selected-source package:

```json
{
  "format": "sha1",
  "commit": "<independently selected commit hex>",
  "files": [{"pathHex": "7372632f6d61696e2e7273", "blob": "<original blob hex>"}]
}
```

The file specification names the desired complete bodies as data, not executable
commands. For example, changing `src/main.rs` and adding `src/new.rs`:

```json
{
  "files": [
    {"path_hex": "7372632f6d61696e2e7273", "kind": "file", "body_file": "/private/edit/main.rs"},
    {"path_hex": "7372632f6e65772e7273", "kind": "file", "body_file": "/private/edit/new.rs"}
  ]
}
```

Use `kind: "executable"` for executable regular files. Deletion is explicitly
`kind: null, body_file: null`; a zero-length file is an empty blob, NOT deletion.
Raw paths are lowercase hexadecimal. Desired bodies preserve all original bytes,
including binary data, CRLF, and missing final LF. They need not be a checkout.

```bash
node scripts/fg_source_edit.mjs plan-results \
  --source-expected /private/edit/source-expected.json \
  --files /private/edit/desired-files.json \
  --output /private/edit/result-expected.json
```

No token, endpoint, or network option is accepted. The planner hashes each body
with the native Git `blob <length>\0` framing and the independently selected
SHA-1/SHA-256 domain. The output is create-only, synchronized and read back. Keep
its `expected_sha256` independently. A file already published is not undone by
late cancellation or lost stdout; the existing retained-result/error receipt
reports local publication uncertainty.

Planning does not yet verify the source package or prove new-path absence. The
receipt explicitly says `source_membership_verified: false`. A missing path in
the positive selection merely becomes an explicit creation intent. Preparation
must still prove that absence before it makes any native request.

## Prepare with the retained plan

Use the normal explicit edit selection, patch, and source package, substituting
the result plan as `--expect`:

```bash
node scripts/fg_source_edit.mjs prepare-verified \
  --selection /private/edit/selection.json \
  --package /private/edit/selected-source.json \
  --expect /private/edit/result-expected.json \
  --patch-file /private/edit/change.patch \
  --token-file /private/edit/read-token \
  --output /private/edit/candidate
```

The selection's `paths_hex` must equal the result plan's complete path set.
Subsets, extra paths, duplicate/ancestor collisions, wrong hash domains, unsafe
paths, and unchanged blob-and-mode effects are refusals, not implicit edits.
Do not derive the plan from the server's returned inspection; that would discard
the independence this profile supplies.

Before any network I/O, preparation owns all input primitives and authenticates
the selected base commit, complete needed parent trees, and original full blobs.
Explicit creation paths must be absent at an actually missing tree entry. An
unproved existing subtree, occupied path, symlink, or gitlink cannot establish
absence. The shared tree-transition kernel then derives the exact intended root
from that verified base plus the caller's after commitments, preserving all
untouched child identities. No server-provided after tree chooses this root.

After preparation and inspection, the candidate root and every reported
blob/mode/deletion must match the independent result. The existing original-byte,
review-span, candidate-commit-byte, and exact tree-effect validators still run.
A valid Git candidate with different content in an allowed file therefore fails,
even when all its server receipts and echoed patch hash are self-consistent.
Source movement or disagreement never causes a base refresh or wider retry.

## Durable verification and compatible readers

Result-bound captures use `frankengit-source-edit-files-v4` and evidence profile
`frankengit-source-edit-evidence-v3`. The manifest binds the same four private
payloads: `capture.json`, `candidate.bundle`, `source-package.json`, and
`source-expected.json`. The expected file now contains the versioned result plan;
there is no new native upload field or authority token.

`inspect` rehashes and rederives the desired root. `stage` copies the same owned
proof and plan into its private candidate. The original-key intent already binds
the candidate manifest, so `apply`, offline `status`, and `recover` cannot silently
drop result constraints. Missing/corrupt plans or relabeled evidence refuse.
Damage after dispatch does not remove its marker or allow a second submission.
Only the original pinned evidence can restore that local custody.

The result receipt adds `requested_result_verified: true`, `intended_tree`, and
`result_commitments_from: "independent-expected-selection"`. Positive-source and
creation-only expectations retain their old v2/v3 serialization and do not gain
this claim. Ordinary preparation still emits v1. Old clients refuse v4; upgrade
the reader instead of stripping evidence or manufacturing a lower-version root.

For binary review, matching a desired blob commitment is not the same as reading
and hashing the candidate bundle's omitted after body. Such paths remain in
`unverified_after_paths_hex`. The profile does not expand the pack or establish
its complete object closure. A correct result does not prove that the submitted
patch was applied, that the code is semantically correct, or that the server is
currently authorized to publish it. Native validation remains necessary.

Keep outputs private: source packages contain full original selected files and
sibling tree names, even when only one file changes. Plans expose path and blob
identities. Offline replay verifies retained evidence, not current permissions.

## Bounds and library surface

Plans admit 1–32 disjoint changed paths, each at most 4096 raw bytes and depth 64,
with 32768 aggregate path bytes. The offline planner accepts at most 1 MiB per
desired body and 8 MiB total; each source/specification/expectation input is bounded
by 128 KiB. Native preparation still retains its independent patch, bundle,
inspection, and source-package ceilings. These are buffered input bounds, not an
aggregate heap measurement or a preemptive JavaScript execution guarantee.
One deadline covers input checks and acquisition; begun local writes drain.

Library callers use `sourceEditResultSelection(source, changes, check)` with
`{pathHex, bytes: Uint8Array | null, kind}` rows, then the existing
`captureVerifiedSourceEdit`/`validateSourceEditEvidence` and verified custody APIs.
`saveSourceEditResultPlan` is the same private file owner invoked by the CLI.

```bash
bash scripts/verify_source_edits.sh
# Focused result-profile execution:
node --test tests/operator/source_edit_results.test.mjs \
  tests/operator/source_edit_results_custody.test.mjs
```

The tests use complete production modules, actual HTTP sockets, private files,
CLI child processes, and independently Git-created objects/bundles in both hash
domains. They include valid-but-unwanted candidates, malformed plans, exact
source joins, legacy serialization, downgrade attempts, ownership before I/O,
concurrent exporters, lost stdout, and SIGKILL after dispatch with original-key
recovery. Peers are explicit native-schema fixtures, not a live Rust server,
authorization/CAS verification, full-workspace gate, or Agent Protocol broker.
