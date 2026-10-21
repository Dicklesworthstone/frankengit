# Compact checked source splices

Related: FG-032, `SOURCE_EDIT_SPLICES.md`, `SOURCE_EDIT_REPLACEMENTS.md`,
`COMPACT_SOURCE_PATCHES.md` and `MULTI_HUNK_SOURCE_PATCHES.md`. This connects
the existing byte-splice and exact-line owners without introducing a new diff
engine, authority path or publication operation.

A small byte edit need not retransmit the entire original and desired file.
Select the existing shared line encoder explicitly:

```bash
node scripts/fg_source_patch.mjs splice \
  --splices-file /private/edit/splices.json \
  --output /private/edit/change.patch \
  --patch-profile bounded-line-hunks-v1
```

`bounded-line-hunks-v1` separates distant edits into bounded exact-line hunks.
`trim-common-lines-v1` trims identical complete leading/trailing lines around a
single changed region. Both retain three unchanged context lines where possible,
preserve the exact before/after byte images and native identities, and use the
UNCHANGED `browser/source-patch.mjs` production implementation. There is no
additional diff algorithm, fuzzy application, line-ending normalization, or
server-selected encoding in this adapter. The byte offsets and expected ranges
are still checked against the entire pinned original BEFORE line encoding.

The option belongs to the operator, not the untrusted JSON plan. It is valid only
for `splice`, not `compile`, and cannot be combined with `--binary`. NUL-bearing
inputs/results are refused by either line profile; select the existing explicit
binary literal/delta path separately. Unknown/repeated profiles refuse. No
failed diff, oversized patch or exhausted budget retries with another profile.
Omitting `--patch-profile` preserves the original compile/splice output bytes and
receipt shapes. Opt-in receipts name `frankengit-source-splices-compact-v1` and
include `patch_profile` and total `hunks` alongside the existing splice counters.

The complete original/result pairs share the line owner's 4 MiB input ceiling,
in addition to the splice owner's per-file, path, range and byte ceilings. A
one-line edit in an 800 KiB original can therefore fit a small patch even though
the full-file representation cannot fit the unchanged 1 MiB output limit. Two
distant changes can become two compact hunks. This is a bounded representation
choice, not a promise of minimal output or unrestricted full-file rewriting.

For multi-hunk encoding the unchanged owner shares 16,777,216 work units and
1,048,576 line positions across all files, with maximum edit distance 256,
66,049 trace cells and 4,096 hunks. Exhaustion refuses the complete compilation.
The single-hunk profile uses linear complete-line scans. Neither accepts caller
budget increases. The wrapper checks the narrower 1 MiB patch / 131,072 record
allowances (or smaller caller limits) before returning its output or beginning
network/filesystem publication. The shared owner may temporarily construct up
to its own 8 MiB bounded output before that narrower check; the output allowance
is not claimed as a whole-process allocation limit.

### Asynchronous library and acquisition

`compileCompactSourceSplices(format, files, { patchProfile, ...limits }, check)`
is an asynchronous companion to the unchanged synchronous `compileSourceSplices`.
It verifies and owns all originals/instructions before the first hash await,
uses the same LF-based byte-line owner, and checks the emitted file inventory
against the exact independently computed replacement identities. It returns a
Buffer patch and the existing per-path before/after IDs and modes plus profile,
record and hunk counts. `check` is used throughout the shared owner's hash/line
work, including its cooperative yields.

`captureCompactSourceSplices(selection, files, credential, options)` accepts
`patchProfile`, the narrowing compiler limits and the existing signal/deadline/
response options. It requires an independently selected `expected_result_tree`,
checks source/ranges/path scope before connecting, and uses the same operation
clock for compilation and native prepare/inspect. It checks returned before/after
identities and modes in addition to the native capture owner's root and commit
validation. Source membership, complete pack verification, policy and publication
authority remain outside this compiler. Saved candidates retain their normal
root-pinned capture format; the extra encoding receipt is not an authority token.

Focused verification includes SHA-1/SHA-256 forward AND reverse Git index
application, raw paths/bytes and modes, newline edges, all unequal pairs of six
small line sequences, large files, separate hunks, exact/insufficient limits,
profile conflicts, async cancellation, caller mutation, real HTTP acquisition,
actual private-file CLI processes, competing exporters and lost stdout:

```bash
node --test tests/operator/source_edit_compact_splices.test.mjs \
  tests/operator/source_edit_compact_splices_cli.test.mjs
```

These use installed Git only as a local test oracle and explicit native-schema
HTTP peers, not a live Rust source service, pinned conformance tier or native
admission/CAS campaign. Existing source-edit verification targets are retained.
