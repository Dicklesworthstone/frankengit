# Exact source edits from original byte ranges

Related: FG-032, `SOURCE_EDIT_REPLACEMENTS.md`, `SOURCE_EDIT_RESULT_TREES.md`,
`REMOTE_SOURCE_EDITING.md` and plan sections 26–27. This is an external authoring
adapter, not an authenticated Agent Protocol intent or another publication path.

An agent can express a few exact changes at retrieved byte offsets without
rewriting the full desired file or hand-authoring a unified patch. The splice
owner verifies a complete original blob against an independently retained native
Git identity and compares each selected original range byte-for-byte. It then
passes ordinary owned replacements to the existing patch compiler. Native Rust
remains responsible for patch application, repository policy and publication.

## Private-file command

Use the existing executable with the new `splice` operation:

```bash
node scripts/fg_source_patch.mjs splice \
  --splices-file /private/edit/splices.json \
  --output /private/edit/change.patch
```

The input and original bodies must be bounded, private, regular, single-link
files in owner-private 0700 directories. Output must not already exist. The
operator never modifies those originals, opens credentials, contacts a server,
executes repository text, or creates a Git checkout. It publishes a new 0600
patch through the existing create-only, synchronized, readback-verified writer.
Pre-publication cancellation creates no final patch. Once publication starts it
is drained; output failure retains the exact original receipt on stderr when
possible, never a claim that the patch disappeared.

A closed input example replacing the first three bytes of `src/file` is:

```json
{
  "schema": "frankengit-source-splices-v1",
  "object_format": "sha1",
  "files": [{
    "path_hex": "7372632f66696c65",
    "before": {
      "file": "/private/edit/original",
      "blob": "<independently retained original native blob hex>",
      "mode": 33188
    },
    "after_mode": 33188,
    "edits": [{
      "byte_start": 0,
      "before_hex": "6f6c64",
      "after_hex": "6e6577"
    }]
  }]
}
```

Both hash domains are supported. Blob identities are full lowercase unprefixed
SHA-1/SHA-256 hex in the selected domain. Do not derive the trust anchor merely
by hashing an untrusted file that happens to be present. A source package or
another independent source selection must establish the original identity and
path membership. An excerpt alone is not a complete original blob.

`byte_start` is a zero-based ORIGINAL-file byte offset, not a character, column,
line, or offset in a previously modified buffer. `before_hex` names exactly the
bytes being replaced; its length determines the range end. `after_hex` is the
literal replacement. Empty `before_hex` inserts; empty `after_hex` removes bytes.
Removing every byte leaves an empty file; it does not delete the file itself.
New-file creation and file deletion remain explicit full-replacement operations.
Use decimal mode 33188 for a regular file or 33261 for an executable.

Every range refers to the same original regardless of input ordering or length
changes in earlier ranges. Edits are sorted by original offset, files by raw
path. Adjacent ranges are allowed. Overlapping ranges and duplicate start offsets
(including two insertions at the same point) refuse. Combine same-point effects
into one instruction. The implementation never searches for a matching substring,
adjusts stale coordinates, normalizes newlines, decodes UTF-8 source, or accepts a
successful prefix. No-op instructions and collectively no-op file changes refuse.
An empty edits list is valid only for an explicit executable-bit change.

NUL-bearing source/results require `--binary literal` or `--binary delta` at
compilation, exactly as for full replacements. There is no automatic binary downgrade or alternate patch
fallback. Raw paths, CRLF, non-UTF-8 bytes, and missing final LF retain their
existing compiler behavior. `--max-patch-bytes` and `--timeout-ms` retain their
existing finite bounds. `compile --changes-file` and its receipts are unchanged;
`splice --splices-file` cannot be enabled by an extra field in a replacement plan.

The splice receipt adds `splice_profile`, `splice_count`, `expected_bytes`,
`inserted_bytes` and `preimages_verified`. Those counts describe the instructions,
not patch hunk counts. `source_membership_verified` and `publication_attempted`
remain false. Keep the plan and generated patch private: the current compiler
uses whole-file text hunks or reversible binary members (literal or delta), so
its output can contain far more original data than the small edited spans.

## Library and native acquisition

`spliceSourceFiles(format, files, limits, check)` takes the same shape but uses
`before: { bytes, blob, mode }` and `edits: [{ byte_start, before, after }]` with
Uint8Array/Buffer values. It returns detached ordinary replacements and checked
instruction counters. This raw-byte operation does not itself choose a patch
encoding or make a request. `compileSourceSplices` feeds those results through
the existing compiler and requires explicit `{ binary: 'literal' }` or
`{ binary: 'delta' }` for binary encoding.

`captureSourceSplices(selection, files, credential, options)` composes with the
existing prepare/inspect owner, requiring `expected_result_tree` selected
independently of the server response. It checks original bytes, all ranges and
the exact path set before connecting; owns input buffers before the first await;
shares one finite deadline and response allowance; and verifies returned file
identities, modes and the expected root. Mismatch, cancellation, or exhausted
bounds never retry, widen, silently rescan, or apply another candidate.

Saved candidates use the existing root-pinned capture format. Splice instructions
are not a new canonical HTTP form or an authorization grant. Feed the generated
patch into the established `prepare-verified` workflow when independently verified
source membership and durable evidence are required. Review, staging, one-shot
apply and original-key recovery remain separate explicit decisions.

## Bounds and verification

At most 32 disjoint existing paths, 32 KiB aggregate path bytes, 4096 bytes per
path, 64 components, and 4096 total splices are admitted. Original and final file
bodies are each at most 1 MiB, with 8 MiB aggregate source and result ceilings.
Expected-range and inserted bytes have separate 8 MiB totals; all these limits
can only narrow in the library. Final lengths and the entire interval inventory
are checked before allocating result bodies. Buffered intermediate copies are
bounded, not claimed to fit in a single 8 MiB total heap allowance.

The CLI plan has a separate 512 KiB JSON ceiling, including hex expansion. Patch
output still has the independent 1 MiB ceiling and record bound; a valid splice
can therefore be too large to encode. This is not a compact/minimal-diff or
transfer-size optimization. No production dependency or Rust implementation is
introduced.

```bash
node --test tests/operator/source_edit_splices.test.mjs \
  tests/operator/source_edit_splices_cli.test.mjs
bash scripts/verify_source_edits.sh
```

The focused tests use complete production modules, real private files, CLI child
processes, and native-schema HTTP peers. Installed Git independently applies and
reverses generated text/binary patches to indexes in both hash formats, comparing
roots with independently constructed desired indexes. A deterministic 2000-case
original-coordinate oracle, exact/insufficient budgets, input ownership, stale
spans, overlapping instructions, competing exporters and lost stdout are covered.
These are not live Rust-server, native policy/CAS, pinned conformance-tier,
hardware power-loss, full-workspace or Agent Protocol completion evidence.

The explicit delta profile is preserved for both `compile` and `splice`. It
uses the existing bounded binary member planner and reports `delta_members` and
`literal_members`; splice receipts additionally retain their own range counts.
Small edits to large binary originals can therefore fit the patch ceiling when
whole forward/reverse literals do not. This does not widen the source, result,
instruction, or output budgets and does not add an automatic profile fallback.
