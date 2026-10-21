# Exact source replacements without hand-written patches

Related: FG-032, `NATIVE_EXACT_PATCH.md`, `REMOTE_SOURCE_EDITING.md`,
`SOURCE_EDIT_RESULT_TREES.md`, and `SOURCE_EDIT_RESULT_PLANS.md`.

`scripts/fg_source_patch.mjs` converts explicit full original/desired file bytes
into a bounded native-compatible patch: unified text or explicit binary literals.
It is an offline encoder, not a Git engine, diff heuristic, repository reader,
authorization check or publisher.
It never invokes Git, a shell, hooks, external encoders or a network endpoint.

## Private-file operator

Create an owner-private 0700 directory. Original/desired body files and the plan
must be private, regular, single-link files with normalized absolute paths.
Each original blob ID must be selected independently, not obtained by hashing
whatever happened to be in an untrusted local file. The compiler hashes the
original bytes and refuses an identity mismatch. Tree/path membership remains a
separate verification step in `prepare-verified`.

A changes file uses this closed schema (33188 is regular, 33261 executable):

```json
{
  "schema": "frankengit-source-replacements-v1",
  "object_format": "sha1",
  "changes": [{
    "path_hex": "7372632f6d61696e2e7273",
    "before": {
      "file": "/private/edit/original.rs",
      "blob": "<independently retained original native blob hex>",
      "mode": 33188
    },
    "after": { "file": "/private/edit/desired.rs", "mode": 33188 }
  }]
}
```

Use `before: null` for a creation and `after: null` for a deletion. A zero-byte
file is a real file, not a deletion. Both sides null, identical body-and-mode
pairs, duplicate paths and file/descendant collisions refuse. Creations do not
claim absence: the evidence-backed preparation path must prove it separately.

```bash
node scripts/fg_source_patch.mjs compile \
  --changes-file /private/edit/replacements.json \
  --output /private/edit/change.patch
```

The command writes a new 0600 patch, synchronizes it, reads it back and returns
its SHA-256 and size. It cannot overwrite an existing destination. No credential
is accepted. `--max-patch-bytes` may narrow 1..1048576, and `--timeout-ms` may
narrow the operation to 1..300000 milliseconds (default 30000). Cancellation
before local publication leaves no final patch; an already-started publication
is drained. A lost stdout reports the retained receipt on stderr when possible.
Exit 0 is confirmed local compilation, 2 is refusal, and 4 means a published or
possibly published file needs inspection. None indicates repository mutation.

Use the output with the existing `fg_source_edit.mjs prepare-verified` command,
independent package/expectation, explicit source-edit selection, and read token.
Use `plan-results` or an independently selected `expected_result_tree` to reject
a server-returned candidate that is internally consistent but not your intended
result. Compilation does not stage or apply that candidate. Review, one-shot
publication and original-key recovery remain separate explicit operations.

## Explicit binary literal encoding

NUL-bearing original or desired bodies require an explicit operator opt-in:

```bash
node scripts/fg_source_patch.mjs compile \
  --changes-file /private/edit/replacements.json \
  --output /private/edit/change.patch \
  --binary literal
```

The private changes-file schema stays the same; it cannot enable binary encoding
by embedding another field. Omitting the flag retains the existing text-only
refusal behavior and receipt shape. Unknown/repeated profiles are refused, not
converted to a default. The opt-in receipt names
`frankengit-source-replacements-binary-v1` and adds `binary_files`, counting file
sections with emitted binary bodies. Text-only sections retain exactly the same
patch bytes. Pure executable-bit changes do not fabricate content members.

For each changed file containing NUL on either side, the encoder writes full
forward AND reverse Git `literal` members, complete native index IDs, and raw
path/mode headers. Creation, deletion, binary-to-text, text-to-binary and empty
results are distinct. Each member uses deterministic stored DEFLATE blocks,
zlib framing with Adler-32, and Git base85 rows with exact length prefixes and
zero padding. The production encoder invokes no compression library, native
zlib, Git, shell or external service. It does not select deltas or reinterpret
binary bytes as text.

This is intentionally **uncompressed** binary encoding, not a transfer-size
optimization. Both complete bodies, framing and base85 expansion count toward
the same 1 MiB patch ceiling; a file admitted by the body limit can still be too
large to encode. Exact member-byte and record costs are checked before framed
bodies are allocated. No compression fallback, increased allowance, successful
prefix or omission of the reverse member is permitted. Keep the patch private:
it contains the complete selected original and desired bodies.

The resulting patch uses the native binary preparation path already selected by
`prepare_trusted_patch_in`. An older/disabled native service may refuse it; the
client neither retries with another grammar nor weakens original/result pins.
Compilation remains offline; `prepare-verified`, inspection, explicit one-shot
publication and original-key recovery remain separate operations. Binary bodies
omitted by native review are still reported as omitted: compiler output does not
prove the returned pack's full object closure or grant publication authority.

## Library path

`compileSourceReplacements(format, changes, limits, check)` accepts the same
raw paths but uses owned `Uint8Array`/Buffer body values instead of filenames:
`before: { mode, blob, bytes }` and `after: { mode, bytes }`. It returns the exact
patch and per-path old/new native IDs and modes. Limits can only narrow the
profile. Input buffers and returned patch storage are detached. Passing
`{ binary: 'literal' }` as a compiler option enables the binary profile; other
values refuse. `captureSourceReplacements` accepts the same option while
retaining one deadline, aggregate response allowance and mandatory independent
result-tree constraint. No binary option is added to native HTTP form fields.

`captureSourceReplacements(selection, changes, credential, options)` composes
that encoder with the existing native prepare/inspect client. This convenience
path **requires** an independently selected `expected_result_tree`, verifies the
exact selected path set before any connection, and compares inspected old/new
identities and modes against the compiled changes. No fallback, source refresh,
mutation or retry is introduced. The returned capture uses the ordinary saved-
candidate workflow and retains the root constraint, not an authorization grant.

## Exact bytes and bounds

The deterministic encoder sorts raw paths, emits C-quoted byte names and full
native index identities, and uses one whole-file hunk per text content change. It
preserves CRLF, non-UTF-8 bytes, empty files, executable bits and missing final LF.
This is not a minimal diff: unchanged lines inside an edited file are repeated.
Native Rust still checks exact original bytes and coordinates during application.
A generated patch that exceeds its bound is refused, not truncated or rewritten.

The profile admits at most 32 disjoint effects, 32768 aggregate path bytes,
4096 bytes per path, 64 path components, 1 MiB per body, 8 MiB total original
bytes, 8 MiB total result bytes, 1 MiB patch output and 131072 emitted records.
These are buffered resource ceilings, not a total heap/latency guarantee.
NUL-bearing bodies refuse unless binary literals were explicitly selected.
Symlinks, gitlinks, rename/copy records, unsafe paths and no-op changes always
refuse. There is no automatic binary opt-in, newline normalization, offset
search or interpretation of body text.

## Verification and claims

```bash
node --test tests/operator/source_edit_replacements.test.mjs \
  tests/operator/source_edit_replacements_cli.test.mjs \
  tests/operator/source_edit_binary.test.mjs \
  tests/operator/source_edit_binary_cli.test.mjs
bash scripts/verify_source_edits.sh
```

Tests run the complete encoder/client and actual CLI, private files and HTTP
sockets. Installed Git is used only as a nonproduction oracle: its index applies
the generated patches, and its root is compared with an independently assembled
desired index. Both hash formats, quoted raw paths, mode/empty/delete/newline
cases, all unequal pairs from six small line sequences, bounds, concurrency and
lost output are covered. Native-schema HTTP peers are fixtures, not a live Rust
patch service. These tests do not establish full workspace, release, source
membership, authorization, freshness, pack closure or Agent Protocol claims.

The binary tests apply and reverse actual patches with installed Git, comparing
both resulting roots to independently built indexes in SHA-1/SHA-256. They cover
creation/deletion, every byte value, raw names, mixed text/binary/modes, empty
files, 65535-byte stored-block boundaries, exact and insufficient allowances,
input ownership, cancellation, output races and lost stdout. A test-only zlib
decoder and independent bigint base85 folding verify framing/checksums/padding
for every short length and larger boundaries. Production does not import those
test helpers. Native-schema HTTP peers exercise the real preparation client,
not the Rust service. A local test pass is not a live native interoperability,
full-custody, full-workspace, release or power-loss campaign.
