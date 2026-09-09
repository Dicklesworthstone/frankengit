# Source search over a pinned repository snapshot

`fg search` searches native repository content without exporting a pack or
creating a checkout. The node selects one authenticated current ref, verifies
source identities, applies TreeFS capability/path restrictions and returns
lossless byte-coordinate matches. It does not write an index, stage objects,
seal a transaction, move a ref, append forge events or change an outbox.

**Implementation status:** the core, node adapter, CLI and tests are committed.
Rust compilation and native execution have not run in this editing environment.
The executed checks below are not a passing production conformance gate.

## Command

For an existing local node and known repository coordinates:

```bash
fg search "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main \
  --trusted-local \
  --literal 'admit_merge' \
  --path crates \
  --max-matches 100
```

Omit `--path` to search every regular file admitted by this local read profile.
Repeat it to select multiple slash-bounded prefixes. `src` selects `src` and
its descendants, never `src2`. Prefixes must be canonical relative TreeFS paths,
not host paths or globs. Duplicate prefixes are normalized into a sorted set.

The default object format is SHA-1. Use `--object-format sha256` for a SHA-256
node; a format mismatch is not silently guessed away. Refs must directly name
commits. Annotated-tag peeling is not part of this command.

`--ignore-ascii-case` folds only ASCII letters. No Unicode normalization or
Unicode case-folding occurs. A literal query must contain 1 through 256 bytes
and no LF byte. Other byte values, including NUL, are supported by the explicit
hexadecimal form:

```bash
fg search "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main --trusted-local --literal-hex 00ff
```

`--literal` and `--literal-hex` are mutually exclusive. `--path-hex` specifies
raw path-prefix bytes, including valid non-UTF-8 names. Invalid hex, repeated
singleton options, unknown options and out-of-profile limits refuse before
repository opening. `fg search --help` prints the complete argument contract.
Regex, symbol and semantic search are not inferred from the literal input.

## Completeness is part of the result

Exit status has one explicit meaning:

| Exit | Meaning |
|---|---|
| 0 | Complete result for the declared regular-file scope, including zero matches |
| 3 | Bounded prefix of matches; at least one additional match exists |
| 2 | Invalid request, unavailable/corrupt source, budget, cancellation, shutdown or output error |

The command does not use grep's zero-match exit convention. Consume `complete`,
`truncated_reason` and `match_count` from the JSON result. A count of zero is
absence evidence only when the answer is complete for the requested scope.

The matcher looks for one additional hit after filling `--max-matches` before
claiming truncation. Exactly N hits with a limit of N can therefore be a complete
answer. Source/read/traversal/byte-budget errors are not successful partial
results or empty results: they return an error and no search JSON.

Every regular-file body in scope is eligible, including binary data and invalid
UTF-8. Symlink entries and gitlinks are excluded and counted in
`non_regular_entries`; their targets are not followed or searched. Directory
entries are traversal containers, not content matches. A complete result does
not claim anything about excluded entry kinds or paths outside its scope.

## Result identity and byte coordinates

The JSON object contains `type: "source_search"`, `profile:
"literal-bytes-v1"`, repository ID, selected source RCR, native commit and tree
IDs, ref bytes, query bytes, case mode, path prefixes and completeness.
Source coordinates remain pinned throughout the read; concurrent ref movement
does not splice files from different trees into one answer. The result is a
statement about those identities, not a promise that the ref is still current
when a consumer acts on it.

Matches are ordered by raw full-path bytes, then byte offset. Each includes:

- `path_hex` and the native `blob` identity;
- zero-based `byte_offset`, one-based `line` and one-based `byte_column`;
- `match_length`, `excerpt_hex` and zero-based `excerpt_offset`.

Lines split on LF. CRLF and UTF-8 remain original bytes, so columns are byte
columns rather than display columns. Overlapping matches are included. Excerpts
contain the entire match plus bounded same-line context, at most 416 bytes.
Hex fields preserve exact bytes and prevent repository content from emitting
terminal-control sequences through the CLI. They are not lossy display strings.

`files_selected` describes the discovered scope; `files_read`, `bytes_read`
and `bytes_searched` describe the work performed, including truncation
lookahead. These are payload counters, not total disk/authority I/O counters.
The node is explicitly closed before the JSON is emitted. Write and flush
failures remain errors rather than successful report delivery.

There is no continuation cursor in v1. When narrowing or rerunning a limited
query, compare its source commit/tree identities before combining results.

## Authority and bounds

`OneNode::search_source_in` accepts caller-owned `TreeCapability`, current
ref-visibility policy and runtime request context. Query prefixes intersect
that scope and cannot enlarge it. The existing TreeFS traversal contract still
applies: required container reads must be authorized; search does not widen a
leaf-only grant to make a refused ancestor traversal succeed. Foreign,
revoked or expired capabilities refuse. Hidden and absent refs use the same
`RefUnavailable` outcome. Private node sources refuse objects outside the
selected authenticated closure and verify native identities and kinds.

`OneNode::search_source_local_in`, used by the CLI, is a different boundary:
an already-authorized local operator grants whole-repository read authority.
`--trusted-local` acknowledges that assumption; it is not a credential check
or a remote authentication service. This entrypoint must not be exposed as an
unrestricted remote endpoint. Its read-only top-level grants come from the
same selected tree, and explicit query prefixes narrow them before traversal.
It never mints a remotely reusable workspace handle.

Default scan ceilings are 200 returned matches, 50,000 discovered entries,
20,000 regular files, depth 64, 8 MiB per source object and 64 MiB of searched
file payload. `--max-matches` admits 1 through 4096; `--max-files`,
`--max-file-bytes` and `--max-bytes` can narrow their defaults. At most 128 query
prefixes and 32 KiB of combined prefix bytes are admitted. The local root-grant
count is separately capped at 4096 because capability matching is linear in
grant count; wider trees require a narrower query rather than quadratic work.

The search object-read phase additionally caps reads at 100,000 and 128 MiB,
with per-object limits enforced at the fabric read boundary before allocation.
Capability fetch budgets remain shared and may be tighter. The node's existing
authority-materialization limits still apply separately. The literal matcher
checks cancellation at most every 4 KiB; tree/object loops have their own
checkpoints. These are logical acceptance ceilings, not measured peak-memory,
latency or throughput guarantees.

## Code and validation

`fgit-forge::source_search` owns the bounded literal matcher, scoped traversal
and result model. `fgit-node` binds it to selected authority and verified source
objects. `fgit-cli` owns parsing, explicit local trust and result serialization.
No external production dependency was added.

Fourteen Rust test functions were added: six core/query/matcher tests, four
embedded-node tests, and four CLI parser/encoding/output tests. They cover
exhaustive short-input matching against scalar windows, overlap/line/byte
coordinates, case modes, capability/ref refusals, scope isolation, both native
hash formats, truncation lookahead, no-mutation checks and output failures.
They are registered but unexecuted in this editing environment.

The real-binary campaign creates independently encoded native objects and runs
fresh CLI processes for nine search cases and seven refusal cases per format,
including repetition and canonical-state comparisons:

```bash
python3 scripts/e2e/source_search_smoke.py --fg /absolute/path/to/fg
```

It verifies blob identities, exact coordinates, original excerpt bytes, scope,
completeness and unchanged repository state. A missing executable is an error,
not a skipped success. Its separate `--self-test` mode validates only fixtures
and the result checker and reports `rust_executed: false`.

Executed here: Python syntax/help checks, fixture framing/native-hash checks
for both formats, checker self-tests rejecting 24 corrupted-report cases,
a missing-binary refusal, Rust lexical/delimiter inspection and byte-for-byte
GitHub blob verification for the generated source files. Cargo, rustc, rustfmt,
Clippy, native Rust tests and the complete real-binary campaign were unavailable.
These checks are not Rust compilation or production-runtime evidence.

This is a usable bounded literal-scan interface, not the complete FG-032
indexed lexical/symbol/semantic search product. Persistent search generations,
ranking, remote authorization/gateway integration and broader conformance
requirements remain separate work. No bead is closed by this source change.
