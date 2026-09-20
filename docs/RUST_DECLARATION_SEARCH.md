# Native Rust declaration retrieval (FG-032 initial channel)

`fgit_forge::source_symbols` adds `rust-declaration-heads-v1`, a bounded initial
source-retrieval channel over verified TreeFS. It searches source-level names of
functions (including methods and nested functions), structs, enums, traits,
type aliases/associated types, modules, unions and `macro_rules!` definitions.
Names support exact or prefix matching, case-sensitively, plus kind and raw path
prefix filters. This is not compiler-resolved identity, a language server, a
persistent symbol generation, a reference/call graph, or FG-032 completion.

## Source and language contract

Only regular files ending in the exact bytes `.rs` are inspected. Other selected
regular files are counted as unsupported-language files, not read. Symlinks and
gitlinks remain explicit non-regular exclusions and are never followed. Source,
path and query capabilities all retain the existing TreeFS authorization and
verified native blob-read boundary. Both Git object formats are supported.

The scanner recognizes declaration heads in code, skipping nested comments,
ordinary/raw/byte/C strings, character literals, attributes and macro token
trees. Lifetimes and labels are distinct from character literals. Raw identifier
names omit `r#` for matching, but retain its presence and exact original name
byte span in results. BOM, shebang, LF/CRLF and UTF-8 comment/literal content do
not rewrite byte coordinates. The lexical reference is the Rust Reference's
[tokens](https://doc.rust-lang.org/reference/tokens.html) and
[items](https://doc.rust-lang.org/reference/items.html) descriptions.

This profile admits ASCII identifiers only. Non-ASCII code identifiers, invalid
UTF-8, unclosed comments/literals, mismatched delimiters and exhausted bounds
refuse the read; they are not successful empty results. It does not validate the
complete Rust grammar, normalize identifiers, type-check code, evaluate cfg,
expand macros, follow module/include paths, run builds or execute source. All
source configurations are searched, including cfg-disabled declarations.
Constants/statics, fields/variants, imports, references, call targets, closure
names and macro-generated definitions are not supported declaration kinds.
The absence of a result is therefore not proof that a compiler would have no
symbol by that name. Attributes/macros skipped are explicitly counted.

## Determinism and bounds

Results are ordered by raw path bytes, then original name byte offset. Names,
kinds, path, native blob, source head/commit/tree/RCR and exact spans identify the
observation. The excerpt contains only original bytes from the same physical
line. No model, rank heuristic or hash-map ordering affects results.

Source discovery and I/O retain their existing independent limits (20,000 files,
50,000 entries, 64 tree levels, 8 MiB per file, 64 MiB source). The scanner has
128-byte names, 128 levels of delimiter/comment nesting, at most 255 raw-string
hash delimiters, 20,000 declarations per whole query, and at most 67,108,864 work
units shared across files. Work includes UTF-8 validation bytes, consumed bytes,
tokens and raw-terminator comparisons; it is not CPU time or a latency promise.
Queries may narrow that work budget. Retained names/paths/excerpts share 2 MiB.

The result ceiling is a bounded prefix, reported only after observing another
matching declaration. Reaching the exact result count is not evidence of a
truncated result. Each read file is fully lexically scanned before contributing
results, and malformed scanned source cannot leak an earlier partial success.
A result-limit response need not scan later files. Completion covers only this
named profile inside the capability and requested path scope.

## Verification

The standalone command compiles the exact std-only production scanner and its
21 tests, with no rewritten model. It covers every supported head, lexical
exclusions, exact coordinates, raw names, lifetimes, shared/exact resource limits,
cancellation, deterministic generated head-position comparisons, and 4,096
hostile byte inputs. A separate forge test covers the closed query profile.

```bash
./scripts/verify_source_symbols.sh
cargo test --locked -p fgit-forge source_symbols
```

The implementation container lacks Rust/Cargo. Local whitespace, source and blob
checks are not Rust execution. An optional workflow invokes the standalone
repository command using `nightly-2026-08-31`; its observed result applies only
to its exact commit and scanner module, never to TreeFS/native-node integration,
full-workspace or release gates. No bead is closed by this slice.

## Native node and authenticated HTTP

`OneNode::search_source_symbols_in` uses a caller-owned sparse TreeFS capability
and an independently supplied visibility restriction. Neither can widen current
canonical hidden-ref policy. `search_source_symbols_snapshot_local_in` is the
whole-repository operator read exposed only after independent HTTP read
permission. Its optional expected head/commit are checked inside the same native
selection that supplies every file and result. Lexical errors remain typed
`SymbolReadError::Syntax`; source/authority errors retain the existing node error.
No workspace, index, transaction, generation activation or outbox effect is
created, and no error starts a fallback scan or changes the requested source.

```text
POST {repository-route}/api/v1/source/search-symbols
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <read-scoped credential>
```

Required fields are `object_format` (`sha1` or `sha256`), full `ref`, and
`name_hex` (lowercase hex for the ASCII identifier, without a raw `r#` prefix).
Optional `match` is `exact` (default) or `prefix`. Repeated `kind` accepts only
`function`, `struct`, `enum`, `trait`, `type`, `module`, `union`, and `macro`.
Repeated `path_prefix_hex` has the existing 128-prefix/4096-byte-per-path/32-KiB
aggregate bound and slash-component semantics. These filters never grant access.

Optional `expected_head` and `expected_commit` preserve an exact observation.
`max_matches` is 1-4096 (default 200); `max_work` is 1-67,108,864 (default maximum).
`max_bytes` and `max_file_bytes` may narrow the 64-MiB/8-MiB source-read limits.
Unknown/duplicate singleton fields, noncanonical hex, unsupported query kinds,
wrong object format, malformed pins or resource widening return HTTP 400.
No `Idempotency-Key`, URL query, Git-Protocol header, or alternate media type is
accepted. Fixed-length and chunked forms use the existing bounded framing.
There is no cursor: the bounded result prefix names its source snapshot and
reports its limit explicitly. Narrow the query or raise its admitted result
limit instead of silently continuing on another snapshot.

For example, search declarations beginning with `Thing` beneath `src`:

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_READ_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'name_hex=5468696e67' \
  --data-urlencode 'match=prefix' \
  --data-urlencode 'path_prefix_hex=737263' \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/search-symbols"
```

The response is `source_search_symbols`, schema 1, with the named scanner
profile and `authority_class: deterministic-derived`. It explicitly reports
`compiler_resolved: false`, `macro_expansion: false`, and `cfg_evaluated: false`.
It retains the repository/incarnation, exact source head/token/RCR/commit/tree,
normalized query fields, completion, read/work/exclusion counts, and matches.
Each match includes `name_hex`, kind, raw-identifier flag, `path_hex`, native
`blob`, byte offset/length, one-based physical line and byte column, and original
`excerpt_hex` plus excerpt offset. Raw identifiers' spans cover the name only.
Existing snapshot-pinned source/blob reads can retrieve the complete file.

Response counters describe the scoped selected corpus; unsupported-language
files count toward selected files but not file reads. Completion covers this
profile only, not all Rust compiler symbols or other languages. The renderer
checks namespace, snapshot pins, object formats, ordering, counters, query
membership, span arithmetic and exact name/excerpt agreement before responding.
Names, paths, source and error text cannot inject HTML, commands or permissions.
The complete JSON response must fit the existing source response ceiling.

Unsupported/malformed `.rs` source returns HTTP 409 `symbol_source_unsupported`,
without echoing source text or diagnostic paths. The typed local error preserves
its path and byte offset for an already-authorized local caller. Resource limits
return 413; cancellation returns timeout; unavailable objects remain errors.
These never produce partial success, fabricated empty results, publication
ambiguity, implicit compiler execution or an older-source fallback. Existing
401/403 credential, revocation, service-switch and rate-limit semantics apply.

Four protocol/renderer tests and eight native integration tests are added. They
use actual OneNode imports, native patch preparation/admission, verified TreeFS,
and the production authenticated TCP listener. Cases cover both hash formats,
raw-byte filenames, comments/macros/raw identifiers, scopes, revocation, exact
limits, syntax errors, cancellation, unpolled work, snapshot movement and reopen.
They do not replace the separate compiler-resolution, persistent-symbol-index,
real-browser or full-workspace acceptance campaigns. Rust/Cargo are unavailable
locally; native compilation and these tests remain unexecuted in this session.

```bash
cargo test --locked -p fgit-node --test source_symbols_http
cargo test --locked -p fgit-node --lib smart_http::server::source
cargo check --locked -p fgit-forge -p fgit-node --all-targets
```
