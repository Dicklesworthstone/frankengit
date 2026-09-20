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
