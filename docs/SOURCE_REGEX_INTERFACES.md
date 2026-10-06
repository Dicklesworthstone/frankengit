# Native byte-regex search interfaces

This source-read slice connects the existing native bounded Thompson matcher to
MCP. It does not implement another regex engine, read indexes, or change literal
search. Owning work: FG-096 (MCP source retrieval); canonical source selection
remains in the node's existing capability-aware reader.

## MCP

Use `frankengit_source_search` with `operation: "regex"`, a full `reference`, and
exactly one of `pattern` (UTF-8 bytes) or `pattern_hex` (lowercase byte pairs).
The source-read launch grant is independently required. All existing source
pins and source limits apply, including `expected_head`, `expected_commit`,
`path_prefixes_hex`, `ignore_ascii_case`, `max_files`, `max_file_bytes`,
`max_total_bytes`, and `max_matches`. `max_regex_steps` bounds aggregate matcher
work across every searched file; its maximum/default is 67,108,864 steps.

```json
{"operation":"regex","reference":"refs/heads/main","pattern":"^(pub )?fn [a-z_]+","path_prefixes_hex":["737263"],"max_matches":20}
```

Omitting `operation` retains exact literal `needle_hex` behavior. Pattern fields
are not accepted by that profile. Batch literal search and the tool count are
unchanged. Indexed retrieval is a separate, unpublished change; it is not
included in this slice and there is no automatic index/regex/literal fallback.

## Semantics and completeness

The profile is line-oriented bytes, not Unicode/PCRE or compiler symbol search.
It returns one leftmost-longest span per matching physical LF-delimited line.
It never crosses LF. CR remains ordinary source data, so `$` does not strip CR
from CRLF. An empty file and the position after a final LF are not invented
lines. Empty lines and zero-width matches are valid; captures, backreferences,
lookaround and external drivers are not supported. The native compiler owns
syntax and its 256-byte pattern, 512-state and finite compilation-work bounds.

Byte offsets are zero-based; line and byte-column coordinates are one-based.
The exact span can exceed its bounded 416-byte excerpt. Such a row has
`match_fully_in_excerpt:false` and null `match_bytes_hex`; it is not presented
as a complete copy of the matched bytes. Complete zero-width spans encode as
an empty `match_bytes_hex` string, not null. Raw paths and excerpts retain hex
representations even when not UTF-8. Sources are regular files only; symlinks
and submodules are never followed. Prefixes are component-bounded selectors,
not grants or filesystem paths.

A match ceiling yields an explicitly incomplete prefix only after the native
engine observes an extra matching line. VM work, object, source-byte, or output
exhaustion instead fails the whole read. It cannot yield a successful empty or
partial answer. Source selection, every object read and cancellation share one
request. No refs, objects, indexes, approvals or retry keys are written.

## Validation boundary

Authored tests cover strict schemas, independent grants, source pins, raw query
bytes, actual persisted SHA-1/SHA-256 reads, longest spans, blank lines, CRLF,
missing final LF, long excerpts, match ceilings, work exhaustion, cancellation,
reopen parity and the real MCP protocol. Compilation and these Rust tests were
not executed in the implementation environment, which lacks Rust tools.
Static checks are not a passing native gate or a performance claim.

## CLI

The same native reader is available through the explicit `fg search --regex`
profile, separately from the default literal, indexed-current and symbol modes:

```sh
fg search --regex ./fgit-data TENANT_ID REPOSITORY_ID refs/heads/main \
  --trusted-local --pattern '^(pub )?fn [a-z_]+' --path src --max-matches 20
```

Use `--pattern-hex` for arbitrary pattern bytes. `--expected-head` takes the
returned algorithm-qualified `snapshot_token`; `--expected-commit` takes an
exact nonzero native commit. Pins constrain the same selection that supplies
all searched bytes. `--max-regex-steps` is an aggregate VM budget, while the
existing file/count/total-byte limits remain independent. `--trusted-local`
explicitly authorizes whole-repository reads; patterns and path filters cannot.

The CLI returns bounded JSON only after the node has closed successfully. It
preserves the exact line and excerpt semantics above and distinguishes exit 0
for a complete answer (including zero matches), exit 3 for a match prefix, and
exit 2 for parsing, source/work, output or shutdown failures. It never shells
out to Git or a regex command. Standard global `--timeout-secs` remains in use.

Additional authored tests exercise argument and output boundaries, and a real
`CARGO_BIN_EXE_fg` integration target covers fresh-process SHA-1/SHA-256 searches,
CRLF/blank/last lines, long spans, zero hits, truncation and failed work budgets.
These tests and native compilation have not been executed in this environment.
