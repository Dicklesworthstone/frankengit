# Persisted Rust declaration search through MCP

`frankengit_source_symbols` supports focused reads of the native persisted Rust
declaration index. This extends the existing tool without consuming another MCP
tool slot. It delegates source selection, current visibility, generation ancestry,
immutable payload verification, name-directory pruning and declaration lookup to
the existing native symbol owners.

## Select source behavior explicitly

| `source_mode` | Read behavior |
| --- | --- |
| Omitted or `scan` | Existing direct source scan, with the original result shape. Malformed Rust refuses the scan. |
| `indexed-exact` | Read the active persisted symbol generation only if its original source authority still matches the selected current source. Unrelated repository metadata changes can make this mode stale. |
| `indexed-current` | Independently select the currently visible ref and verify its native commit and root tree, then reuse the existing index only for that same source. Keep current and indexed provenance separately. |

The indexed modes require `--allow-source` and the selected host's source-read
authority. An ordinary `--trusted-local` launch supplies operator authority; a
sponsored launch authenticates canonical `source-read` on every invocation.
Before calling the local native readers, the adapter verifies that an agent has
an active source-read request for this repository namespace. Metadata authority,
a completed response reservation, index generation or source-write permission
does not imply source-read permission. The same original request deadline and
response-byte reservation cover lookup and disclosure. Revocation takes effect
on the next independently authenticated call, including after a process reopen.

No mode builds or refreshes an index. The indexed modes never fall back to a
source scan. An operator can initialize or refresh indexes through the existing
native symbol-index commands or the explicitly configured index-maintenance
service. Missing, stale, corrupt or over-budget index data is a refusal, never an
empty successful answer.

```json
{
  "name": "frankengit_source_symbols",
  "arguments": {
    "reference": "refs/heads/main",
    "source_mode": "indexed-current",
    "name": "parse",
    "match": "prefix",
    "kinds": ["function"],
    "path_prefixes_hex": ["737263"],
    "max_matches": 50,
    "max_payload_bytes": 8388608
  }
}
```

The path prefix above is the exact bytes `src`. Prefixes are slash-bounded, so
`src` includes `src/lib.rs` and excludes `src2/lib.rs`. Names are case-sensitive
ASCII identifiers without `r#`; returned `raw_identifier` distinguishes a raw
declaration such as `fn r#type()`. Supported kinds remain function, struct, enum,
trait, type, module, union and macro.

## Source authority and generation identity are separate

`expected_head` and `expected_commit` constrain the **current** read in both
indexed modes. A moved pin refuses; the tool does not silently select another
snapshot. Successful indexed responses expose:

- Top-level current `snapshot_token`, `source_head`, `source_rcr`, `source_commit`
  and `source_tree` coordinates.
- `current_source`, independently selected by the native reader, including the
  tenant, repository, incarnation, ref bytes, native format and forge root.
- `indexed_source`, the original source coordinates authenticated by the persisted
  manifest. These coordinates are never overwritten with current metadata.
- `distinct_provenance`, true when the two source records differ.
- `index_token` and `index_number`, identifying the generation actually read.

Metadata-only changes may alter the current head/RCR/forge coordinates while
leaving the native commit/tree unchanged. `indexed-current` can reuse the same
generation in that case. A changed commit or tree, changed namespace/ref,
unavailable ref, or inconsistent same-head provenance refuses reuse. A generation
does not confer a source-read grant.

Clients can retain an anti-rollback checkpoint and send both
`minimum_index_token` and `minimum_index_number`. The token is the canonical
`alg:<algorithm-code>:<lowercase-digest>` spelling; the number is a positive decimal
u64 string. The native generation authority proves that the selected active
generation satisfies the retained ancestry floor. These fields do **not** select
an exact historical generation, retain it, or create a pagination cursor. A future,
incompatible or unavailable floor refuses instead of falling back. Supplying only
one field is invalid.

## Completion and coverage answer different questions

Indexed responses have `type: "source_symbol_index_search"`,
`profile: "source-symbols-indexed-v1"` and schema version 1. The underlying
declaration and index profiles are also named explicitly.

`complete` describes matching declarations in the recorded Rust tables under the
given query. When an additional matching declaration exceeds `max_matches`, the
response contains the ordered bounded prefix with `complete: false` and
`truncated_reason: "match_limit"`. `pagination_supported` is false. Narrow the
name, kinds or paths, or increase the result limit up to its ceiling. The tool
rejects `after`, exact `index_token`/`index_number` selectors and other invented
continuation arguments.

`coverage_complete` independently describes the entire recorded Rust-file
inventory. An omission-tolerant native index can return useful declarations from
supported files while reporting omitted files explicitly. `omissions` carries
each exact `path_hex`, native blob identity, source byte count, typed reason and
applicable byte offset or limit. Reasons include unsupported identifiers,
malformed syntax, invalid UTF-8 and per-file/table limits. A complete query with
incomplete coverage cannot establish that a declaration is absent from omitted
files.

Coverage metadata covers the whole index even when query paths narrow matching.
An out-of-query omission remains visible as part of that inventory. Both the
ordinary source profile and canonical sponsored `source-read` authorize this
whole-repository inventory for the selected visible source; path prefixes are
query filters, not narrower authorization grants. Unsupported non-Rust files and
non-regular entries have their own counters and are not represented as indexed
Rust declarations.

Every match preserves the original scanner's byte contract: exact name/path/blob,
byte offset, one-based line and byte column, match length, excerpt start, and raw
excerpt bytes with a UTF-8 convenience field when representable. Scan and indexed
adapters share validation of these coordinates, name/kind selection, slash-bounded
scope and deterministic raw path/offset order. Source text is untrusted content.

## Independent finite budgets

| Input | Default | Maximum | Meaning in indexed modes |
| --- | ---: | ---: | --- |
| `max_matches` | 20 | 100 | Returned declaration prefix; an observed extra match marks it incomplete. |
| `max_files` | 2,000 | 20,000 | Selected persisted declaration tables read. |
| `max_file_bytes` | 1 MiB | 8 MiB | Referenced original source size for a selected table. |
| `max_total_bytes` | 8 MiB | 64 MiB | Aggregate referenced source sizes of selected tables. |
| `max_payload_bytes` | 8 MiB | 32 MiB | Aggregate immutable manifest, name-directory and declaration-table bytes read. |
| `max_work` | 67,108,864 | 67,108,864 | Native shared declaration-query work budget. |

File and source-byte limits remain meaningful even though indexed lookup does not
read source blobs. Native name-directory pruning may avoid irrelevant tables;
whole-index inventory counters therefore need not fit a narrowly selected query's
table/source limits. `tables_read`, `payload_bytes_read` and `work_units` report
actual indexed work. `source_blobs_read` and `source_bytes_read` are zero; current
mode still performs bounded native commit/root-tree metadata verification.

All counters in the new indexed response use decimal strings, including generation
numbers and byte offsets; `counter_encoding` is `decimal-strings-v1`. Schema version
is a JSON integer. The legacy scan result is unchanged. Retained match/omission
bytes share a 256 KiB ceiling before hex expansion, and the complete encoded result
has a 1 MiB ceiling. Exhaustion refuses the whole response. Request cancellation
is checked through native access, report validation, row rendering and final
bounded encoding; no new context or budget is acquired to finish output.

Representative refusals include `symbol_index_uninitialized`,
`symbol_index_stale`, `symbol_index_generation_unavailable`,
`symbol_index_unavailable`, `resource_limit`, `read_cancelled`,
`incomplete_index_generation` and `invalid_index_generation`. Native current-source
pin/visibility refusals retain the existing source-read mapping. No response
claims canonical or index publication: `repository_changed`, `index_changed`,
`transaction_created` and `published` remain false.

This is the bounded `rust-declaration-heads-v1` parser profile. It does not resolve
compiler symbols, expand macros, evaluate cfg branches or execute source code.

## Regression coverage

The adjacent MCP tests exercise actual native source admission and persisted
index publication/reopen in SHA-1 and SHA-256 repositories: scan/index equivalence,
MCP protocol dispatch, name/kind/path filtering, raw identifiers, truncation,
metadata-only revalidation, stale source refusal, explicit native refresh,
retained-generation floors, partial corpus coverage, budget refusal and grant
isolation. Additional unit tests reject malformed generation pairs and tampered
provenance/spans and exercise cancellation and output retention limits. The test
source describes these scenarios; its presence is not an execution claim.
