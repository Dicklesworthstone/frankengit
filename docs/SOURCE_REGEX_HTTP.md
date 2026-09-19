# Bounded native byte-regex source search

`POST {repository-route}/api/v1/source/search-regex` exposes a model-free
regular-expression search over the same authority-selected, verified TreeFS
objects as literal and batch source search. It does not shell out to Git, invoke
a foreign regex engine, or install a new runtime, dependency, index or store.

This is a search capability under FG-032, not completion of its persistent
lexical/symbol indexes, progressive semantic refinement, immutable-generation
activation, or full acceptance campaign.

## Exact matching profile

The named profile is `byte-regex-lines-v1`. Its match policy is
`leftmost-longest-per-line`: return at most one span per matching physical line,
choosing the smallest starting byte offset and then the greatest ending offset.
Alternation order does not change that choice. This is not PCRE's
leftmost-first/capture policy or the literal endpoint's overlapping-hit policy.

Lines are delimited only by LF. No expression matches across LF, even `.` or a
negated class. An escaped `\n` is valid pattern syntax but cannot consume a line
separator. CR stays part of the input: `^name$` does not match `name\r`, whereas
`^name\r?$` does. Empty files have no physical lines; a final LF does not create
a phantom extra line. An actual empty LF-delimited line may match `^$`.
Expressions that match empty strings return one zero-length span per matching
line; they cannot create an unbounded sequence of empty results.

All patterns, paths, excerpts, offsets and columns are byte-oriented.
ASCII-insensitive matching folds only `A`–`Z`; it is not Unicode case folding.
Raw UTF-8 patterns therefore match their encoded bytes, and `\xNN` can express
arbitrary byte values, including NUL and non-UTF-8 bytes. Dot consumes one byte,
not one Unicode character. Binary regular files are not silently excluded.
Symlinks and gitlinks are counted within the selected scope but never followed.

Supported syntax:

- Concatenation, grouping `(…)`, alternation `|`, dot `.`, and line anchors
  `^` / `$`. Groups do not capture. Empty groups and alternatives are supported.
- `*`, `+`, `?`, `{m}`, `{m,n}`, `{m,}`; each finite repetition operand is at
  most 64. Quantifiers are neither lazy nor possessive.
- Byte classes, ranges and complement, such as `[a-z_]` and `[^0-9]`.
  Escape literal brackets or other metacharacters when necessary. Case folding
  applies before complement, so insensitive `[^a]` excludes both `a` and `A`.
- ASCII `\d`, `\w`, `\s` and their complements `\D`, `\W`, `\S`.
  Word bytes are ASCII alphanumeric bytes plus underscore. Whitespace is space,
  tab, CR, LF, vertical tab and form feed, subject to the line boundary above.
- ASCII word/non-word boundaries `\b` and `\B`; hexadecimal `\xNN`;
  `\0`, `\a`, `\f`, `\n`, `\r`, `\t`, `\v`; escaped punctuation.
  Inside a class, `\b` is backspace rather than a boundary.

Backreferences, lookaround, `(?…)` extensions (including noncapturing groups and
inline flags), Unicode properties, POSIX bracket classes, set-intersection
syntax, malformed ranges, repeated quantifiers and unsupported escapes refuse.
They never silently become literals or select an alternate engine.

## Requests and authorization

Use a fixed-length or chunked `application/x-www-form-urlencoded` body.
The source service must be enabled and the credential must hold the independent
`read` grant. Receive, issue, PR, review and outcome grants confer no source-read
access. Source read quotas and the existing repository/incarnation binding apply.
The listener retains its loopback/external-TLS-termination deployment boundary.

Do not send an `Idempotency-Key`. This operation does not seal a transaction,
stage objects, change refs, publish forge events, or create a recoverable write.

Required fields are `object_format` (`sha1` or `sha256`, matching the repository),
`ref` (a visible commit-valued ref), and `pattern_hex` (1–256 pattern bytes,
encoded as lowercase hexadecimal). Unknown fields and duplicate singleton
fields refuse.

Optional fields:

| Field | Meaning and bound |
|---|---|
| `case` | `exact` by default, or `ascii-insensitive`. |
| Repeated `path_prefix_hex` | Up to 128 raw repository path prefixes, each at most 4096 bytes and 32 KiB combined. Scope follows slash-component boundaries; it does not grant access. |
| `expected_head` | A previous response's `snapshot_token`. An intervening canonical write returns a conflict, even when the Git commit stayed unchanged. |
| `expected_commit` | An exact, nonzero, complete native object ID in the repository's format. A comparison, not an arbitrary-object lookup. |
| `max_matches` | Matching lines retained: 1–4096, default 200. |
| `max_bytes` | Selected blob bytes read: default/maximum 64 MiB. |
| `max_file_bytes` | Per-object source-read ceiling inherited from the source adapter: default/maximum 8 MiB. This also bounds metadata reads in that adapter. |
| `max_steps` | Aggregate VM work across all lines/files: 1–67,108,864, default the maximum. |

Example for an operator-configured TLS endpoint or protected loopback:

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --data-urlencode 'ref=refs/heads/main' \
  --data-urlencode 'pattern_hex=5c6228536f7572636551756572797c547265654361706162696c697479295c62' \
  --data-urlencode 'path_prefix_hex=637261746573' \
  --data-urlencode 'max_matches=50' \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/search-regex"
```

That pattern is `\b(SourceQuery|TreeCapability)\b`; the path prefix is `crates`.
Query fields narrow selection and do not grant access to hidden refs, other
repositories, host files or arbitrary objects.

## Results and failure semantics

The JSON response identifies `type: source_search_regex`,
`profile: byte-regex-lines-v1`, and the exact match policy. It carries tenant,
repository, incarnation, object format, selected ref, authority head/snapshot
token, source RCR, source commit and root tree. One selection supplies every
result; there is no preliminary head read that can race with a second selection.

The response echoes pattern bytes, case mode and normalized path prefixes.
`matches` is ordered by raw path bytes and then line number. Each row contains
native blob identity, zero-based `byte_offset`, one-based `line` and
`byte_column`, `match_length`, `excerpt_offset`, and lossless hexadecimal path
and excerpt bytes. Excerpts contain at most 416 bytes. A long match keeps its
complete span and sets `match_truncated_in_excerpt: true` when the excerpt does
not include the whole match. Excerpt truncation does not truncate the match.

`complete` means all selected regular files were searched. `match_limit` means
at least one additional matching line was observed beyond the returned limit.
Merely filling the result array does not establish truncation. Work exhaustion,
missing/corrupt objects, capability failures and cancellation refuse the entire
read rather than return an incomplete answer labeled complete or a fabricated
empty result.

Counters report files selected/read, bytes read/searched, lines searched,
program states and exact VM work. The lookahead matching line is charged.
Source responses label `read_only: true`, `transaction_created: false`, and
`published: false`. Text is JSON data, never executable HTML.

## Resource model

Compilation is bounded independently by 256 pattern bytes, nesting depth 16,
512 program states and 8192 expression-expansion steps. The expansion bound is
necessary even when the pattern emits no states: nested repetitions of empty
expressions otherwise multiply compiler work while evading the state ceiling.

Execution uses ordered Thompson state sets, not recursive backtracking.
At each input position a state retains the earliest starting thread; later
starts at that state cannot improve a leftmost match. Epsilon cycles are
deduplicated. Runtime storage is bounded by program size and reused for each
line, not allocated in proportion to source length. Input positions,
epsilon-stack pops and active byte transitions all consume the shared work
budget. Cancellation is checked at line boundaries and every 1024 VM work
steps. No assertion of throughput or end-to-end latency is made.

Existing tree, object, depth, source-fetch and response ceilings also apply.
Retained result paths plus excerpts are bounded to 2 MiB independently of row
count. The response uses the existing 8 MiB ceiling and is fully built before
HTTP success is emitted. Invalid patterns/requests return 400; VM or resource
exhaustion returns 413; stale snapshot/commit pins return 409. Infrastructure
failures are not successful no-match answers.

## Implementation and verification boundary

`fgit-forge::source_search::regex` owns compilation and verified-tree execution.
`OneNode` exposes caller-capability and independently authorized local snapshot
APIs. Regex, single-literal and batch-literal reads share the existing private
source-selection implementation. The HTTP route reuses the source gateway's
authentication, quotas and hostile-input body framing.

Added Rust tests cover syntax/refusals, leftmost-longest semantics, byte classes,
anchors, nullable repetitions, compiler expansion, work bounds, cancellation,
literal/scalar parity, native SHA-1/SHA-256 reads, path/hidden/ref/revocation
checks, fixed/chunked authenticated HTTP, explicit long/empty spans, stale
snapshots after forge writes and reopened-node read-only behavior.

The implementation session executed an independent Python Thompson-model
comparison against a POSIX regex reference: 36,840 span comparisons agreed,
with the model's state-work bound checked. This is separate algorithm-model
evidence, not execution of the Rust implementation or a full regex conformance
claim. Rust/Cargo were unavailable; compilation, Rust tests, native HTTP
execution, complete workspace checks and release gates remain unverified.

Focused checks, using the repository's pinned toolchain and build lane:

```bash
cargo test --locked -p fgit-forge source_search::regex
cargo test --locked -p fgit-node --test source_regex_http
cargo test --locked -p fgit-node --lib smart_http::server::source
```

These checks do not close FG-032 or establish persistent indexing, semantic
retrieval, generation activation, browser UI support or release readiness.
