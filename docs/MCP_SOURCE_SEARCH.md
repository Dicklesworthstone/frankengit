# MCP source retrieval

The launch-time `--allow-source` grant now exposes `frankengit_source_search`
alongside source tree/blob, history and review reads. Repository content cannot
select another storage root, tenant, repository, principal or capability.
The source grant is whole-repository read authority; query path prefixes narrow
that scope. These tools do not publish authority, build indexes or execute Git.

## Exact literal search

Call `frankengit_source_search` with arguments such as:

```json
{
  "reference": "refs/heads/main",
  "needle_hex": "546f6f6c4572726f72",
  "path_prefixes_hex": ["637261746573"],
  "max_matches": 20
}
```

This searches the literal bytes `ToolError` under `crates`. Hex is lowercase,
even-length and exact; no Unicode normalization, regex expansion, host-path
interpretation or binary-file exclusion occurs. Needles contain 1–256 bytes
and cannot contain LF. Optional `ignore_ascii_case` affects only ASCII bytes.
Symlink payloads and submodule contents are not searched.

The result includes the authority `snapshot_token`, source RCR, commit and tree
coordinates from the same node selection used for the entire scan. Optional
`expected_head` and `expected_commit` are preconditions checked inside that
selection; they are not a separate preliminary read. A moved snapshot is a
failure, not an automatic retry against different source.

Matches retain byte-exact paths/excerpts in hex. `excerpt_utf8` is optional data,
not instructions. Byte offsets are zero-based; lines and byte columns are
one-based. Position and work counters are decimal strings, not floating-point
JSON numbers. Results are ordered by raw path bytes and byte offset.

`complete: false` with `truncated_reason: "match_limit"` means an additional
match was observed. There is no pagination cursor. Narrow the scope or raise
the limit with the returned snapshot/commit pins to repeat against the same
source. Exhausted byte/file limits, cancellation, corrupt or missing objects,
and unavailable or hidden refs return errors, never successful empty results.

## Bounds

The defaults are 20 matches, 2,000 files, 1 MiB per file and 8 MiB total file
bytes. Callers can request at most 100 matches, 20,000 files, 8 MiB per file and
64 MiB total. The node's existing entry, depth, fetch and runtime budgets also
apply. At most 32 slash-bounded path prefixes may contain 16 KiB of decoded
bytes in total. The adapter refuses responses exceeding 256 KiB of retained
path/excerpt bytes or 1 MiB of encoded tool-result JSON rather than silently
truncating them. Narrow `path_prefixes_hex` or `max_matches` after this refusal.

## Shared-read batch retrieval

`frankengit_source_search_batch` takes the same source selection, scope, pins and
work limits, but replaces `needle_hex` with an ordered `needles_hex` array:

```json
{
  "reference": "refs/heads/main",
  "needles_hex": ["546f6f6c4572726f72", "536f757263655175657279", "546f6f6c4572726f72"],
  "path_prefixes_hex": ["637261746573"],
  "max_matches": 5
}
```

This performs one native multi-needle scan, not several independently selected
searches. All slots share one authority head, source RCR, commit and tree.
File reads and byte budgets are shared; reported work counters are batch totals.
The first and third duplicate needles intentionally keep separate result slots.

Each entry in `results` carries `query_index`, `needle_hex`, `matches`,
`match_count`, `complete` and `truncated_reason`. The index is an exact decimal
string in input order. An absent needle remains a complete zero-match answer
even when another needle hits its limit. Top-level `complete` is true only when
every slot is complete. The profile is `literal-bytes-batch-v1`.

A batch contains 1–32 needles. `max_matches` applies to each needle and defaults
to 5. The requested needle count multiplied by `max_matches` must not exceed
200. The 256 KiB retained path/excerpt budget and 1 MiB encoded-result ceiling
apply to the whole batch, not separately to each slot. A failed source read,
snapshot precondition, cancellation or aggregate budget refuses the whole
operation; the adapter never returns whatever subset happened to finish first.
