# Native MCP code review

The repository-scoped `fg-mcp` server exposes the existing native review engine,
not a second diff implementation or a subprocess. Launch configuration and all
read-only session limits from `MCP_READ_ONLY_SERVER.md` still apply.

## Independent read grants

`frankengit_source_compare` requires `--allow-source`.
`frankengit_pull_diff` requires **both** `--allow-source` and `--allow-pulls`.
Neither `--allow-issues` nor any other read grant implies either permission.
Disabled tools are omitted from discovery and refused before handler input or
repository work. The handler independently repeats the same permission check.
No tool admits a transaction, executes scripts, creates a checkout, casts a
review vote, or grants merge permission.

## Ref comparison

Example `tools/call` arguments for `frankengit_source_compare`:

```json
{
  "before_ref": "refs/heads/main",
  "after_ref": "refs/heads/topic",
  "comparison": "direct",
  "context_lines": 3,
  "paths_hex": ["737263"]
}
```

Each ref uses exactly one of `before_ref`/`before_ref_hex` or
`after_ref`/`after_ref_hex`. The UTF-8 spelling is a full `refs/...` name;
hex preserves arbitrary native ref bytes. Neither is a filesystem path or an
arbitrary-object lookup. Both references must be visible at the selected head.

`direct` compares their two trees. `merge-base` compares their unique best
common ancestor with the requested after commit. Missing ancestry, multiple
best bases, corrupt objects, resource exhaustion and cancellation refuse the
operation; no synthetic merge base or successful partial diff is returned.

## PR comparison

Example `frankengit_pull_diff` arguments:

```json
{"number":"7","expected_version":"3","comparison":"merge-base"}
```

Both positive decimal-string fields are mandatory. Obtain the version from PR
list/show; the native reader compares it at the **same authenticated head** used
for the code, ref visibility and recorded PR tips. A mismatch is a tool error.
The default mode is `merge-base`; an explicit `direct` compares recorded target
to recorded source. Later pushes or deleted branches do not silently refresh the
PR's recorded tips. Native closed/merged PR review behavior is unchanged. The
answer carries the exact PR number and version that were checked.

Both tools accept `expected_head`, a strict current-head `snapshot_token` pin.
They do not substitute a retained historical head. `expected_before` and
`expected_after` optionally compare the requested native commit IDs (nonzero,
lowercase hex in the repository's object format); they never select arbitrary
objects. For merge-base mode, `expected_before` binds the requested before tip,
not the computed base. Changing the head or pins is a new review request.

## Output and limits

Each result names the repository/incarnation, object format, authenticated head,
raw ref names, requested commit pair, actual compared-before commit, and both
tree IDs. Entries are sorted by exact raw path and distinguish additions,
deletions, modifications, mode changes, and type changes. Content is explicitly
`identical`, `object_only`, `binary`, or `text`. Directories count as entries, not
regular files. Symlink payloads remain data; submodule identities are not followed.

Text hunks carry half-open original byte spans, zero-based line spans and exact
`before_hex`/`after_hex`. CRLF, arbitrary non-NUL byte sequences and a missing
final LF are preserved. No lossy text conversion, normalization, rename guess,
attribute/textconv driver or external Git runs. Native diff algorithm identity
is retained as a diagnostic field. Byte counts, offsets, line counts and native
PR counters are decimal strings, never floating-point JSON numbers.

Optional controls and hard MCP ceilings:

| Field | Default | Accepted range |
|---|---:|---:|
| `context_lines` | 3 | 0..20 |
| `max_changes` | 64 | 1..128 |
| `max_blob_bytes` | 1,048,576 | 1..1,048,576 |
| `max_output_bytes` | 65,536 | 1..262,144 |
| `max_diff_work` | 1,000,000 | 1..1,000,000 |

`paths_hex` accepts at most 32 distinct component prefixes, 4,096 bytes each and
16 KiB total. Prefixes narrow traversal/output, not authorization. Labels such
as `src` do not also select `src-old`. At most 32 text files and 256 hunks are
returned. Native ancestry, source and tree limits remain in force. The native
output-byte budget charges raw path and hunk bytes; a separate 2 MiB ceiling
bounds complete encoded tool JSON. The entire response is validated and encoded
before success, including exact hunk lengths and bound identities.

`complete=true` describes only the selected path-prefix scope. There is no
diff pagination or silent truncation. Over-budget requests fail; narrow paths
or adjust limits within the documented ceiling. `merge_permission=null` and
`repository_changed=false` explicitly separate review data from authority.
This local-owner profile is not remote authentication, a path-capability broker,
a full Intent Run, or a complete FG-096 implementation.

## Verification boundary

Tests exercise all read-grant combinations, strict argument and limit handling,
raw/non-UTF-8 refs and hunks, native direct/merge-base reports, malformed report
bindings, binary/mode/gitlink distinctions, and exact span validation. A native
node scenario constructs and publishes a root, branch, child patch and PR,
reopens SHA-1 and SHA-256 nodes, calls the MCP protocol handlers, checks exact
hunks, stale head/version pins and resource refusals, and confirms that review
requests do not advance authority. It also checks recorded PR tips after a later
branch write. These test cases were written in an environment without Cargo or
rustc and have **not been executed**. No package, conformance or release pass is
claimed. Intended command: `cargo test --locked -p fgit-cli --bin fg-mcp`.
