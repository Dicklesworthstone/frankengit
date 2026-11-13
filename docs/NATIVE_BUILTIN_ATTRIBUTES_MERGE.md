# Native merges with built-in attributes

The explicit `builtin-attributes-v1` preparation profile permits ordinary text
merges in repositories containing `.gitattributes`. It evaluates supported rules
for the particular path being merged. For example, an unchanged declaration

```gitattributes
*.bin filter=lfs diff=lfs merge=lfs -text
```

does not prevent a clean two-sided merge of `src/main.rs`. A two-sided content
merge of a matching `.bin` file still reports `AttributesRequireDriver`: the
native planner never executes the LFS merge driver or another external program.

This is an additional bounded native profile. `path-v1` / `path-merge-v1` retain
their conservative refusal when ancestor attributes affect a content merge;
`exact-renames-v1` retains its existing content-identical rename semantics.
The new profile does not combine rename detection with attribute evaluation,
and it does not claim Git `ort` equivalence.

## Prepare a candidate

```sh
fg merge prepare "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  refs/heads/main /tmp/attributes-candidate.bundle \
  --trusted-local --profile builtin-attributes-v1 \
  --source-ref refs/heads/topic \
  --author 'Reviewer <reviewer@example.test>' \
  --timestamp 1788883200 --message 'Merge topic with native attribute rules'
```

The receipt identifies the selected profile, exact source/target/base and
candidate commit. A clean result creates a new bundle; conflicts create no
bundle. Preparation does not move a ref or publish a forge event. Inspect and
apply the candidate through the existing native merge admission flow.
`--method squash` selects the existing single-parent construction with the same
attribute evaluation. Both SHA-1 and SHA-256 repositories are supported.

The native CLI also accepts `--profile exact-renames-v1`, exposing the existing
exact-rename engine through `fg merge prepare`. Profile selection remains
mandatory. `fg merge resolve` continues to require `--profile path-v1`; it
refuses the other profiles instead of silently resolving a different conflict
set.

Existing HTTP pull-request/queue preparation forms and MCP candidate preparation
accept `profile=builtin-attributes-v1`. Native queue preparation and workflow
watchers accept the same token in their existing profile option. Defaults do
not change. Receipts preserve the selected token, and queue-prefix artifacts and
durable watcher configuration identities bind it distinctly from the older
profiles. Queue preparation retains its existing two-parent-only restriction.

The browser pull-request and merge-queue preparation forms offer the same
explicit profiles. A preparation response must report the profile requested
before its candidate can enter inspection. Changing the selection invalidates
prepared work and any pending inspection. Conflicts from the attributes or
exact-rename profiles remain visible, but cannot enter the direct-path resolver;
revise the source or explicitly prepare again with the direct-path profile.

## Attribute selection

Only repository-native, identity-verified blobs participate. For each ancestor
directory of a path requiring a two-sided content merge, `.gitattributes` must
be absent from all three input snapshots or be the identical regular-file entry
in base, target and source. Changed, newly introduced, deleted, nonregular or
otherwise inconsistent declarations produce `AttributesRequireDriver` for the
affected content merge. Trivial, identical and one-sided paths still reuse their
original objects without interpreting attributes.

Rules follow the declared subset of Git's
[attribute precedence](https://git-scm.com/docs/gitattributes) and
[path matching](https://git-scm.com/docs/gitignore): a nearer directory overrides
an ancestor, later matching lines override earlier lines for each attribute,
and later assignments on a line win. Paths and literals are raw bytes.

| Declaration for a matching path | Native content decision |
| --- | --- |
| No selected `merge`, `merge`, `merge=text`, or `!merge` | Existing bounded line merge; binary/NUL content still refuses as binary |
| `-merge` or `merge=binary` | `Binary` conflict when both sides need content merging |
| Built-in `binary` macro | Selects the built-in binary merge behavior, subject to ordinary assignment precedence |
| A later `-binary`, `!binary`, or a value assigned to `binary` | Suppresses an earlier expansion of that macro; other independently selected `merge` assignments retain their precedence |
| `merge=lfs`, `merge=union`, or another driver name | `AttributesRequireDriver`; no driver is invoked |
| Ordinary metadata such as `diff`, `text`, `eol`, `filter`, or `working-tree-encoding` | Does not execute a filter, normalize bytes, convert encoding, or select an external program |

The line merger consumes the exact native blob bytes, including CRLF. Attribute
evaluation does not introduce worktree normalization or ambient configuration.
No worktree, index fallback, global attributes file, `.git/info/attributes`,
`merge.default`, user hook or custom macro expansion participates.

Supported patterns include literals, `*`, `?`, directory-relative paths, leading
`/` anchors and `**` directory components. A pattern without `/` matches a
basename below its attribute directory. A trailing directory `/` does not
recursively apply to files beneath it. Quoted/escaped patterns, bracket patterns,
negative patterns, all-star components longer than `**`, custom macro declarations and other unsupported syntax
conservatively refuse content merging in their applicable attribute context.
They are never reinterpreted as a simpler literal. An unrelated, well-formed
custom-driver rule does not block a path it does not match.

## Bounded execution and failure

The existing graph, tree-depth, path, content-merge, conflict, object and output
limits remain in force. Attribute evaluation adds these fixed ceilings:

| Resource | Ceiling |
| --- | ---: |
| One attribute blob | 64 KiB |
| Distinct parsed attribute bytes | 1 MiB |
| Distinct parsed attribute blobs | 128 |
| Rules in one file / total rules | 1,024 / 8,192 |
| Pattern bytes | 1,024 |
| Assignments on one rule | 64 |
| Matching work | 4,194,304 charged steps |

Matching uses bounded dynamic programming with cancellation checkpoints, never
recursive wildcard backtracking. Parsed rules and work accounting are shared
across paths and across candidates within one queue-prefix preparation. A limit
failure returns the existing typed preparation budget error; it never silently
ignores a rule or publishes a partial candidate.

Regression coverage includes unrelated LFS rules, applicable driver and binary
refusals, nested precedence and resets, stable snapshot requirements, native byte
preservation, wildcard boundaries, cancellation, each new resource boundary,
legacy profile preservation, explicit selectors and distinct durable identity.
The profile is a native implementation slice, not a pinned-client differential
compatibility claim or a release gate result.
