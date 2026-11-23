# Native pull-request labels

Labels are durable metadata for an existing, visible native pull request. They
are available through the CLI, MCP, repository HTTP API and PR browser. Open,
closed and merged PRs retain their label sets. A legacy merge-only receipt has
no native metadata subject and cannot acquire labels through these commands.

Labels have an independent canonical aggregate and exact version. Replacing
labels does not advance the PR lifecycle/content version, move refs, change the
review subject, or make an approval stale. Every committed replacement records
the authenticated actor. There is no separate label database or catalog.

## Complete replacement and exact identity

A command supplies a PR number, the exact predecessor **label** version, a
complete desired label set and a durable retry key. The label version is not the
PR metadata version, discussion version, review version, or repository head.

CLI and MCP encode version counters as decimal strings; HTTP uses JSON numbers.

| Read state | `labels_version` | `labels_actor` | `labels` |
|---|---|---|---|
| Existing PR whose labels have never been written | `"0"` | `null` | `[]` |
| Existing PR after a replacement | Positive decimal string | Last label actor | Complete sorted set |
| Existing PR after clearing | Positive decimal string | Clearing actor | `[]` |
| Missing or hidden PR, dedicated labels read | `null` | `null` | `null` |

The first replacement uses `expected_version=0`. A successful replacement
advances only the label stream by one, including an explicit clear or a
replacement with the same set. An already-written empty set is not an unset
stream: use its positive version for subsequent replacements. Stale exact
versions receive a canonical refusal; adapters do not read latest state to
repair a command during admission or retry.

Sets contain at most 32 distinct labels. Each label must be nonblank, have at
most 64 UTF-8 bytes, and contain no control characters. Adapters sort input by
exact UTF-8 bytes before admission and reject duplicates. They preserve case,
spaces and Unicode spelling. `bug`, `BUG`, and ` bug ` are three distinct labels.
Labels are literal untrusted content and grant no permissions or approvals.

After a lost or uncertain write response, retain the identical repository
binding, principal, PR number, expected label version, complete label set and
original retry key. A new JSON-RPC request ID or HTTP connection does not create
a new durable identity. Do not refresh the version, replace the key, or change
labels while reconciling an unknown outcome. An identical retry recovers the
original terminal receipt even after later replacements or a restart.

Replacement receipts bind the original canonical `labels`, `expected_version`,
transaction and terminal decision. On commit, `labels_version` is that original
command's successor version; on refusal it is `null`. These receipts describe a
historical outcome, not the current set. A current read cannot establish whether
a missing response committed, because another writer may already have replaced
the same labels.

## CLI

The CLI is a trusted local operator interface over an existing repository. The
tenant, repository, format and principal are explicit local bindings. Read first:

```sh
fg pr labels "$STORAGE" "$TENANT" "$REPOSITORY" 41 \
  --trusted-local --object-format "$OBJECT_FORMAT"
```

Replace an unset set with two labels:

```sh
fg pr set-labels "$STORAGE" "$TENANT" "$REPOSITORY" 41 \
  --trusted-local --object-format "$OBJECT_FORMAT" \
  --principal "$PRINCIPAL" --idempotency-key pr-41-labels-first \
  --expected-version 0 --label bug --label 'needs review'
```

Explicitly clear the set observed at label version 1:

```sh
fg pr set-labels "$STORAGE" "$TENANT" "$REPOSITORY" 41 \
  --trusted-local --object-format "$OBJECT_FORMAT" \
  --principal "$PRINCIPAL" --idempotency-key pr-41-labels-clear \
  --expected-version 1 --clear-labels
```

The write parser requires either one or more `--label` arguments or
`--clear-labels`, never both or neither. `fg pr list` and `fg pr show` include
`labels`, `labels_version` and `labels_actor`. A list can require several labels:

```sh
fg pr list "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --object-format "$OBJECT_FORMAT" --limit 20 \
  --label bug --label 'needs review'
```

Every selected label must be present. Native filtering occurs before page limits
and cursor selection. For continuation, preserve the same label filter and pass
both `--after` and the previous `--expected-head` snapshot token. An exact labels
read also accepts `--expected-head`; it reads the retained snapshot subject to
current branch disclosure, rather than silently refreshing to latest state.

CLI exit codes are 0 for a complete read or committed replacement, 3 for a
canonical refusal, 4 for a missing/hidden dedicated labels lookup, and 2 for an
input, infrastructure, cleanup or output error. A known terminal receipt is
preserved in output-error diagnostics; such errors cannot establish rollback.

## MCP

`frankengit_pull_labels` requires the existing PR read launch grant.
`frankengit_pull_set_labels` requires the independent PR write launch grant and
authenticated principal. Writes do not imply reads or recovery. Sponsored agents
use their canonical `pulls-read` or `pulls-write` operation scope in addition to
the launch ceiling; tool arguments cannot supply identity or broaden scopes.

Read arguments:

```json
{"number":"41"}
```

Full replacement arguments for `frankengit_pull_set_labels`:

```json
{
  "number":"41",
  "expected_version":"0",
  "idempotency_key":"pr-41-labels-first",
  "labels":["bug","needs review"]
}
```

The `labels` array is required; `[]` explicitly clears. Numbers and versions are
canonical decimal strings bounded by `u64`, preserving values above JavaScript's
exact integer range. The dedicated read supports optional `expected_head` and
returns a complete repository-bound report with `found`, the label fields,
`pull_request_version`, `snapshot_token`, `read_only:true` and
`transaction_created:false`.

`frankengit_pull_list` accepts optional `labels:["bug","needs review"]`, an
exact AND filter applied before pagination. Keep the same array contents,
`next_after` and `snapshot_token` for continuation. Both list and show include
the independent label state alongside PR lifecycle data.

## HTTP and browser

The existing `--allow-pulls` listener ceiling and repository credentials apply.
GET requires `pulls-read`; POST requires `pulls-write`. These are repository-wide
writer permissions, including editing another author's labels, not per-author
access rules. Both PR branches remain subject to canonical disclosure policy.

```text
GET  {REPO_URL}/api/v1/pulls/{number}/labels
POST {REPO_URL}/api/v1/pulls/{number}/labels
```

A dedicated GET accepts optional `expected_head`. It returns a
`pull_request_labels` report. Missing and hidden subjects share the not-found
behavior; absence never reveals the next visible PR. Read responses do not
create a transaction.

POST requires `Idempotency-Key` and an
`application/x-www-form-urlencoded` body. Submit the independent label
`expected_version` and either repeated `label` fields or `clear_labels=true`:

```sh
curl --fail-with-body --header @/secure/pr-writer.headers \
  --header 'Idempotency-Key: pr-41-labels-first' \
  --data-urlencode 'expected_version=0' \
  --data-urlencode 'label=bug' \
  --data-urlencode 'label=needs review' \
  "$REPO_URL/api/v1/pulls/41/labels"

curl --fail-with-body --header @/secure/pr-writer.headers \
  --header 'Idempotency-Key: pr-41-labels-clear' \
  --data-urlencode 'expected_version=1' \
  --data-urlencode 'clear_labels=true' \
  "$REPO_URL/api/v1/pulls/41/labels"
```

The clear flag and label fields are mutually exclusive. Label commands contain
no tips, title, body, force flag, caller-selected actor, or metadata version.
The complete body is framed and validated before admission. POST reports use
action `set-labels`; a returned canonical refusal is a terminal outcome, while
an uncertain delivery requires recovery of the original command identity.

PR list requests accept repeated `label` query fields with the same AND
semantics. Existing PR list and show responses include the label set, independent
version and actor. The browser exposes the labels and filter and uses the same
exact replacement flow. See [the PR HTTP contract](HTTP_PULL_REQUEST_API.md) and
[browser PR workflow](PR_BROWSER_COLLABORATION.md) for deployment and session rules.

## Validation scope

The implementation includes codec, canonical admission, retained-read, retry,
HTTP, CLI parser/receipt, MCP protocol/grant, sponsored-agent and browser
regressions. Native Rust execution is a separate validation gate; presence of a
test does not establish a passing run. No release or bead closure is implied by
this interface document.
