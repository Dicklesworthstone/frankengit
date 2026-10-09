# Authenticated issue operations from a terminal

`node scripts/forge_issues.mjs` uses FrankenGit's existing authenticated HTTP API
and its shipped `IssueClient`. It never opens a local node, accepts a principal
argument, invents a mutation codec, or treats local files as repository authority.
The server authenticates the bearer token and enforces its configured scopes at
each request. This supplies a network operator alternative; it does not change
the trusted-local principal semantics of the native `fg` or MCP commands.

The command supports issue opening, partial edits (including labels), comments,
closing, reopening, outcome lookup and explicit same-request retry. Mutation
semantics and terminal-response validation are the same as the served issue UI.
All commands require the exact issue-page URL and expected tenant/repository IDs.
HTTPS is required except for loopback HTTP. Redirects are refused; no cookies,
environment-token fallback or credentials in arguments/URLs are used. This does
not add TLS to the native server; remote HTTPS needs a separately trusted TLS
endpoint. HTTP responses remain trusted-server claims, not authenticated roots.

## First mutation

Use a token with `issues-read`, `issues-write` and `outcomes-read` scopes for the
same repository. Store its 64 lowercase hexadecimal characters in a private
regular file (optionally with one final newline). The file must belong to the
current user, have no group/other permissions and have exactly one hard link.

```sh
mkdir -m 700 "$PRIVATE_DIR"
# Provision $PRIVATE_DIR/token securely; never put the bearer token in argv.
node scripts/forge_issues.mjs open \
  --url "$ISSUE_PAGE_URL" --tenant-id "$TENANT_HEX" \
  --repository-id "$REPOSITORY_HEX" --token-file "$PRIVATE_DIR/token" \
  --record "$PRIVATE_DIR/open-1.json" \
  --number 1 --expected-version 0 --title 'First issue' \
  --body-file "$PRIVATE_DIR/draft.txt" --label bug
```

`ISSUE_PAGE_URL` is the exact URL ending in `/ui/issues/`, including the repository
route, with no query, fragment or credentials. The caller chooses the issue
number and expected version. Before staging, the command reads that issue,
checks tenant/repository identity and refuses a moved version. The native server
still enforces the exact expected version if state changes after this observation.
No client read is an authorization grant and no race refreshes the request.

A new immutable record is created with exclusive file creation, synchronized,
read back and followed by parent-directory synchronization and file close before
the first mutation HTTP request. Failure at any of those stages prevents that
submission. The record includes the original form, exact key, route, expected
identity and credential fingerprint, but never the token. It contains private
issue text: do not publish it. Existing records, partial records and symlinks are
not overwritten. The existing parent must be owner-private and trusted. This
Unix filesystem profile is not a sandbox against a malicious same-UID writer.

The command rechecks the saved bytes immediately before submission. It keeps
the record on success as well as failure. No automatic retry follows a network
failure, cancellation, malformed reply or nonterminal HTTP 409. A valid canonical
refusal is a terminal result, not success and not a missing reply.

## Recovery after lost replies or process death

Run `status` with the same URL, identity, token file and original record:

```sh
node scripts/forge_issues.mjs status \
  --url "$ISSUE_PAGE_URL" --tenant-id "$TENANT_HEX" \
  --repository-id "$REPOSITORY_HEX" --token-file "$PRIVATE_DIR/token" \
  --record "$PRIVATE_DIR/open-1.json"
```

It restores the shipped client's exact credential-bound request and queries the
native outcome endpoint. It never submits an issue mutation. A local file or an
absent outcome cannot establish that the original request failed to commit.
The server's terminal observation can resolve a lost response without resending.

`retry` performs the same lookup first. If it is terminal, no write follows.
Otherwise this explicitly requested operation can send the **same request and
key once**. It never creates a fresh key, selects a new expected version, edits
private text, switches credentials or silently abandons the original request.
Concurrent retries retain the same native idempotency identity; the immutable
record is not a client-side authority lock. Outcome lookup failures stop retry.
Records are not retired automatically, and credential rotation across an
unresolved request is deliberately unsupported by the existing client contract.

Use a fresh record only for a genuinely new operation. An exported/prepared
record is treated as potentially sent. A crash while initially writing a record
can leave a partial file, which refuses recovery rather than fabricating a key.
Inspect that file; never infer a remote result from its apparent filesystem phase.

## Bounds and results

`--timeout-ms` covers command intake, reads, persistence and network work, with a
30-second default and a 300-second maximum. Cancellation aborts the outstanding
HTTP request; that does not cancel a possibly committed server transaction.
Blocking host filesystem calls and synchronous work are not preemptible. A
confirmed terminal result is not retroactively rolled back by later cancellation
or failed stdout. Output errors return failure with `operation_completed` set
when the command had already produced its result; the original record survives.

Titles, bodies, labels, safe-integer counters and response limits retain the
shipped client profile. This does not expand it to the native u64 domain. Body
files can be empty when clearing an issue body and have a 64-KiB ceiling. Token
files and all control files are bounded before allocation. A prepared receipt
that cannot fit the client's own recovery limit is refused before submission.
JSON output escapes terminal control/bidi characters without changing data.

Exit codes: **0** committed terminal result; **3** canonical terminal refusal;
**2** unresolved outcome, validation, I/O, transport, cancellation or output error.

## Evidence boundary

```sh
node --test tests/operator/forge-issues.test.mjs
```

The tests execute the unchanged shipped issue client, real fetch/HTTP sockets,
private filesystem operations and separate CLI processes, including SIGKILL
after the simulated server receives a mutation. Their HTTP authority is explicitly
simulated. They are not native Rust/node/authority integration or a power-loss
campaign, and do not close the broader CLI/MCP authentication work. No Rust,
server permission, dependency, codec or authority changes are introduced.
