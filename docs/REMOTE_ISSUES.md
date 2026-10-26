# Authenticated remote issue operations

Related work: `frankengit-root-doctrine-x2mv.4.13`. This is an external Node
operator client of the existing native issue and outcome APIs, not a replacement
for `fg`, the identity service, a server runtime or canonical admission. No Rust
dependency, credential grant, principal impersonation mechanism or native schema
changes. The server must enable issues and outcomes and provision the caller
with the independent issue-write and outcome-read grants.

`scripts/operator/remote_issue.mjs` supports native `open`, `edit`, `comment`,
`append-comment`, `close`, `reopen`, `assign` and `unassign`. Issue numbers and expected versions
are canonical decimal **strings**, including values beyond JavaScript's safe
integer range. Text and list limits follow the native form contract; unknown
fields, duplicate labels/assignees and invalid versions refuse before I/O.
Label replacement with an empty list emits the explicit native `clear_labels`
field. Omitting labels in an edit leaves them unchanged. No issue number or
expected version is guessed, and no read/modify/write retry updates a request.

Use `append-comment` explicitly when a comment should survive intervening issue
changes. Its input must contain `expected_version: null` and `fields: { "body":
"exact comment text" }`. This local null encodes the absence of a predecessor:
the HTTP form contains **only** `body`, never an `expected_version` field, and
the publication receipt must return `expected_version: null`. Supplying a version,
omitting the input property or adding other fields refuses before I/O.
`comment` retains its exact positive version requirement and original saved
request/key encoding. The client never converts a strict comment to an append,
refreshes its version or falls back when a server lacks the append route.

The native append profile binds the authenticated actor, issue and exact body
while planning its position against the current canonical history. See
[the native contract](NORMATIVE_PROTOCOL_CONTRACTS.md#2021-native-issue-append-comment-intents).
This permits comments on open or closed issues; it grants no other edit or
authority. Different request identities with identical text remain different
comments. Keep the saved intent for recovery, including after a lost reply.

## Request and recovery contract

`prepareIssue(input, token)` returns a detached, token-free intent. `input`
contains `endpoint`, `scope`, `number`, `expected_version`, `action` and `fields`.
The independently obtained scope has exactly `tenant_id`, `repository_id`,
`repository_incarnation` and `principal_id`, each 32 lowercase hex characters.
This principal is an expected authenticated identity, **not** a form field or a
server-side impersonation selector. A fresh client nonce, the credential digest,
endpoint, scope and exact normalized command determine the saved key. That key
is not a client-computed native transaction ID or seal.

`submitIssue(intent, token, { confirmKey: intent.key })` first performs a
bodyless original-key outcome query. A matching historical terminal is returned
without sending the mutation. Otherwise an explicit send attempts the identical
saved form and key once, then confirms its terminal through the existing outcome
client. Confirmation checks the complete expected scope, transaction, decision
sequence and RCR/refusal identity. The response retains both observations.

`recoverIssue(intent, token)` performs **only** a bodyless original-key lookup.
A rotated credential may recover the same principal's key; it cannot resend the
original request. `known` can retain a previous normalized native outcome to
refuse seal, transaction or decision regression. No absent key, absent seal,
HTTP error or cancellation is proof of non-commit. An uncertain invocation must
keep the original intent and key, not prepare a fresh command.

Issue v1 publication replies omit repository incarnation. The preflight and
confirmation observations do **not** create an atomic server-side incarnation
precondition on the intervening issue POST. Keep credentials bound to their
original repository incarnation; never reuse them across a recreated repository.
A conflicting/unavailable confirmation reports uncertainty and retains any
validated issue publication observation. This client does not independently
verify authority signatures or canonical seal digests, grant an identity role,
solve organization/team IAM, or change the trusted-local CLI's privileges.

## Transport and evidence boundary

Only canonical HTTPS repository endpoints or numeric-loopback HTTP are accepted.
TLS certificate and hostname verification remain enabled; `ca` may supply an
explicit, copied, bounded private trust bundle. No redirects, cookies, ambient
proxy configuration, custom authentication headers, implicit retries, pooled
connections or token-bearing URLs. Each socket is closed before an observation
returns. A single finite deadline covers preflight, publication and confirmation;
`signal` requests cancellation. Validated terminals win a cleanup race.

Commands are bounded to 256 KiB; publication replies to 16 KiB; saved intents to
512 KiB. Issue JSON refuses invalid UTF-8, duplicate keys, excessive nesting,
noncanonical numbers and unsafe integer rounding. Native u64 counters in reports
are decimal strings. Original-key recovery uses the unchanged, independently
bounded `transaction_outcome.mjs` parser and transport. Do not treat transport
errors as canonical refusals or raw remote error text as trusted diagnostics.

Run `node --test tests/operator/remote_issue.test.mjs` with Node 22.16 or newer.
Tests use the complete production modules, real HTTP/TLS sockets, exact native
response fixtures, full-width counters, refusal/cancellation and lost-response
scenarios. OpenSSL is used only to create ephemeral **test** certificates.
This is client contract/transport evidence, not native Rust admission, live `fg`,
end-to-end identity-service, crash-filesystem or full-workspace verification.
No broad bead closure follows from these tests.

## Durable command-line workflow

Use `node scripts/remote_issue.mjs --help`. No access to the server's storage
root is required. The tool uses only the explicitly selected native HTTP APIs.
The expected actor comes from your administrator's credential binding, not from
an arbitrary `--principal` option. This does not remove or repair the separate
trusted-local CLI/MCP impersonation boundary tracked by the owning bead.

Create an operator-owned private directory **outside any Git worktree** and use
`umask 077`. Place the token in a private regular file (64 lowercase hex bytes,
optionally followed by one LF). Do not put a token in arguments, input JSON,
source control, or an environment-variable example. `request.json` contains:

```json
{
  "endpoint": "https://forge.example/team/repo.git",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "principal_id": "44444444444444444444444444444444"
  },
  "number": "7",
  "expected_version": "0",
  "action": "open",
  "fields": { "title": "Investigate import failure", "body": "Exact issue text", "labels": ["bug"] }
}
```

Those IDs are placeholders. Obtain the actual scope independently and use an
explicit issue number. For an existing issue, obtain its exact current version
from the native issue API/browser for exact-version operations. A concurrent
version change causes a native refusal, never a silently refreshed mutation.
For contention-tolerant commenting instead, select `"action": "append-comment"`,
`"expected_version": null` and a body-only `fields` object.
`edit` can replace selected title,
body or labels; `comment` takes a body; `assign`/`unassign` take an `assignees`
array of principal IDs; `close`/`reopen` take an empty `fields` object.

```sh
node scripts/remote_issue.mjs prepare \
  --input /private/operator/request.json --token-file /private/operator/token \
  --request-dir /private/operator/issue-7

node scripts/remote_issue.mjs inspect --request-dir /private/operator/issue-7

node scripts/remote_issue.mjs send \
  --request-dir /private/operator/issue-7 --token-file /private/operator/token \
  --confirm-key EXACT_KEY_FROM_INSPECTION \
  --record /private/operator/issue-7-result.json

node scripts/remote_issue.mjs recover \
  --request-dir /private/operator/issue-7 --token-file /private/operator/rotated-token \
  --known /private/operator/issue-7-result.json \
  --record /private/operator/issue-7-recovery.json
```

Omit `--known` until a complete result record exists. It must be a result for
this exact request; an arbitrary native outcome or another issue's receipt is
refused before I/O. `--record` always names a new file and never replaces a prior
observation. `--ca-file` selects a private PEM trust bundle, not permission to
skip TLS verification. `--timeout-ms` bounds the entire network operation;
SIGINT/SIGTERM request cancellation and socket cleanup. SIGKILL cannot run
cleanup, but the already saved request remains the recovery input on restart.

`prepare` and `inspect` perform no network operations. Preparing creates a new
0700 request directory with one canonical 0600 `intent.json`, syncs the parent,
file and directory, then reports the original key. A slot already present is
never overwritten, even if empty or interrupted. Sending validates the complete
saved bytes and re-syncs the intent and directories before contacting the API.
No live registry, local issue database or local file can make a mutation canonical.

Private files must be owned, singly linked regular files, with no group/other
permissions; immediate directories must also be private and owned. Symbolic
links, directory aliases, FIFOs, oversized/changing files and request/record
locations inside worktrees refuse. All ancestors must be operator-controlled.
These checks are not confinement against a hostile owner changing parent
paths, a multi-host lock, or authentication of an operator-edited checksum.
Concurrent sends of the **same** saved request rely on native key/seal semantics,
not an invented local authority or cross-process exactly-once claim.

Result files use a private staging file, body sync, create-only hard link to the
final name, staging unlink and directory sync. The final path is never replaced.
A crash may leave staging residue or two links to a complete body; the ordinary
reader refuses multiply-linked files instead of guessing a clean result. No
error path deletes a visible result or reclaims an interrupted request slot.
A destination race or failed final sync cannot undo a canonical terminal. When
available, the error retains the already validated native result and distinguishes
known outcome from failed local result publication. Recover with the saved key
rather than making a new request. A lost stdout pipe likewise cannot erase a
saved result. Success of these local calls is not a tested power-loss guarantee
for every filesystem, and local records do not verify authority signatures.

Exit codes are 0 for local preparation/inspection or a confirmed native commit,
1 for a canonical terminal refusal, 2 for a local input/file refusal before the
network operation, and 3 for a nonterminal/unknown operation or result-output
failure. Inspect the structured result: output failure can follow a known commit.
Neither a nonzero exit nor an absent key is evidence that nothing happened.

Run `bash scripts/verify_remote_issues.sh` for the complete client/CLI lane.
It checks ordinary production module syntax and runs both test files. The added
CLI cases execute real child processes and private filesystem publication,
including exact-key restart recovery after dropped responses, SIGTERM, SIGKILL,
closed stdout, conflicting result publication, scope/history pins and refused
unsafe input files. Native replies remain explicit protocol peers, not `fg`.
