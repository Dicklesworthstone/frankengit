# Authenticated remote issue operations

Related work: `frankengit-root-doctrine-x2mv.4.13`. This is an external Node
operator client of the existing native issue and outcome APIs, not a replacement
for `fg`, the identity service, a server runtime or canonical admission. No Rust
dependency, credential grant, principal impersonation mechanism or native schema
changes. The server must enable issues and outcomes and provision the caller
with the independent issue-write and outcome-read grants.

`scripts/operator/remote_issue.mjs` supports native `open`, `edit`, `comment`,
`append-comment`, `close`, `reopen`, `lock`, `unlock`, `assign`, `unassign`,
`add-assignees`, `add-labels`, `set-milestone` and `clear-milestone`. Issue numbers and expected versions
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
This permits comments on unlocked open or closed issues; it grants no other edit or
authority. Different request identities with identical text remain different
comments. Keep the saved intent for recovery, including after a lost reply.

Use `add-labels` or `add-assignees` to add metadata while other writers change
the same issue. Both require explicit `expected_version: null`; the form omits
the predecessor completely. Their `fields` objects contain exactly one nonempty
array:

| Action | Fields | Addition limit | Required publication profile |
|---|---|---|---|
| `add-labels` | `{ "labels": ["bug", "urgent"] }` | 1–32 distinct labels, at most 64 UTF-8 bytes each | `issue.add-labels.v1` |
| `add-assignees` | `{ "assignees": ["44444444444444444444444444444444"] }` | 1–16 distinct principal IDs | `issue.add-assignees.v1` |

The client sorts each addition by UTF-8 bytes before retaining its exact form
and key. It rejects duplicates, empty sets, version fields and unrelated fields
before I/O. The native server unions the supplied values with the current issue
state and enforces the **resulting** 32-label or 16-assignee limit. A missing,
swapped or unsupported `command_profile` in the publication receipt leaves the
operation unresolved until original-key recovery; it cannot silently acquire
replacement semantics. See the [label-addition contract](NORMATIVE_PROTOCOL_CONTRACTS.md#2026-native-issue-label-addition-intents)
and [assignee-addition contract](NORMATIVE_PROTOCOL_CONTRACTS.md#2025-native-issue-assignee-addition-intents).

Exact-version `edit` still replaces or clears labels, and `assign`/`unassign`
retain their predecessor checks. Their saved forms, keys and receipt shapes
remain unchanged. A retry of a terminal addition recovers that original outcome
without adding again, including after a later writer removes one of its values.
A terminal capacity refusal also remains refused after space becomes available.
The client never refreshes a predecessor, changes the addition, or falls back to
a strict operation when an addition route is unavailable.

`lock` and `unlock` require the existing issue-write grant, a positive exact
`expected_version` and an empty `fields` object. The lock is independent of
open/closed state. Both strict and append comments refuse new publication while
locked; field edits, assignments, close and reopen remain available and preserve
it. A duplicate lock state under a fresh key refuses
`ProtectedRefTransitionDenied`, and a stale version refuses `EvidenceStale`.
Neither response permits an automatic version refresh.

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
Changing the lock does not change an earlier terminal result. A previously
committed comment still recovers its commit while locked; a previously refused
comment still recovers its refusal after unlocking. The same original-key rule
applies to lock and unlock themselves.

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
For independent metadata additions, select `"action": "add-labels"` or
`"action": "add-assignees"`, `"expected_version": null` and the corresponding
nonempty array shown above. Sending and recovery use the same commands below.
`edit` can replace selected title,
body or labels; `comment` takes a body; `assign`/`unassign` take an `assignees`
array of principal IDs; `close`/`reopen`/`lock`/`unlock` take an empty `fields` object.

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
skip TLS verification. For send/recover, `--timeout-ms` bounds the whole
invocation, including local intake, network work and asynchronous stdout
delivery (30 seconds by default, at most 300 seconds). Local-only commands
use the same 30-second default. SIGINT/SIGTERM request cancellation, socket
cleanup and release of blocked output. Synchronous work and blocking host
filesystem calls cannot be preempted. Final diagnostics have a separate drain
capped at 250 ms, which authorizes no further remote work. SIGKILL cannot run
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
The `remote_issue_output_failure` diagnostic names its error code and whether
command work completed before output failed. When available, `native_result`
preserves the validated terminal observation; output cancellation never rolls
back publication or changes the original request, key or saved result record.
If command work already failed, stderr instead preserves its original
`remote_issue_error`, including the error code, phase, dispatch flag and any
publication receipt. An added `output_failure` names the separate output
problem. A publication receipt without completed incarnation-bound confirmation
still leaves `outcome_unknown:true`; recovery uses the original request.
Neither a nonzero exit nor an absent key is evidence that nothing happened.

Run `bash scripts/verify_remote_issues.sh` for the complete client/CLI lane.
It checks ordinary production module syntax and runs both test files. The added
CLI cases execute real child processes and private filesystem publication,
including exact-key restart recovery after dropped responses, SIGTERM, SIGKILL,
closed stdout, conflicting result publication, scope/history pins and refused
unsafe input files. Native replies remain explicit protocol peers, not `fg`.

The separate `scripts/e2e/suites/operator/remote_issue.sh` campaign uses actual
native listeners. For both Git hash domains and committed/refused transactions,
it pairs complete confirmation with a two-session listener that publishes then
retires before confirmation. Drained output and a real full, unread OS pipe
must preserve the same error/receipt semantics. Separate `fg outcome` and issue
reads bind the original key, transaction, decision and canonical effects. This
bounded host-pipe campaign does not establish power-loss safety, browser/TLS
behavior, every operator entrypoint or same-revision native build qualification.
