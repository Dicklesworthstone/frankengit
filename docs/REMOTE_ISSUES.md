# Authenticated remote issue operations

Related work: `frankengit-root-doctrine-x2mv.4.13`. This is an external Node
operator client of the existing native issue and outcome APIs, not a replacement
for `fg`, the identity service, a server runtime or canonical admission. No Rust
dependency, credential grant, principal impersonation mechanism or native schema
changes. The server must enable issues and outcomes and provision the caller
with the independent issue-write and outcome-read grants.

`scripts/operator/remote_issue.mjs` supports native `open`, `edit`, `comment`,
`close`, `reopen`, `assign` and `unassign`. Issue numbers and expected versions
are canonical decimal **strings**, including values beyond JavaScript's safe
integer range. Text and list limits follow the native form contract; unknown
fields, duplicate labels/assignees and invalid versions refuse before I/O.
Label replacement with an empty list emits the explicit native `clear_labels`
field. Omitting labels in an edit leaves them unchanged. No issue number or
expected version is guessed, and no read/modify/write retry updates a request.

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
