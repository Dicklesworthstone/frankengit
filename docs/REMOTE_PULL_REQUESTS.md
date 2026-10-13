# Authenticated remote pull-request commands

This external Node.js operator client completes native PR lifecycle, discussion,
and fast-forward-only publication without opening the node's canonical storage.
It calls the existing FrankenGit API, not GitHub. Related work is
`frankengit-root-doctrine-x2mv.4.13` and `.4.20`; this does not close either bead.
The existing branch-tip synchronization tool remains separate and unchanged.

## Supported commands

`preparePull` in `scripts/operator/remote_pull.mjs` accepts an explicit endpoint,
expected scope, PR number, action, and exact command fields. Preparation is local
and produces no repository transaction. Scope contains `tenant_id`,
`repository_id`, `repository_incarnation`, `principal_id`, and `object_format`.
The four identities are 32 lowercase hex characters; format is `sha1` or `sha256`.
Numbers and versions are canonical decimal **strings**, including values above
JavaScript's safe integer range.

| Action | Required fields |
| --- | --- |
| `open` | `expected_version:"0"`, source/target refs and tips, title, body |
| `update`, `close`, `reopen` | Nonzero `expected_version`, source/target refs and tips, title, body |
| `comment` | `expected_version` of the separate discussion stream, body |
| `fast-forward` | `pull_request_version`, source/target refs and tips |

The four lifecycle operations carry complete metadata because that is the
native command contract; even close/reopen must not silently replace a newer
PR's coordinates. Refs are explicit UTF-8 `refs/heads/...` names. Byte-only refs
are not lossy-decoded or silently renamed. Input tips are full, raw lowercase
native OIDs in the selected hash domain. There is no arbitrary route, force,
review assertion, policy override, bundle, or alternative merge-method field.
Titles are bounded to 256 UTF-8 bytes; bodies to 64 KiB. Encoded forms are bounded
to 256 KiB (8 KiB for fast-forward); retained intents to 1 MiB, independently of
the 32 KiB publication response limit. The larger intent bound accounts for both
JSON escaping and the saved URL-encoded body.

## Submission and recovery

`submitPull(intent, token, {confirmKey: intent.key})` verifies the frozen request
and original credential fingerprint, then uses the shared `lookupOutcome` client
to check the original key before publishing. Fast-forward additionally requires
`confirmFastForward:true`. This is consent to submit those exact coordinates,
not an assertion that the merge is allowed. The native endpoint independently
requires the merge-publication grant and checks ancestry, current refs, PR
version and branch protection. A refusal never falls back to merge-commit,
squash, force-update, branch deletion, or another principal.

A historical terminal suppresses publication. Otherwise a submission makes one
mutation request and checks the matching native outcome afterward. The reply
must bind scope, principal, action, number, predecessor, transaction and decision;
fast-forward also binds both text/byte refs and native tips. A comment receipt
must retain its separate next version and explicitly change no refs. Native
refusal receipts and pre-decision HTTP errors are different outcomes.

`recoverPull(intent, originalOrRotatedToken)` only looks up the original key.
A rotated credential must still authenticate as the expected original principal;
it cannot resubmit. Optional `known` outcome and `publication` receipt retain
prior observations and refuse regression. A retained publication prevents
resending even when its subsequent outcome lookup is unavailable. Errors after
a valid publication preserve that receipt on `error.publication`. A timeout,
missing key, cancelled request, malformed reply, or HTTP error never proves
non-commit. The caller must retain the original intent and reconcile uncertainty.
No retry, new key, tip refresh or expected-version refresh happens automatically.

All network work shares one finite deadline (default 30 s, maximum 300 s).
`signal` supports cancellation; `ca` accepts a copied bounded PEM trust root.
HTTPS verifies certificates and hostnames. Cleartext is restricted to canonical
numeric loopback addresses. No redirects, cookies, ambient proxy credentials,
connection pools, arbitrary headers, TLS-disable option or third-party requests
are used. Full native u64 counters remain exact; duplicate publication JSON keys,
wrong scopes, conflicting decisions and oversized/truncated bodies refuse.

## Boundaries and validation

The prepared key is a client idempotency key, **not** a native transaction ID or
seal. Saved local state is not authority. Only the node authenticates principals,
checks grants and policy, and atomically publishes refs and forge state.
The native forms do not carry an atomic expected-incarnation precondition. A
preflight read and a receipt check cannot add that server-side guarantee; an
operator must not replace an endpoint's repository identity during a command.
This client does not remove trusted-local CLI/MCP privileges, implement native
IAM, run checks, grant approval, or implement reviewed merge-commit/squash.

Run the focused client tests:

```sh
node --test tests/operator/remote_pull.test.mjs
```

Node 22.16.0 is the executed profile. Tests import complete normal production
modules and use real HTTP/TLS sockets with explicit native-schema peers. OpenSSL
is used only by the test to generate ephemeral certificates. These tests are not
a live Rust-node, native authorization/ancestry, full-workspace or deployment
pass. The shared outcome module remains unchanged at blob `9d497c67e0b2f49895efd4259d7a28c5129f7541`.
