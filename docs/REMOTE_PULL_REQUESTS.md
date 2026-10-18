# Authenticated remote pull-request commands

This external Node.js operator client completes native PR lifecycle, discussion,
and fast-forward-only publication without opening the node's canonical storage.
It calls the existing FrankenGit API, not GitHub. Related work is
`frankengit-root-doctrine-x2mv.4.13` and `.4.20`; this does not close either bead.
The existing branch-tip synchronization tool remains separate and unchanged.

The same client and CLI now also support exact-candidate approval, change
requests, withdrawal and reviewed merge-commit/squash. Their separate bundle
intent schema, confirmations and durable workflow are documented in
[REMOTE_REVIEWED_MERGES.md](REMOTE_REVIEWED_MERGES.md). The six original form-only
commands below retain their existing intent bytes, keys and requirements.

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
native OIDs in the selected hash domain. These six original form-only commands
accept no arbitrary route, force, review assertion, policy override, bundle, or
alternative merge-method field. Candidate review/merge is a separate explicit
action profile, never a fallback for a failed fast-forward.
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
IAM, run checks, or grant authority. Its separate exact-candidate operations can
submit an authenticated reviewer statement or request a reviewed merge; the
native engine still decides whether any review or merge may be published.

Run the focused client tests:

```sh
node --test tests/operator/remote_pull.test.mjs
```

Node 22.16.0 is the executed profile. Tests import complete normal production
modules and use real HTTP/TLS sockets with explicit native-schema peers. OpenSSL
is used only by the test to generate ephemeral certificates. These tests are not
a live Rust-node, native authorization/ancestry, full-workspace or deployment
pass. The shared outcome module remains unchanged at blob `9d497c67e0b2f49895efd4259d7a28c5129f7541`.

## Durable command-line workflow

The CLI uses private files rather than token arguments, environment credentials,
or access to the node's storage root. Node 22.16.0 and POSIX filesystem semantics
are the exercised profile. Create an owner-private directory outside a Git
worktree, provision a 64-character lowercase hexadecimal bearer token in a mode
0600 file, and write an input JSON file in that directory. An optional final
newline is accepted in the token file. Do not put a real token in shell history.

For example, this input opens PR 37. Replace the illustrative IDs and OIDs with
independently obtained repository/principal identity and current native tips:

```json
{
  "endpoint": "https://forge.example/repo.git",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "principal_id": "44444444444444444444444444444444",
    "object_format": "sha1"
  },
  "number": "37",
  "action": "open",
  "fields": {
    "expected_version": "0",
    "source_ref": "refs/heads/topic",
    "target_ref": "refs/heads/main",
    "source_tip": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "target_tip": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "title": "Review the topic branch",
    "body": "Explicit PR description."
  }
}
```

```sh
node scripts/remote_pull.mjs prepare --input /private/pr-input.json \
  --token-file /private/token --request-dir /private/pr-37
node scripts/remote_pull.mjs inspect --request-dir /private/pr-37
node scripts/remote_pull.mjs send --request-dir /private/pr-37 \
  --token-file /private/token --confirm-key EXACT_KEY_FROM_PREPARE \
  --record /private/pr-37-first-result.json
```

The existing native PR API/browser supplies current metadata and discussion
versions. `inspect` above inspects the saved local intent, not live state. It
prints private command data; do not route its output into public logs. `prepare`
prints only identifying receipt fields, not the token or PR body. All JSON output
escapes control/bidirectional formatting characters; repository text stays data.

A fast-forward input uses `action:"fast-forward"` and only
`pull_request_version`, `source_ref`, `target_ref`, `source_tip`, `target_tip`
inside `fields`. Its send command additionally requires `--fast-forward-only`.
That switch is refused for other actions. The server can refuse a protected or
non-fast-forward merge; there is no fallback or second strategy submission.

Recover an interrupted command using the **same request directory**:

```sh
node scripts/remote_pull.mjs recover --request-dir /private/pr-37 \
  --token-file /private/original-or-rotated-token \
  --record /private/pr-37-recovered.json \
  --known /private/pr-37-first-result.json
```

Omit `--known` when interruption produced no complete prior record. Recovery
never sends a mutation. `--known` binds a retained observation to this exact
request and refuses changed transactions, seals, terminal decisions or scope.
Both network commands require a **new** `--record` destination. Existing files
are never overwritten. `--ca-file PRIVATE_PEM` provides an explicit CA, and
`--timeout-ms` bounds the combined preflight/publication/confirmation network
operation. Bounded filesystem operations are outside that network deadline and
cannot be preempted as a hard real-time filesystem guarantee.

The entire canonical intent is saved and synced before sending; later commands
revalidate and resync it before I/O. Files must be owner-private, regular and
singly linked, with stable device/inode, size and nanosecond timestamp checks.
Aliases, symlinks, special files, unsafe parents and worktree locations refuse.
This is an operator-controlled-filesystem profile, not confinement against a
hostile writer swapping parent directories or rolling retained files back.

Preparation creates its slot once. Interrupted/partial intent files refuse and
are retained for diagnosis, not erased or silently replaced. A killed process
never justifies choosing another key. The native original-key endpoint remains
the recovery source even when local result publication was interrupted.

A result is written and synced under a new private staging name before a
create-only hard link publishes the final name. The staging link is then removed
and the directory synced. An interrupted publication may retain a `.pending`
file or a temporarily multiply-linked final file; those are not silently fixed
or accepted as stable records. Retain them and recover from the original request
into a different new record. A result-name race leaves the existing file intact
and emits the newly observed native evidence in the error diagnostic. Lost
stdout after a completed result write leaves that result available on disk.
These checks are not a universal hardware power-loss durability guarantee.

Exit codes: **0** for local preparation/inspection or confirmed native commit,
**1** for a native terminal refusal, **2** for local validation/file failure
before network admission, **3** for incomplete/unknown network work or result
output failure. No nonzero exit proves rollback. A valid publication whose
confirmation fails is retained in its result record, and supplying that record
on a later send suppresses resubmission while checking the original outcome.

Run the combined client, filesystem and actual-process tests:

```sh
bash scripts/verify_remote_pulls.sh
```

At the candidate-CLI checkpoint, the combined suite has 241 tests: all 129
original tests, 69 candidate client tests and 43 candidate CLI/file tests.
It includes real processes killed
with SIGTERM/SIGKILL, credential rotation, broken pipes, immutable-file races,
unsafe file refusal, and both hash domains. HTTP replies are explicit native
contract fixtures; no live `fg` or native admission/policy execution is claimed.
