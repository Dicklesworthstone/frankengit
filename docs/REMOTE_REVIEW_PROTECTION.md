# Remote review-protection operator

`scripts/fg_protection_admin.mjs` is an operator helper for the existing native
`GET/POST /api/v1/protection` contract. It is not a Git engine, policy evaluator,
bootstrap service, or repository authority. The Rust node still authenticates
the token, checks the independent gateway grant and current administrator set,
and publishes a permitted complete replacement through native admission.

## Inspect and prepare

Use Node 22.16 or newer on a trusted-local POSIX host. Input files must be
owner-private regular files; symlinks, hardlinks, permissive modes and parent
aliases are refused. Receipt directories and their ancestors must be under the
operator's control. This is not a hostile shared-filesystem containment boundary.
The operator never opens the server's storage directory.

The server must have its existing protection-admin API enabled and provision
independent `protection-read` / `protection-write` grants as appropriate; recovery
requires the separate `outcomes-read` grant. First
installation remains `fg protection set ... --trusted-local --expected-version 0`
on the server host. A remote request cannot enroll its own first administrator.
Every required reviewer on a protected branch remains mandatory; neither the
PR opener nor merge submitter supplies independent approval. Workflow observations
can satisfy a gate only through explicitly configured publisher/source/graph/job
selectors in the [required workflow check profile](REQUIRED_WORKFLOW_CHECK_PROTECTION.md).

Store the 64-character lowercase token, optionally followed by one LF, in a
private file rather than a command-line argument. An independently checked scope
file binds all four repository coordinates:

```json
{
  "tenant_id": "11111111111111111111111111111111",
  "repository_id": "22222222222222222222222222222222",
  "repository_incarnation": "33333333333333333333333333333333",
  "object_format": "sha1"
}
```

```sh
node scripts/fg_protection_admin.mjs inspect \
  --endpoint https://forge.example/team/repo.git \
  --token-file ./operator.token --scope-file ./scope.json
```

HTTP is allowed only for literal `127.0.0.1` / `[::1]`; use HTTPS otherwise.
Redirects and compressed API responses are refused. There are no ambient cookies,
proxy inference, TLS-disable switches, background retries or automatic writes.
`--timeout-ms` bounds one request, including its response body; the client closes
its owned socket before returning. OS filesystem/DNS work is not an independently
preemptible sandbox.

A policy file names the **complete replacement**, not a patch:

```json
{
  "administrators": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
  "branches": [{
    "reference_hex": "726566732f68656164732f6d61696e",
    "required_reviewers": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    "required_checks": []
  }]
}
```

`reference_hex` carries native branch bytes (`refs/heads/main` above), including
non-UTF-8 names without lossy conversion. Limits match the native profile: 32
administrators, 64 branches, 32 reviewers and 32 checks per branch, and a 256 KiB
encoded command. Each check is `{source_ref_hex, publisher, graph_root, job}`;
source refs are canonical branches, graph roots are 64 lowercase hex characters,
and jobs are exact nonempty UTF-8 without controls, at most 1,024 bytes. Preserve
the complete check array when editing a policy file. A check-only branch may
have an empty reviewer list. A branch may also set the strict JSON boolean
`require_merge_queue: true` to require an authenticated canonical queue landing
for its exact target. Queue-only branches use empty reviewer/check arrays and
zero or omitted approvals. Ordinary PR merges and direct writes do not qualify;
all configured checks and reviews continue to apply. Preserve the boolean when
editing other fields: omission in a complete replacement means false. The
operator includes queue requirements in its change summary, exact HTTP form,
saved intent and retry validation. Omitted and explicit false retain historical
intent bytes and keys. Long refs or jobs may exhaust the byte budget
before the count limits. Empty branch lists require explicit `--clear` and still
retain administrators. Empty check arrays retain legacy intent bytes and keys.

```sh
node scripts/fg_protection_admin.mjs prepare \
  --endpoint https://forge.example/team/repo.git \
  --token-file ./operator.token --scope-file ./scope.json \
  --principal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --policy-file ./replacement.json --intent ./policy-change

node scripts/fg_protection_admin.mjs show-intent --intent ./policy-change
```

Preparation performs one read and creates a new private intent directory. It
never sends a mutation. Output lists administrator, reviewer and check additions
and removals, the original head/version/epoch, and the exact intent digest. Every
successful native replacement advances the policy epoch and invalidates earlier
approvals, including administrator-only replacements.

The saved intent binds endpoint, scope, expected original principal, original
token fingerprint, prior policy, replacement, versions, clear flag, nonce and
encoded request/key. It contains no token. Versions and epochs remain full-width
u64 decimal strings; the outcome decoder also preserves unquoted u64 decision
sequences without rounding. Hashes detect accidental or unmatched modification;
they are not signatures or evidence against a malicious local operator. Review
endpoint and scope independently rather than trusting an imported file's claims.

A failed preparation or stdout write does not delete the intent. Inspect its
private directory explicitly. No repository transaction can have been created
by this preparation command.

## Explicit publication and original-key recovery

After inspecting the complete replacement, copy the displayed `intent_sha256`
into a separate confirmation. Supply the intended endpoint independently on the
command line, not by automatically reading it from an untrusted imported intent:

```sh
node scripts/fg_protection_admin.mjs send \
  --endpoint https://forge.example/team/repo.git \
  --token-file ./operator.token --intent ./policy-change \
  --confirm-intent <reviewed-intent-sha256>
```

This is the only command that sends a policy mutation. It checks the original
credential fingerprint, acquires an exclusive send lock, and syncs a
may-have-sent marker before creating a network request. It transmits the saved
body and original key once. There is no automatic policy refresh, new nonce,
retry, bootstrap, or merge action. The server's current administrator set and
exact native policy version/epoch decide whether replacement is permitted.

A decoded publication receipt must match the original repository scope,
principal, version, epoch, terminal outcome, and HTTP status. A committed receipt
must advance the epoch exactly once. A generic HTTP error, missing response,
malformed receipt or connection loss is not a terminal refusal certificate.
The client does not read current policy after publication and substitute it for
an original terminal receipt.

The operator can check the original outcome independently:

```sh
node scripts/fg_protection_admin.mjs outcome \
  --endpoint https://forge.example/team/repo.git \
  --token-file ./current-token --intent ./policy-change
```

The token may have been rotated, but it must identify the **same original
principal** with `outcomes-read` access. The lookup carries only the original
key in its header and no mutation body. Returned principal and repository
coordinates must match the intent. Rotation never rewrites the original token
fingerprint or grants permission to resend with a different token.

`key_not_observed`, `seal_not_observed` and `undecided` remain nonterminal.
**Absence never proves non-commit.** Once the client retains a transaction ID,
later responses cannot lose or change it; retained seals and terminal decisions
cannot be silently replaced by weaker or conflicting observations. A stale
policy's explicit native refusal is retained, not silently re-prepared against
a different epoch.

After an ambiguous send, another `send` requires explicit `--retry`, the same
confirmation and original credential. It reuses the exact saved bytes and key.
Do not create a new intent merely because the response was lost. When a verified
terminal observation is already saved, `send` returns that local observation
without transmitting another request. `outcome` still queries the server, so
later conflicting evidence is not hidden by the cache.

## Local custody, interruption and results

Keep the **whole private intent directory**, not only `intent.json`:

| Record | Meaning |
|---|---|
| `intent.json` | Immutable original scope, command, policy basis and recovery key. |
| `attempt.json` | Send responsibility was acquired; transmission or commit may have occurred. |
| `known.json` | First retained observation naming the original transaction. |
| `terminal.json` | Validated committed/refused observation for that same intent. |
| `.send-lock/owner.json` | Exclusive sender ownership, never automatically stolen. |

These records are bounded, create-only and revalidated on every use. No growing
append journal or substitute policy database is introduced. The observation
records are not signatures or independent proofs of the server's authority;
they preserve what the authenticated connection returned. Local hashes do not
protect against an operator who can rewrite all files and recompute them.
Filesystem sync calls are exercised, but hardware power-loss durability is not
established by the tests.

SIGTERM and SIGINT request cancellation and await socket closure and local
cleanup. A terminal receipt validated before late cancellation remains terminal
and is retained. A failure syncing that observation, cleaning up the lock, or
writing stdout reports the known receipt rather than inventing rollback.

A SIGKILL can leave `.send-lock` behind. A later sender refuses that lock instead
of trusting a stale PID or guessing whether publication occurred. The read-only
`outcome` command does not acquire or steal the send lock and remains usable for
recovery. Lock removal is an explicit operator investigation, not an automatic
retry policy. Likewise, incomplete or corrupt custody files fail closed: keep
them for diagnosis rather than discarding them and constructing a new command.
Concurrent outcome readers may encounter a not-yet-complete create-only record;
such a local refusal can be retried explicitly without resubmitting the mutation.

The command exit codes distinguish outcome from delivery of local evidence:

| Exit | Meaning |
|---|---|
| `0` | Inspect/prepare/show completed, or a committed outcome was observed. |
| `2` | Explicit native refusal, or local input/permission/protocol refusal. Inspect the structured result; this exit alone never proves non-commit. |
| `3` | Nonterminal/unknown outcome, ambiguous send, or a potentially interrupted sender still owns its lock. |
| `4` | A terminal decision is known, but local observation, cleanup or output delivery failed. The error contains the retained observation. |

Inspect/show summaries report `original_outcome: "not_queried"`; displaying an
old intent cannot claim that its mutation never occurred. Results include
`absence_proves_non_commit: false`. Tokens and arbitrary remote error prose are
not emitted in diagnostics or retained intent/observation records.

## Evidence boundary

```sh
node --test tests/operator/review_protection.test.mjs \
  tests/operator/protection_publication.test.mjs
```

These tests execute the actual client and CLI, real loopback HTTP sockets,
private files and child processes. They cover the complete prepare/show/send/
outcome sequence, both native hash domains, full-width u64 counters, exact retry,
rotated credentials, refusal, concurrent sends, retained knowledge, SIGTERM,
SIGKILL/restart and a broken stdout pipe after a committed response. The server
peer is explicitly a native-schema contract fixture, not the Rust node. No
native authorization/CAS correctness, live `fg` integration, deployment TLS
correctness, hardware power-loss durability or Cargo/full-workspace pass is
claimed. The wider policy-integration bead remains open to its own acceptance
gate; this operator does not complete CI attestation, organization IAM or the
remaining core storage and runtime integration work.
