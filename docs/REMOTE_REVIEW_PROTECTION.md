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
independent `protection-read` / `protection-write` grants as appropriate. First
installation remains `fg protection set ... --trusted-local --expected-version 0`
on the server host. A remote request cannot enroll its own first administrator.
Every required reviewer on a protected branch remains mandatory; neither the
PR opener nor merge submitter supplies independent approval. Local workflow
observations do not become passing CI checks.

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
    "required_reviewers": ["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]
  }]
}
```

`reference_hex` carries native branch bytes (`refs/heads/main` above), including
non-UTF-8 names without lossy conversion. Limits match the native profile: 32
administrators, 64 branches, 32 reviewers per branch, and a 256 KiB encoded
command. Long branch names may exhaust the byte budget before the count limits.
Empty branch lists require explicit `--clear` and still retain administrators.

```sh
node scripts/fg_protection_admin.mjs prepare \
  --endpoint https://forge.example/team/repo.git \
  --token-file ./operator.token --scope-file ./scope.json \
  --principal aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --policy-file ./replacement.json --intent ./policy-change

node scripts/fg_protection_admin.mjs show-intent --intent ./policy-change
```

Preparation performs one read and creates a new private intent directory. It
never sends a mutation. Output lists administrator and reviewer additions and
removals, the original head/version/epoch, and the exact intent digest. Every
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

## Evidence boundary

Run `node --test tests/operator/review_protection.test.mjs`. These tests exercise
the actual client, real loopback HTTP sockets, native response schemas and actual
private files. The server peer is explicitly a contract fixture, not the Rust
node. They do not establish native authorization/CAS correctness, live `fg`
integration, deployment TLS correctness, power-loss durability or a full-workspace
pass. The wider policy-integration bead remains open to its own acceptance gate.
