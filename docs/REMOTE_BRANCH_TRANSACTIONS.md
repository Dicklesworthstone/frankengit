# Durable remote atomic branch transactions

The external operator can create, advance and delete branches in one native
atomic transaction without local access to repository storage or a native
executable:

~~~sh
node scripts/fg_branch_transaction.mjs prepare \
  --input /srv/operator/branches.json \
  --token-file /srv/operator/branch-writer.token \
  --request-dir /srv/operator/reviewed-branches

node scripts/fg_branch_transaction.mjs inspect \
  --request-dir /srv/operator/reviewed-branches \
  --confirm "$INTENT_SHA256"

node scripts/fg_branch_transaction.mjs send \
  --request-dir /srv/operator/reviewed-branches \
  --confirm "$INTENT_SHA256" \
  --token-file /srv/operator/branch-writer.token \
  --outcome-token-file /srv/operator/recovery.token \
  --record /srv/operator/branch-result.json
~~~

Retain the intent_sha256 returned by preparation independently. Inspection
shows the complete saved endpoint, repository scope, changes, native form and
original key. Preparation and inspection do not contact the server.

## Exact selection

The input is private JSON with the following shape:

~~~json
{
  "endpoint": "https://forge.example/team/project.git",
  "bind_writer_scope": true,
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "principal_id": "44444444444444444444444444444444",
    "object_format": "sha1"
  },
  "changes": [
    {
      "operation": "update",
      "ref_hex": "726566732f68656164732f746f706963",
      "expected_commit": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "new_commit": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    },
    {
      "operation": "delete",
      "ref_hex": "726566732f68656164732f6f62736f6c657465",
      "expected_commit": "cccccccccccccccccccccccccccccccccccccccc"
    },
    {
      "operation": "create",
      "ref_hex": "726566732f68656164732f61726368697665",
      "new_commit": "dddddddddddddddddddddddddddddddddddddddd"
    }
  ]
}
~~~

Supply the actual repository identity, incarnation, authenticated principal and
independently observed OIDs. The client does not discover or refresh tips.
The examples select refs/heads/topic, refs/heads/obsolete and refs/heads/archive.
All names travel as exact lowercase hexadecimal bytes, including non-UTF-8
branch names; response display text must match those bytes.

The closed client profile reuses the browser's native transaction validators:
1 through 32 changes, distinct branch destinations, names up to 1,024 bytes,
exact nonzero OIDs in the declared SHA-1 or SHA-256 domain, and a bounded form.
Create requires absence; update and delete require an exact old tip. An atomic
rename can be expressed as deletion of the old name plus creation of the new
name at the same commit. The complete ordered batch is retained unchanged.

The native endpoint is /api/v1/source/branches/transaction. All commands share
one native transaction and terminal outcome. A stale lease, occupied destination
or native policy refusal cannot publish only the compatible entries. Native
reachability, non-forced update rules, default-branch restrictions and canonical
branch protection remain authoritative. New tips must already be available
through permitted native history; this operator does not upload Git objects.
See [the native branch API](HTTP_BRANCH_API.md).

## Authorization and credentials

Publication requires the existing native receive grant plus the source and
receive deployment ceilings. Original-key recovery independently requires
outcomes-read and its deployment ceiling. Read, PR and merge grants do not
imply these permissions. The client does not decode a bearer into capabilities.

Set `"bind_writer_scope": true` at preparation to pin the tenant, repository,
incarnation and principal into the mutation form. With this option,
`send --outcome-token-file` uses the separate outcomes-read credential for both
original-key lookups. The publication request uses only the original receive
credential. Both credentials must authenticate the selected principal. The
server checks the publication credential against the pinned scope before
admission, and the operator verifies the scope of each outcome reply.
Only the publication credential fingerprint is retained.

When omitting `--outcome-token-file`, the original sending credential must
have both grants. Saved intents without the binding keep their original form
and use a combined grant. Prepare a new reviewed intent to use separate
credentials. Servers that predate the binding reject the additional form field
before admission. The operator does not retry with an unbound form.

The native sponsored source-branch-create grant applies to the separate
single-create endpoint. Atomic transaction preparation and sending reject
sponsored credentials, including batches containing only creates. Use
[branch bootstrap](NATIVE_BRANCH_BOOTSTRAP.md#sponsored-task-branches) for that
supported agent operation. Recovery accepts the native credential spellings,
but the server must authenticate the original selected principal and an
independent outcome grant; a sponsor is not substituted for its agent.

Credential files contain the exact bearer, optionally followed by one LF.
CRLF, extra whitespace, a BOM, multiple newlines and noncanonical spellings
refuse. Sending requires
that original fingerprint; a rotated same-principal credential can read an
original outcome without acquiring permission to send the saved body.

Only canonical numeric-loopback HTTP or certificate-verified HTTPS is accepted.
Network commands accept --ca-file for a private trust file. Redirects, ambient
credentials, URL overrides and connection pooling are excluded.

## Recovery and retained observations

A missing response is an unresolved observation. Keep the original directory,
pin and key, then perform a read-only lookup:

~~~sh
node scripts/fg_branch_transaction.mjs recover \
  --request-dir /srv/operator/reviewed-branches \
  --confirm "$INTENT_SHA256" \
  --token-file /srv/operator/recovery.token \
  --known /srv/operator/branch-result.json \
  --record /srv/operator/branch-recovered.json
~~~

The optional --known file must belong to this exact retained intent and cannot
conflict with the next native observation. Omit it when no earlier result file
exists. Recovery never calls the branch mutation endpoint. A historical commit
remains the original result after branches move, are deleted, or the server
restarts; it is not a statement about their current tips.

Every explicit send performs original-key preflight and submits at most once.
A known terminal outcome or valid retained publication prevents another send.
There is no automatic retry. An explicit later send uses the unchanged original
key, body and credential, so native idempotency still governs the attempt.
An absent or undecided outcome never establishes non-commit.

Native publication validation covers the whole ordered effect list, ref bytes,
old/new tips, actor, repository/incarnation, hash domain, atomic flag and exact
decimal u64 decision sequence. Request-level HTTP errors are not canonical
refusals. A valid publication survives a later unavailable or contradictory
confirmation; the conflicting observation is rejected before replacing the
compatible retained evidence.

## Local custody and limits

Use absolute owner-private paths outside Git worktrees. Directories must have
mode 0700; files must be private regular files with one link and no symlink
alias. Preparation creates a new request directory, synchronizes its complete
intent, and never repairs or overwrites an interrupted slot.

Each network invocation requires a new create-only --record file, checked
before network work. Received observations drain into bounded local custody
even after network interruption. Failed output does not erase a saved record.
If a local write fails after possible publication, inspect the original request
and recover the same key into another new record path.

The --timeout-ms option accepts 1 through 300,000 and bounds preparation/read
checkpoints and the remaining network operation. CLI output has a separate
ten-second bound. Intent and publication JSON are bounded to 256 KiB; result
records to 320 KiB. Raw server parser errors and bearer values are not printed.

Exit status is **0** for successful preparation/inspection or an observed native
commit, **1** for an observed native refusal, **2** for a local/preflight failure,
and **3** for an unresolved network invocation or failure after retaining or
possibly publishing work. No exit status proves rollback of an earlier attempt.

## Validation scope

Run the focused pinned-Node lane:

~~~sh
scripts/verify_branch_transactions.sh
~~~

It checks module syntax and runs the branch_transaction and
branch_transaction_cli operator suites. These exercise real TCP/HTTP and private
filesystem custody against a peer that speaks the inspected native schemas:
both hash domains, mixed batches and raw byte renames, stale leases, original-key
recovery after lost replies/rotation, response substitution, contradictory
confirmation retention, concurrent result publication, cancellation, strict
credentials and output failure.

The native campaign uses a prebuilt `fg` and pinned Node to exercise split
grants, mismatched writers and readers, exact byte-named effects, retained
output, restart recovery, and an atomic stale-lease refusal in both formats.
The suite retains the native terminal decisions and canonical ref map.

~~~sh
FG_BIN=/absolute/path/to/fg FGE_NODE=/absolute/path/to/node \
  scripts/e2e/suites/operator/remote_branch_transaction.sh
~~~
