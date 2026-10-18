# Recover a watched check publication without replaying it

`scripts/fg_workflow_checks.mjs recover` resolves previously started publication
requests through the existing native `POST /api/v1/outcomes` API. It reads the
original keys from the publisher's saved plans. It never runs `fg`, opens local
repository storage, reads workflow artifacts, submits a check body, or executes
workflow code.

Use this when `fg workflow publish` may have committed but its response was lost,
including when the original workflow journal or local executable is unavailable.
The remote node must still have the original repository authority and expose the
outcome API. Unavailable authority is not replaced by a local receipt or guess.

## Inputs and trust

Retain the original private watcher configuration file and the publisher's
private state directory, including `binding.json`, `plan-*.json`, and the
corresponding `started-*.json` records. Configuration values and original paths
remain part of request identity even when the files at those paths no longer
exist. Do not edit the configuration to point at a new executable or source
store merely to perform recovery. Missing or conflicting publisher records are
refused, not regenerated from an untrusted report.

Choose the repository endpoint independently of any workflow or repository
content. On the first recovery invocation it is saved in
`recovery-binding.json`, bound to the complete original publisher configuration.
Subsequent invocations require the identical canonical URL. A different endpoint
is refused before sending credentials. This equality pin prevents silent
retargeting; the first URL is still an operator trust decision, not independent
proof of server authenticity or authority freshness.

Supply a current 64-character lowercase hexadecimal token identifying the
**original publisher principal**, with the server's independent `outcomes-read`
grant. The token may be rotated; changing the principal is not rotation. The
server authenticates the principal and selects its key namespace. The client
checks the returned tenant, repository, incarnation and principal against the
retained configuration. A token with write permission does not cause this
command to send a write.

Place the token in an owner-private regular file in an owner-private 0700
directory, without symlink aliases. A single final LF or CRLF is permitted.
The token itself is not a command-line argument, URL parameter, saved receipt,
or diagnostic. Treat publisher plans and outcome records as private metadata.

```bash
node scripts/fg_workflow_checks.mjs recover \
  --watch-config /srv/workflow/watch.json \
  --state /srv/workflow-publication \
  --principal-id "$ORIGINAL_PUBLISHER_PRINCIPAL" \
  --trusted-local \
  --endpoint https://forge.example/team/repo.git \
  --token-file /srv/credentials/outcome.token \
  --max-lookups 128
```

HTTPS uses certificate verification. An optional `--ca-file` accepts a private
PEM CA file of at most 128 KiB; it does not disable hostname or certificate
checks. Cleartext HTTP is permitted only for numeric loopback addresses
`127.0.0.1` and `[::1]`, not arbitrary hosts or a DNS `localhost` alias.
Redirects, ambient cookies, connection pooling, automatic retries, compressed
responses, and mutation body/endpoint options are not supported.

## What recovery establishes

Only jobs whose original start responsibility has been persisted and whose
terminal is unresolved are queried. An unsent plan is neither submitted nor
queried. Each selected key is queried at most once per invocation.

`key_not_observed`, `seal_not_observed`, and `undecided` remain unresolved. None
proves rollback or permits automatic resend. When a transaction is observed,
its exact transaction ID, seal ID, request schema, and canonical request digest
are retained in a create-only `observed-*.json` record. A later terminal is
retained separately in `recovered-*.json`; the first observation is never
rewritten. A first observation that is already terminal needs only the original
`observed-*.json` record. Missing transactions, substituted seals, changed
principals, and contradictory decisions fail closed against retained knowledge.

A native committed or refused decision settles that original **publication
transaction**. Decision sequences retain all 64 bits, including unquoted native
JSON integers beyond JavaScript's exact numeric range. The generic outcome API
does not return a check ID, so recovery reports `check_id: null` instead of
fabricating a check-specific publication receipt.

Offline `status` and subsequent publisher `once`/`resume` recognize these
recovered terminals and skip their requests. `resume` remains a distinct,
explicit mutation operation for requests that are still unresolved, using its
original principal, keys and required native files. Recovery never invokes it.

A terminal outcome does not establish current branch state, process containment,
workflow reaping, downstream delivery, or passing required checks. Successful
trusted-local jobs continue to be `action_required`. Nothing here introduces
PR triggers, hostile-code isolation, signed runner attestation, or merge
permission.

## Locks, interruptions and partial progress

The normal publisher retains `owner.lock`. Recovery does not acquire, delete,
reset or steal that lock: checking a transaction's outcome cannot establish
whether a sender or its children have stopped. This permits read-only remote
lookup while a crashed or active sender's lock remains intact, without enabling
another sender.

Recovery has its own exclusive `recovery.lock`. Concurrent recovery writers
refuse. A SIGKILL can leave it in place; there is no automatic lock stealing.
`status` remains available and reports both `owner_present` and
`recovery_owner_present`. Reconcile the owning process and filesystem condition
before operator intervention; lock removal is not part of this command.

SIGTERM/SIGINT close an outstanding read socket and prevent new lookups. A fully
validated terminal that wins the response/cancellation race is saved before
stopping. A failure after one job does not erase its decision or start another
job. A later recovery invocation reads only the remaining started requests.

A concurrent native sender may store its own terminal while recovery is reading.
The two observations must agree on transaction and terminal decision; neither
silently overwrites the other. If local publication completes after an earlier
nonterminal HTTP snapshot, repeat the read explicitly instead of treating the
older observation as a regression of local knowledge.

Local persistence, observer, cleanup, and stdout failures are distinct from a
canonical refusal. Error output retains any validated terminal and partial
recovery summary. A returned terminal can be known even when its local save
failed: preserve the diagnostic and inspect state before retrying the same read.
No local error certifies non-commit.

## Bounds and exit codes

The default maximum is 128 original-key lookups per invocation, configurable
with `--max-lookups 1..128`. `--request-timeout-ms` defaults to 30000 and permits
1..300000 ms. `--timeout-ms` defaults to 660000 and permits 1..660000 ms for the
whole operation. The remaining whole-operation time caps every network read.
Native outcome bodies are limited to 16 KiB and selected headers to 16 KiB.
Filesystem checks are cooperative between bounded operations; synchronous
filesystem latency and arbitrary library observers do not have hard deadlines.
The CLI owns its separate bounded stdout deadline.

The original 32 MiB plan/start/native-terminal reservation and existing run/job
limits are unchanged. A separate allowance reserves at most two 8 KiB outcome
records per job and an 8 KiB endpoint binding. Aggregate publisher metadata reads
are capped at 64 MiB; capacity is checked before admitting a new plan. The extra
allowance cannot increase new-work capacity or evict original receipts.

Exit 0 means all saved jobs are settled as committed, or there are no pending
jobs. Exit 1 means at least one saved canonical refusal and no pending jobs.
Exit 3 means pending/unknown work, a lookup limit, or an unavailable outcome.
Exit 2 means input or local-state failure. Exit 4 distinguishes a known terminal
from later local delivery/cleanup failure. Saved terminal observations are
historical, not a claim that their HTTP lookup was repeated on every invocation.

## Validation boundary

Run the transport and integrated client tests with a Node runtime supporting
JSON reviver source context (tested with Node 22.16.0):

```bash
node --test \
  tests/operator/transaction_outcome.test.mjs \
  tests/operator/workflow_check_outcome.test.mjs \
  tests/operator/workflow_check_publish.test.mjs \
  tests/operator/workflow_watch.test.mjs
```

Tests use real HTTP/TLS sockets, files, process signals and CLI child processes.
They cover saved-plan recovery, lost publication replies, source/executable
loss, original keys, partial progress, exact counters, receipt conflicts and
both ownership locks. The native executable and server responses are explicit
contract fixtures, not Rust `fg`, native evidence verification or authority CAS.
No native/Rust, hardware power-loss or full-workspace acceptance is claimed.
