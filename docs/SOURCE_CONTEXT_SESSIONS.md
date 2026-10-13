# Durable same-source context sessions

`scripts/operator/source_context_session.mjs` adds a bounded local owner for a
sequence of explicit source-context follow-ups. It composes the existing
continuation client and private bundle exporter; it is not a second search
engine, native server session, Agent Protocol IntentRun, or authorization grant.

The gap addressed is aggregate accounting and durable lineage. Independent
`continueCapture` calls have separate budgets and return a parent link only in
their receipt. A session retains every request and result in a hash-linked,
create-only ledger, and reserves each call's entire configured allowance before
network I/O. Failed, cancelled and interrupted calls never refund unreported work.

## Native-client composition

```js
import { createSession, runSessionStep, inspectSession, recoverSessionStep }
  from './scripts/operator/source_context_session.mjs';

const created = await createSession(sessionDirectory, priorBundle, priorManifest, {
  queries: 4,
  work: 67108864,
  payload_bytes: 134217728,
  source_bytes: 268435456,
  excerpt_bytes: 4194304,
});
// Retain the session hash and each latest tip independently.
const result = await runSessionStep(sessionDirectory, created.session_sha256,
  created.tip_sha256, { terms: ['rollback'] }, readCredential, { timeoutMs: 30000 });
```

Initialization verifies and copies the independently pinned parent into `base/`;
the external original remains untouched and is no longer needed for replay.
Initialization is local: no query, credential or remote write is required. The
base was acquired before this session and is not charged as a follow-up.

Every successful follow-up inherits the last successful capture's exact source,
strongest observed lexical checkpoint, independent symbol floor, path scopes
and per-request bounds through the existing continuation implementation. Terms
may change and bounds may narrow, not widen. Required symbols stay required.
Each result remains independently inspectable with the normal bundle inspector.
Partial context is retained as explicitly partial; completeness never describes
the union of queries or claims that earlier omissions have been filled.

## Reservation and publication

The maximum is 16 follow-up positions. The caller supplies all five cumulative
ceilings: query count, lookup work, index payload bytes, source decode bytes and
retained excerpt bytes. Their per-call charges are respectively 1, `max_work`,
`max_payload_bytes`, `context_max_source_bytes` and `context_max_excerpt_bytes`.
All five must fit before the next position is claimed. Smaller actual receipts
are not refund evidence: failed channels may have consumed unreported work.
These are configured native allowances, not total wall-clock CPU, transport
headers, authority metadata I/O, monetary spend or a system-wide hard quota.

The on-disk layout is:

```text
session.json                  # pinned session profile/base hash/ceilings
base/{capture.json,context.txt,manifest.json}
steps/0001/request.json        # exact previous tip, parent, query, reservation
steps/0001/started.json        # one-shot dispatch marker
steps/0001/candidate.json      # exact export hashes before bundle publication
steps/0001/bundle/{capture.json,context.txt,manifest.json}
steps/0001/terminal.json       # captured or settled read_refused
```

Exclusive next-position directory creation prevents concurrent reservations from
both succeeding. Exclusive `started.json` creation prevents two processes from
dispatching the same reservation. No marker is cleared based on PID, elapsed time
or a successful parse. Requests and dispatch markers are synced before network
I/O. Validated predecessor records are independently resynced before new
responsibility: seeing another writer's complete bytes is not proof its fsync
finished. The usual exporter writes payloads first and the manifest last; session
terminal publication follows verified candidate readback and local syncs.

`reserveSessionStep`, `acquireSessionStep`, and `recoverSessionStep` expose those
separate responsibility boundaries for a host. `runSessionStep` composes them
under one total deadline. A dispatch returns a staged candidate; recovery/finalize
accepts its exact request and candidate hashes. There is no network retry in
finalization. HTTP refusals and settled cancellation append a refusal terminal
while keeping the full reservation charged; the next explicit request can use
that terminal as its predecessor without losing the last successful context.

## Restart and verification

Inspection requires the independently retained session root and at least one
retained terminal tip. A missing/forked tip refuses rather than rolling back.
New reservation requires the *exact current* terminal tip; it never guesses
`latest`. Keep the latest returned tip, especially after a refused query.

A crash may leave a reserved step, an in-flight/interrupted read, an exact export
candidate, or a terminal whose reply was lost. Inspection names the pending
request and candidate hashes. `recoverSessionStep` may adopt only the originally
recorded candidate with its explicit retained hash, checking its query/source,
payload hashes, excerpts and text projection before resync and terminal write.
Already settled steps recover idempotently without new cost or network traffic.

No candidate means there is no result to adopt. A missing or partial export is
not permission to requery, substitute another capture, abandon the position,
refund its reservation or begin a successor. Such states remain blocked and
need host/operator investigation. A recorded but undispatched reservation can
be explicitly acquired once through the lifecycle API; a started reservation
cannot be redispatched, even after process death. There is deliberately no
force/reset/abandon option. Never delete files to make a session continue.

Replay checks the complete bounded ledger and all referenced captures, one at a
time. This is linear in retained session data, not constant-time inspection.
Only fixed internal names are used as filesystem paths. Owner-private POSIX
files/directories, symlink/link checks, exact record bytes, and existing bounded
bundle validation apply. Records retain no credential, credential fingerprint,
raw headers or repository instruction authority. Fixed step, record and bundle
limits bound local retained data; the five logical query ceilings are not a
separate filesystem-storage quota.

This assumes a trusted owner-private local filesystem. It cannot prevent an
owner from creating another session or deleting unobserved state; retained
external tips detect rollback only through the observations they bind. It is
not a distributed lock, authenticated authority proof, hostile-parent filesystem
confinement, hardware power-loss proof or a completed agent control plane.

## Verification command

```bash
node --test tests/operator/source_context_session.test.mjs \
  tests/operator/source_context_continue.test.mjs
```

Tests use complete production modules, real private files, normal child
processes, actual HTTP sockets and explicit native-schema peers. They cover
both Git hash formats, cumulative exact/one-under budgets, concurrent reservation
and dispatch, required symbols, same-source rejection, retained tips, corrupt
records/payloads, cancellation, SIGKILL during a streamed read, and process exit
after export followed by original-candidate recovery. They are not live Rust
server interoperability or whole-workspace verification. FG-032 remains open.
