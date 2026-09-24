# Canonical publication of workflow observations

FG-095b now has a node/library path from a retained trusted job observation to
an immutable canonical forge event and its delivery obligation. This is not a
passing required check, a runner signature, or permission to merge. The event
records what an authenticated local publisher submitted; it does not establish
that its producer was independently trusted or that its process was isolated.

## One publication path, no second authority

`WorkflowCheckRecord` and `WorkflowCheckObservedNative` already define the
bounded observation event. The reference intent vocabulary now has a distinct
`WorkflowCheckObserved` kind. Its source ref is a read dependency, not a ref
mutation. Existing trace and normal-form tags are unchanged; the new required
intent tag is 8. The existing canonical event kind remains 11. Older readers
must refuse unknown required kinds rather than reinterpret them as approval.

`fgit_admission::merge::native::workflow_checks::admit_async` uses the existing
metadata admission driver. It seals the exact event root, resolves an existing
terminal outcome first, authenticates the selected authority basis, validates
the source and immutable aggregate, and stages the complete forge/outbox fold.
The event's inline evidence, authenticated publisher, source coordinates and
conclusion are bound to that original seal. A correct but unrelated seal cannot
be substituted at preparation.

Only the successful exact-predecessor repository-head CAS makes the observation
and delivery obligation canonical together. The resulting ref, retention and
protection-policy roots are unchanged. There is no ref-only publication followed
by a second event write, no mutable results database, and no authority inferred
from local journal files. Existing forge feed/outbox machinery carries the event.

Each publisher/run/attempt/job identifies an immutable observation stream.
A different request cannot overwrite that stream, even with a new idempotency
key. Reusing the original key with changed semantics refuses. An exact retry
returns its original terminal result before source/aggregate freshness checks,
including after the branch subsequently moves. Missing backend dependencies
remain retryable infrastructure failures; they are not invented job failures.

## Node composition

On the existing Linux trusted-workflow node profile, first select a completed
batch/fact and its actual evidence bytes from the retained journal. The bounded
pure intake helper is:

```rust,ignore
let record = OneNode::workflow_check_record_from_batch(
    reporting_branch,
    &batch,
    fact_index,
    &evidence,
    &live,
)?;
```

The existing runner decoder verifies the exact proposal/evidence binding,
including native source, tenant/repository, run/attempt, graph, job, original
limits, timestamp and normalized outcome. The record retains the original
per-job evidence bytes. Queued/in-progress facts, the wrong fact index, another
job's evidence, malformed records and oversized evidence are refused. This
canonical event profile admits at most 1 MiB of evidence per job; the larger
local journal limit does not silently widen it or permit truncation.

Then submit under an independently established local authenticated session:

```rust,ignore
let (tx_id, terminal) = node.admit_trusted_workflow_check_in(
    &request,
    &session,
    &record,
    admission_limits,
).await?;
```

The node independently checks the record against its typed evidence, repository
and actual authority-selected source. The reporting branch must currently exist,
be visible, and name exactly the evidence's executed commit. It may be a different
ref that names the same commit; this is an explicit reporting subject, not an
assertion that the evidence proves the original workflow-launch ref. Unpublished
candidate commits are not admitted merely because a local workflow ran them.

Native commit bytes are read through the existing identity-verifying object
source, parsed in the repository's SHA-1/SHA-256 domain, and required to refer to
a tree in the authority-selected closure. The shared projection supplies current
principal/policy and publication checks. The request context owns cancellation
and budgets. A projection-basis mismatch remains unavailable, not a fabricated
permanent source-moved decision.

This API does not execute a workflow, acknowledge or consume the custody journal,
change a branch, inject secrets, or fabricate a downstream acknowledgement. The
caller retains the returned canonical transaction outcome separately. Reading an
old local receipt is not itself authorization to call the publication method.

## What an observation does not authorize

A succeeded or skipped trusted job becomes **ActionRequired**. Failure, cancelled
and timed-out conclusions remain distinct. There is deliberately no Success or
Neutral conclusion in this observation event profile, and no conversion to an
independently verified `CheckReceipt` or protection grant.

A valid evidence frame establishes internal consistency, not that untrusted
bytes are true. This local authenticated-publisher API must not be exposed as
an untrusted CI upload endpoint. Independent producer authorization, remote
attestation, protected-check admission and hostile-code execution remain separate
work. Likewise, historical recovery may report a prior decision after policy
changes; it does not authorize a new effect under the old policy.

`workflow_checks::read_at` resolves one immutable observation through an exact
authority-selected forge frontier and verifies the stored event identity. It is
a storage-level reader: serving callers must authenticate the requester and apply
source-ref/log disclosure policy before returning its contents. No new public
HTTP or CLI publication endpoint is introduced in this increment.

## Verification boundary

The transaction increment adds seven reference/normal-form tests. The admission
increment adds seven pure preparation tests for seal binding, event/outbox
coupling, source changes, occupied streams and bounds. The node increment adds
seven tests, including actual OneNode source import, trusted shell execution,
canonical publication, disk reopen and exact retries in both native Git domains.
Tests also cover evidence substitution, duplicate streams, source movement,
negative outcomes and preservation of local custody bytes.

Run with the repository's pinned toolchain:

```sh
cargo test --locked -p fgit-reference workflow
cargo test --locked -p fgit-txn workflow
cargo test --locked -p fgit-admission workflow_checks
cargo test --locked -p fgit-node --lib trusted_workflow::durable::publication
```

Cargo and rustc were unavailable in the editing environment. These Rust tests
were authored but not compiled or executed. Source/API review, intended-commit
diff review, exact uploaded blob checks and independent lexical/native-fixture
checks are narrower evidence, not substitutes for Rust testing, native
conformance, power-loss testing or production readiness. FG-095b is not closed.
