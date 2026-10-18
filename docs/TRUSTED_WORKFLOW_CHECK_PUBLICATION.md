# Trusted workflow observations in canonical forge history

FG-095b's `fgit-forge::event::workflow_check` defines an immutable job
observation. It records what an authenticated reporting principal submits,
not independently attested execution. The native publisher verifies the exact
completed job against its original retained execution evidence before publishing
`Success`. Skipped jobs remain `ActionRequired`; unsuccessful jobs retain
`Failure`, `Cancelled` or `TimedOut`. A conclusion alone grants no merge
permission. An administrator can explicitly select a publisher and exact
workflow subject through the
[required workflow check profile](REQUIRED_WORKFLOW_CHECK_PROTECTION.md).
The observation remains a trusted-host report, never an independent runner
attestation or review approval.

Custody history and canonical publication have different result contracts.
`fg workflow recover` preserves the original proposal: succeeded and skipped
jobs both have an `action_required` custody conclusion. `fg workflow publish`
decodes and verifies the saved execution evidence, then maps only an actually
succeeded job to canonical `success`. Recovery never rewrites the journal to
match the published result, and publication never acknowledges or reruns it.

## Identity and compatibility

Each publisher/run/attempt/exact UTF-8 job name has one full 256-bit identity.
The stream label is `check/` followed by 52 lowercase base32hex characters with
canonical zero padding. No invocation or job digest is truncated to fit the
existing 64-byte forge label. Different evidence, source or conclusion for the
same identity does not create a second stream; publication must reject a second
terminal report. A deliberate new execution requires its own attempt identity.

The event adds required aggregate kind 7 (zero u64 escape, u32 kind, raw 32-byte
identity) and payload kind 11 to the existing forge-event codec. The aggregate
version is exactly 1. The payload binds reporting principal, canonical branch,
native source commit, run/attempt/graph commitments, exact job name, conclusion,
and original evidence bytes. `workflow_check.rs` is the byte-layout authority.
Existing aggregate and event tags, schema versions, and body encodings remain
unchanged. `Success` uses conclusion value 5; the existing values 1–4 retain
their meanings. Older readers reject the new required kind or conclusion rather
than ignoring an authority-selected event they cannot interpret. Upgrade readers
before publishing these records; do not write them into a mixed-version deployment.

Job names are nonempty UTF-8 without controls, at most 1,024 bytes. Evidence is
nonempty and bounded to 1 MiB, checked before copying or encoding. Evidence
bytes are inside the event, so a later forge publication retains them under the
same immutable event/batch commitments instead of an untracked local file.
This first subject profile names canonical branches; tag peeling, unpublished
candidates, and signed independent runner attestations are separate boundaries.

## Current scope

The event and batch encoders/decoders implement these identity, framing and
resource checks. `OneNode::admit_trusted_workflow_check_in` verifies evidence and
publishes the observation through ordinary admission and authority-head CAS.
The native PR checks APIs select canonical observations for the exact recorded
source ref and commit; stale source observations do not apply to a moved source.
The legacy digest-valued PR projection does not reinterpret observations as PR
rows. Canonical protection can now require a named publisher, current source
branch, graph and exact job for the proposed new commit. That separate admission
gate selects the latest matching canonical conclusion and requires `Success`;
review requirements still apply independently. No check gains authority merely
by appearing in the PR checks API, and normal merges must check the merge
candidate itself rather than an unrelated source-tip commit.

## Verification

The Rust codec tests in `event/workflow_check/tests.rs` cover both native hash
domains, admitted conclusions, full check identities, canonical labels,
conflicting bodies, aggregate/version corruption, exact bounds, truncation,
unknown conclusions and legacy-byte preservation. Node publication and HTTP
tests assert canonical `Success` after verified execution, including reopen and
source movement; custody tests retain `ActionRequired` for the same local job.

`scripts/e2e/workflow_publication_smoke.py` and
`scripts/e2e/workflow_dispatch_smoke.py` exercise fresh real `fg` processes,
original custody recovery, exact evidence publication and terminal retries in
both Git hash formats. The publication campaign also refuses a protected branch
update while its successful check is visible, then admits the same update under
an explicitly disabled policy. Those campaigns cover review-only protection.
The configured workflow gate has separate native tests for exact candidates,
trusted publisher selection, later failures, source movement and direct updates,
described in [the check profile](REQUIRED_WORKFLOW_CHECK_PROTECTION.md).

Run `./scripts/verify.sh pull-request-checks` with the pinned toolchain for the
owning integration lane. The listed coverage describes test assertions, not a
passing gate at an unspecified revision.
