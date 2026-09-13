# Mandatory exact-candidate review protection

This implementation adds a repository-selected review policy to the embedded
`OneNode` publication paths. It is no longer necessary for a writer to choose
`merge apply-reviewed` in order for the selected requirements to be enforced.
The source and tests are implementation candidates: the full native build and
runtime verification are separate gates, not implied by this document.

## Scope and deployment boundary

The supported policy names exact `refs/heads/*` references and requires every
listed reviewer to approve the exact native merge candidate. It supports current
policy administrators, replacement, disabling, and ownership rotation. It does
not implement the general compiled-policy language, review-count thresholds,
glob rules, status checks, signed-commit requirements, merge queues, remote
identity or metadata ACLs. The existing compiled-policy storage remains separate.

**Upgrade every writer before activating this profile.** Enforcement is in this
version of the embedded node. Arbitrary application-supplied lower-level authority
writers, old binaries, or a process that controls the authority database can
bypass application-level checks. No mixed-version writer compatibility, downgrade
barrier, or remote authorization guarantee is claimed. A trusted local caller must
supply the actually authenticated principal; an arbitrary principal ID is not a
credential. The first installation is authorized by that existing operator trust
boundary, not by a newly introduced remote administrator service.

## Read and replace the policy

```sh
fg protection show "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local

fg protection set "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ADMIN_ID" \
  --idempotency-key protection-install-1 \
  --expected-version 0 --expected-epoch 1 \
  --admin "$ADMIN_ID" \
  --require-reviewer "refs/heads/main:$REVIEWER_A" \
  --require-reviewer "refs/heads/main:$REVIEWER_B"
```

The example version and epoch apply only to a first installation at epoch one.
Read the actual values rather than refreshing or guessing a predecessor during
an uncertain retry. Add `--object-format sha256` for a SHA-256 node.

`set` replaces the complete policy. Repeated administrators and reviewer entries
are sorted before sealing; duplicates refuse rather than silently disappearing.
At most 32 administrators, 64 exact branches and 32 reviewers per branch are
accepted. The first administrator set must contain the installing principal.
Subsequent changes are authorized by the **old** administrator set. Supplying a
new administrator list cannot authorize its own installation.

Disabling is explicit and retains administrative ownership:

```sh
fg protection set "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ADMIN_ID" \
  --idempotency-key protection-disable-1 \
  --expected-version "$POLICY_VERSION" --expected-epoch "$POLICY_EPOCH" \
  --admin "$ADMIN_ID" --clear
```

An empty branch list disables review requirements but does not reset the stream,
forget its administrators, or turn the next replacement into a first install.
A replacement may rotate all administrators, but only a currently authorized
administrator may perform it. Every successful change, including an otherwise
identical replacement, increments the repository policy epoch. Approvals from
older epochs consequently cannot satisfy the new policy. There is no implicit
refresh of PR coordinates, reviewer versions or candidate identities.

`show` returns the selected head, epoch, singleton version and complete policy.
It distinguishes never-installed from explicitly disabled. `ref_hex` always
preserves exact reference bytes; `ref` is null for a non-UTF-8 name. CLI input
accepts UTF-8 names, while the library retains the native raw-reference type.

## Canonical publication and recovery

A policy change is a required `ReviewProtectionChanged` event in the singleton
`review-protection` aggregate. It uses existing forge-position state, immutable
batches, outbox obligations, transaction seals, and repository-head CAS. There
is no mutable side database, on-disk policy toggle, special branch, or reuse of
the hidden-ref configuration's `policy_root`.

The canonical event binds actor, expected policy epoch, administrators and the
entire required-reviewer map. Its aggregate version binds the exact predecessor.
The request's existing stable transaction identity therefore distinguishes every
material change without including a mutable current-head value.

The policy-authorizing RCR names the **old** policy epoch; the successor head
names the incremented epoch. Native history loading permits this difference only
for the exact checked singleton transition: one decision and RCR, one epoch
increment, unchanged ref/retention/configuration roots, the authenticated event
batch, the old administrator authorization, and the matching selected successor
policy. Other epoch mismatches still refuse.

Terminal recovery precedes new-publication quota/service checks. Retrying the
same command recovers its original committed or refused decision, even after
another policy replacement or a shutdown/reopen. A changed command under an
existing key is not a retry. Policy changes never move Git refs and an enqueued
outbox obligation is not evidence of external delivery. Publication JSON names
`proposed_policy`, not a purported fresh policy read; a canonical refusal reports
no committed policy epoch. Output and shutdown failures retain the known terminal
transaction identity. Artifact-free recovery continues to use `fg outcome`.

## Mandatory checks on mutation paths

The shared durable ref materializer checks the actual folded ref effects against
the policy selected at that attempt's authenticated head, before staging decision
evidence. This covers ordinary receive, source import, local branch operations,
workspace publication, and rebase publication that use that materializer.
Creation of a named unborn protected branch is protected too. An unprotected
branch remains available; a no-ref metadata operation does not become a code
change. A legacy merge materializer cannot bypass the direct-update guard.

Native two-parent merges use the existing candidate-review gate after native
object validation. The required reviewer list comes from current policy, not
from the invoking command. The existing gate checks latest canonical decisions,
exact candidate/base/source/target coordinates, PR version, current epoch, and
reviewer independence from PR opener and submitter. Merely supplying a smaller
list to `apply-reviewed` cannot weaken policy, because both requirements apply.

Policy selection and review validation run on each CAS preparation attempt.
A concurrent policy change or withdrawal replaces the same authority head, so
a losing writer must revalidate. A direct update may commit before activation;
it may not commit after activation by relying on a predecessor's disabled policy.
Known historical outcomes remain historical outcomes, never retroactive refusals.

Unavailable or corrupt selected policy/review bodies are errors, not implicit
allow or synthesized terminal policy decisions. Evaluation refusals use the
existing canonical refusal path. Request cancellation and resource failures
remain distinct from evidence that a transaction did not commit.

## Encoding compatibility

Existing forge-event tags 1–8 retain their exact meanings and bytes. The required
new event uses tag 9; the singleton aggregate uses kind 5. Reference transaction
normal-form encoding adds kind 7 without renumbering existing kinds 1–6. Unknown
required kinds are not treated as optional extensions. No dependency, lockfile,
configuration-carrier schema, alternate runtime or production Git subprocess was
introduced.

## Verification entrypoints and recorded limits

```sh
cargo test --locked -p fgit-forge --all-targets
cargo test --locked -p fgit-txn --test review_protection_effects
cargo check --locked -p fgit-cli --all-targets
cargo test --locked -p fgit-node --lib mandatory_protection
cargo test --locked -p fgit-cli --bin fg protection::tests
cargo test --locked -p fgit-cli --test native_protection_smoke
```

The new tests include codec/identity limits and refusal twins, administrator
rotation and disabled-policy ownership, actual normal-form/outbox folding,
mandatory native merge versus weaker opt-in requirements, direct receive/import
publication, stale reviews after epoch replacement, cancelled requests,
shutdown/reopen recovery, and overlapping activation/publication. The Python
campaign uses fresh real `fg` processes in both native hash formats and constructs
its Git fixture mechanically rather than invoking an external Git implementation.

During development in a 4 GiB container, a source-isolated harness executed all
26 actual forge event/aggregate tests, including six new policy tests, plus the
two new normal-form tests against the real production transaction/reference
crates. The harness copied the unchanged event/aggregate sources and real error
vocabulary but excluded unrelated forge snapshot/chronicle/runtime modules. This
is not execution of the complete forge, admission, node or CLI packages.

Full CLI all-target checking was attempted with the retained pinned
`nightly-2026-08-31` toolchain and locked offline dependencies. Rustc was killed
by the memory limit while checking Asupersync, before reaching the node. A
single-threaded next-solver attempt also failed there. Thus native enforcement,
crash/retry/race tests, the real-process campaign and release gates have not been
executed by these development checks. Test presence is not a passing gate and
no Bead is closed by this document.
