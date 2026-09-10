# Durable exact-candidate reviews and gated publication

This implementation joins three real operations: record a review of actual
candidate bytes, read current reviewer decisions, and publish a merge only when
every explicitly required reviewer currently approves that exact candidate.
It reuses the existing immutable forge event stream, canonical outbox, native
object inspector, production quarantine, and exact-predecessor authority CAS.
There is no mutable review database or alternate publication point.

**Scope:** `merge apply-reviewed` is an explicit, sealed named-reviewer
precondition. It is not repository-wide protected-ref configuration. Existing
trusted-local `merge apply` and other source-mutation APIs are unchanged.
Deployments needing mandatory protection across every entrypoint must bind the
requirements to authenticated repository policy and enforce them across all
applicable mutation paths. This command alone does not do that.

## Record an exact review

First inspect the saved candidate with `fg merge inspect`. A source-side PR
diff is insufficient for manual conflict resolution: the actual merge may
contain bytes absent from both parents. Then record an explicit decision:

```bash
fg pr review "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$REVIEWER_ID" --idempotency-key "review-17-v1" \
  --expected-version 1 --review-version 0 --decision approve \
  --source-ref refs/heads/topic --target-ref refs/heads/main \
  --source-tip "$SOURCE_COMMIT" --target-tip "$TARGET_BEFORE" \
  --merge-base "$BASE_COMMIT" --candidate "$CANDIDATE_COMMIT" \
  --policy-epoch "$POLICY_EPOCH" --bundle ./candidate.bundle \
  --reason 'Reviewed the exact candidate and its metadata'
```

The PR must already exist. `--expected-version` is its current metadata version;
`--review-version` is this reviewer's independent stream version, with zero
meaning no previous vote. Another reviewer does not advance this stream or the
PR metadata version. Reviewer identity comes from the authenticated local
session; repository text cannot choose it. `--trusted-local` requires an already
authorized operator and is not a remote authentication mechanism.

`--decision request-changes` records a blocking decision for the same exact
subject. `--decision withdraw` retracts the reviewer's own current decision;
provide its exact subject/candidate, positive review version, and a nonblank
reason, but no bundle. Withdrawal remains possible after PR closure, branch
movement, or a policy change. It cannot retract another reviewer or silently
switch the old candidate. Approval reasons may be empty; other reasons must be
nonblank. Reasons are bounded UTF-8 data, not commands or policy.

Before a new non-withdrawal review can commit, the node authenticates the PR,
live branch tips and policy epoch, and invokes the existing full candidate
inspector at the exact authority head. Native object hashes, ordered parents,
base ancestry, full reachable closure, and actual resulting-tree comparison are
validated without importing the candidate. The immutable review binds the
candidate commit (therefore its metadata and tree), merge base, source/target
refs and tips, PR number/version, policy epoch, reviewer, decision and reason.
This verifies the bytes named by the vote, not whether a person understood them.

The old source-only review profile 1 retains its bytes. Additive profile 2
(`exact-merge-candidate-v1`) appends candidate/base identities. Source-only votes
are readable but cannot satisfy exact-candidate publication. Review decisions
use receipt type `candidate_review_decision`, distinct from the existing
read-only artifact inspector's `candidate_review` receipt.

## Publish with named reviewers

```bash
fg merge apply-reviewed "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$SUBMITTER_ID" --idempotency-key "merge-17-v1" \
  --expected-version 1 --source-ref refs/heads/topic --target-ref refs/heads/main \
  --source-tip "$SOURCE_COMMIT" --target-tip "$TARGET_BEFORE" \
  --merge-base "$BASE_COMMIT" --candidate "$CANDIDATE_COMMIT" \
  --policy-epoch "$POLICY_EPOCH" --bundle ./candidate.bundle \
  --require-reviewer "$REVIEWER_ID"
```

Repeat `--require-reviewer` for additional required principals. The set must be
nonempty, contain no duplicates, and have at most 32 members. All named
reviewers must approve; it is not a quorum over a partial page. The PR opener
and merge submitter cannot satisfy the requirement. Distinct principal IDs are
not, by themselves, proof of organizational or human independence.

The sorted reviewer set and policy epoch become a required scoped entry in the
original semantic merge seal. Changing or dropping the set is a different
request and cannot reuse its idempotency key. The gate resolves the latest
canonical vote for each named reviewer, requires exact subject/candidate equality,
and rejects missing, stale, withdrawn, source-only, or change-request decisions.
Unlisted reviewers are not part of this named-set precondition.

The check executes inside the existing native publication driver on every CAS
attempt, not only as a CLI preflight. A review withdrawal or PR change uses the
same authority head: if it wins while a merge is preparing, the merge's old CAS
cannot publish, and the next attempt rechecks the newly selected votes. Only
then can the ordinary coupled Ref + Forge + Outbox transaction become canonical.
This is code-path integration, not a claim that the complete concurrent fault
matrix has been executed at this revision.

## Read decisions and recover outcomes

```bash
fg pr reviews "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --limit 50
```

Reads default to SHA-1; use `--object-format sha256` for SHA-256 nodes. Mutations
infer the format from the required native identities and reject mixed formats.
Pages are sorted by reviewer ID and return `snapshot_token` and `next_after`.
A continuation requires both `--after` and the first page's `--expected-head`.
A moved snapshot refuses instead of mixing versions. A page never claims an
approval threshold: `approvals_satisfy_policy` is null. `page_complete` means the
requested page is complete; `complete` is false when a continuation exists.
Source-only profile, candidate identities, freshness and opener relation remain
explicit in each row. Canonical hidden-ref policy still applies to both branches.

Terminal recovery precedes new-publication checks. Replaying a committed merge
after a withdrawal returns its historical commitment; it does not claim the
withdrawn vote still approves a new merge. Conversely, a canonical missing-vote
refusal remains a refusal after somebody later approves. A new intended attempt
uses a new key; recovery of an earlier attempt uses its identical key and fields.
The node APIs can recover a terminal review or merge without candidate bytes.
The CLI presently reads required local artifacts before invoking those APIs, so
retain those files for CLI retries. Withdrawal does not require a bundle.

JSON distinguishes a committed review event from a Git-ref change. Known terminal
outcomes are retained when shutdown or receipt output fails. Missing terminal
information and a nonzero exit are not proof of non-commit. Exit 0 is a committed
mutation or successful page; 3 is a canonical refusal; 4 is an absent/hidden PR;
2 is an input, infrastructure, shutdown or output error. Consumers must parse a
complete document and inspect the terminal fields, not only the exit code.

## Bounds and verification status

Reasons are at most 16 KiB; read pages at most 100 rows; the existing read profile
bounds frontier entries and cumulative event data. Required reviewers are at most
32. Bundle, object, graph and diff budgets come from the existing bounded native
inspector/quarantine profiles. Exhaustion is an error, not a successful partial
approval. Candidate bytes remain caller-owned artifacts until source publication;
a durable vote does not promise that its bundle has been archived in the node.

The integration adds three candidate-codec tests, two gate tests, five registered
embedded-authority tests and four CLI tests. They cover both hash formats,
exact-candidate binding, withdrawal, source-only refusal, opener/submitter exclusion,
missing votes, stale metadata, key conflicts, pinned reads, no review-time native
object staging, and terminal recovery. Existing source-review tests are retained.

```bash
python3 scripts/e2e/candidate_approval_publication_smoke.py --self-test
python3 scripts/e2e/candidate_approval_publication_smoke.py --fg /absolute/path/to/fg
```

The new campaign preserves the existing `candidate_review_smoke.py` inspection
campaign. It constructs a manual resolution independently of both parents and
uses fresh CLI processes for reviews, withdrawal, gated publication and recovery.
Its Python helper self-test was executed, as were isolated Git 2.47.3 fixture
fsck, bundle verification, fetch and resulting-byte checks for both hash formats.
Those are fixture/checker checks, not executions of FrankenGit.

Cargo, rustc and a built `fg` were unavailable in this environment. Rust compilation,
Clippy, formatting and the complete real-binary campaign were not run. The native
build/runtime gate, repository-wide protection administration, remote identity
integration, moderator dismissal and required-check policy remain outstanding.
No bead is closed on the strength of this source integration.
