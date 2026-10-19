# Required approval counts for protected native merges

Repository administrators can require N approvals from M configured reviewers.
A team can therefore install a 2-of-3 or 2-of-5 rule without waiting for every
listed person to review every merge. Omitting the count retains unanimity.

This is mandatory repository protection. The node reads the current canonical
policy and exact review frontiers inside native publication, including on every
CAS retry. CLI options, PR display rows and caller-provided approval summaries
cannot substitute for that evidence.

## Configure a branch quorum

`fg protection set` replaces the complete policy. Use the actual current
policy version and epoch, and retain every administrator, protected branch and
workflow-check selector that should remain configured:

```sh
fg protection set "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ADMIN_ID" \
  --idempotency-key require-main-two-approvals-1 \
  --expected-version "$POLICY_VERSION" --expected-epoch "$POLICY_EPOCH" \
  --admin "$ADMIN_ID" \
  --require-reviewer "refs/heads/main:$REVIEWER_A" \
  --require-reviewer "refs/heads/main:$REVIEWER_B" \
  --require-reviewer "refs/heads/main:$REVIEWER_C" \
  --require-approvals "refs/heads/main:2"
```

The principal IDs identify eligible reviewers. They do not create principals or
grant repository access. Repeat `--require-approvals` for other configured
branches. A count for a branch that has no reviewer or check rule is rejected.

| Configuration | Effective requirement |
|---|---|
| Three reviewers, count omitted | All three independent reviewers |
| Three reviewers, count 3 | The same unanimous policy and identity |
| Three reviewers, count 2 | Any two independent exact approvals |
| Reviewers present, count 0 or greater than reviewer count | Invalid |
| Checks present, no reviewers, count omitted or 0 | All checks, no review requirement |
| Neither reviewers nor checks | Invalid branch rule |

A reviewer-bearing rule allows 1–32 eligible principals and a count from 1
through the number of reviewers. Existing administrator, branch and workflow
selector limits are unchanged. Empty policy branches still explicitly disable
branch protection while preserving policy administrators and history.

Only a currently authorized administrator can replace or lower a threshold.
Changing the count advances the policy epoch, just like replacing reviewers or
workflow-check requirements. Earlier approvals cannot satisfy the new epoch;
reviewers must approve the current policy and candidate again.

## Exactly what counts

At the selected authority head, each eligible reviewer's latest canonical
decision contributes at most one approval. That decision must be `Approve`
and bind all of the following exact coordinates:

- PR number and PR version.
- Source and target reference bytes and native commit IDs.
- Current policy epoch.
- Merge-base commit and the precise prepared candidate commit.

A review of a source tip alone cannot authorize an exact candidate. Approvals
for two different prepared commits cannot be combined, even when their trees
are identical. Native SHA-1 and SHA-256 identities remain in their own domains.

The PR opening actor and the person submitting the merge never contribute to
the count. Excluding them does not lower the threshold. For a 2-of-3 rule whose
reviewer set includes the PR opener, both remaining independent reviewers must
approve. If a configured set cannot supply enough independent reviewers, the
merge remains blocked.

`RequestChanges` and `Withdraw` supersede that reviewer's older approval and
contribute zero. **A change request is not an additional veto over a quorum
from other eligible reviewers.** Under 2-of-3, two current exact approvals and
one change request satisfy the review count. To require all reviewers, retain
the default unanimous policy. Discussion comments are separate events and
never approval votes.

A reviewer who has not voted contributes zero. A missing or corrupted body
selected by accepted history is an evidence failure, not a missing vote.
Admission authenticates every eligible configured frontier even after the
threshold is met. Cancellation cannot produce a partial successful quorum.

## Publication and retries

An insufficient non-unanimous quorum produces
`ProtectedRefTransitionDenied`. Default unanimous rules preserve the existing
named-reviewer refusal distinctions. Successful reviews do not import the
candidate's Git objects or move refs; the accepted native merge couples its
objects, ref effect, PR merge event and outbox obligation in the existing
publication path.

A concurrent review withdrawal, PR update, branch movement or policy change
replaces the authority head. A losing merge attempt evaluates the new basis
and its current votes before attempting publication again. A restarted node
reads the same canonical policy and review history.

Recorded terminal outcomes remain immutable. If a merge was refused because
only one of two required votes existed, adding the second vote does not change
that command's original outcome. Submit the intended new attempt with a new
idempotency key. Repeating the old key recovers the original refusal, including
after restart. A successful merge's exact retry recovers its original decision
without requiring the original candidate bundle to be supplied again.

The caller-selected `apply-reviewed` requirements remain additional unanimous
requirements. A repository quorum cannot waive a reviewer explicitly named in
that sealed request. Ordinary direct updates to a review-protected branch
remain denied. [Required workflow checks](REQUIRED_WORKFLOW_CHECK_PROTECTION.md)
remain mandatory alongside the approval count; no vote substitutes for a check.

## HTTP, MCP and browser clients

The protection HTTP form accepts repeated
`required_approvals=TARGET_REF_HEX:N` fields alongside the branch's existing
reviewer/check fields. Reference names retain their exact bytes. The MCP and
JavaScript protection inputs accept an optional numeric `required_approvals`
on each branch. Responses expose the effective numeric count, and browser
policy editors display and edit that count with the reviewer set.

Omission means the number of reviewers, or zero for a check-only branch.
Explicitly supplying that default normalizes to the same saved intent, HTTP
body and retry identity as omission. A genuinely smaller count is retained in
the normalized input and committed into the canonical policy.

## Canonical compatibility

Historical protection event kinds 9 and 13 retain their exact bytes and infer
unanimity when decoded. A policy with a genuinely non-unanimous rule uses new
required event kind 14. Every branch in that body carries an explicit
big-endian `u16` count and the existing check-count/selector fields, including
branches with no checks.

Kind 14 is rejected if it contains only unanimous rules, preventing a second
canonical spelling of an existing policy. Upgrade readers and writers before
activating a quorum: older readers correctly refuse the unfamiliar required
kind. The precise format and admission rules are in
[NORMATIVE_PROTOCOL_CONTRACTS.md §20.3](NORMATIVE_PROTOCOL_CONTRACTS.md#203-native-protected-review-quorums).

## Verification coverage

Codec tests freeze historical kind-9 and kind-13 frames, check mixed quorum,
unanimous and check-only policies, reject redundant/malformed counts and verify
administrator-controlled replacements. Reference-store admission tests cover
latest votes, every candidate coordinate, independence, evidence corruption
and cancellation after a quorum has already been counted.

The native-node integration tests use actual imported Git objects and the
file-backed authority store. They exercise a successful mandatory 2-of-3 merge
in both object formats, exact historical decisions across reopen, withdrawal
and recovery of quorum, author/submitter exclusion, replacement policy epochs,
and separate prepared candidates. These tests are distinct from the synthetic
reference-store fixtures.
