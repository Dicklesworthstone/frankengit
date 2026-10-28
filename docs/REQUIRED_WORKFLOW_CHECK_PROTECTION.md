# Required workflow checks for exact protected candidates

Canonical protection can require verified workflow results from publishers
chosen explicitly by the current repository administrators. The requirements
apply in the native admission paths that publish protected refs and PR merges.
They use the same durable policy, predecessor version, policy epoch and
authority-head CAS as mandatory review protection.

## Authority and subject

Each protected branch has a sorted `required_checks` list. Every selector binds:

| Field | Meaning |
|---|---|
| `source_ref` / `source_ref_hex` | Exact canonical `refs/heads/*` branch on which the candidate was executed. Raw reference bytes remain exact. |
| `publisher` | Exact authenticated reporting principal trusted by the policy administrators. |
| `graph_root` | Full 32-byte workflow graph commitment. |
| `job` | Exact UTF-8 job name, with no normalization or wildcard matching. |

All configured checks must pass. Defaults are empty, and publishing a check
never installs a requirement or enrolls its reporting principal. Policy
replacement is still authorized by the old canonical administrator set. An
administrator chooses the publisher's authority deliberately; a principal cannot
grant itself that authority by submitting a successful observation.

The native publisher verifies a completed job against its retained original
execution evidence before publishing canonical `Success`. Custody records retain
their original proposals: a succeeded local job can still have an
`action_required` custody report while its verified canonical result is
`success`. Admission reads canonical history, so custody proposals, PR display
rows and caller-supplied summaries cannot satisfy protection. See
[trusted workflow publication](TRUSTED_WORKFLOW_CHECK_PUBLICATION.md).

This is a trusted-host publisher profile. It provides no independent runner
attestation, remote identity enrollment, signed third-party execution proof or
generic expiring status receipt. The configured publisher remains responsible
for the host and execution inputs within the existing trusted workflow boundary.
Upgrade every reader and writer before activating check-bearing policy; old
required-kind readers will refuse the new policy encoding.

## Exact candidate and latest result

At each authenticated admission basis, the configured source branch must still
name the exact proposed **new commit** of the protected ref. A canonical
observation must match that source branch, native commit ID, publisher, graph
and job. SHA-1 and SHA-256 commit domains remain distinct.

For a fast-forward merge the candidate is the PR source commit. A configured
PR source branch can therefore be used directly if it still names that commit.
For a two-parent merge or squash, the candidate is the newly prepared merge
commit. Passing checks on a different source-tip commit cannot authorize it.
Publish the prepared candidate on a separate ordinary CI branch, execute the
workflow there and publish the retained result before submitting the merge.
The protection policy itself does not schedule CI or create that branch.
An operator can automate those steps with
[exact PR merge-candidate watch](NATIVE_PULL_REQUEST_MERGE_WORKFLOW_WATCH.md),
using a fixed CI ref, explicit publication identity and deterministic metadata.
The watcher uses these existing exact-candidate rules without relaxing them.

Admission scans canonical history backwards and selects the latest matching
publication for each requirement. It requires `Success`. A later matching
`Failure`, `Cancelled`, `TimedOut` or `ActionRequired` supersedes an earlier
success. A subsequent successful rerun can satisfy the requirement again.
Another publisher's result cannot supersede the selected publisher's result.
The order is canonical publication order, not an untrusted wall clock or a
lexicographic run ID.

Source movement or deletion invalidates applicability even if an older result
was successful. The ref snapshot, selected policy and scanned history all come
from the same authenticated basis. Every CAS retry rechecks them. A concurrent
check publication, source movement or policy change replaces the authority head
and forces a losing writer to evaluate again. An atomic direct update also
cannot move or delete a configured CI source away from the checked candidate
within the same accepted ref transaction.

Already committed or refused commands retain their original terminal outcomes
under the original idempotency key. A new successful check does not turn a
previously refused command into an accepted retry; submit a deliberate new
command with a new key after resolving the refusal.

## Configure through existing production surfaces

`fg protection set` replaces the complete policy. A check-only requirement for
`refs/heads/main` can be installed or replaced with the actual predecessor:

```sh
fg protection set "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ADMIN_ID" \
  --idempotency-key require-main-build-1 \
  --expected-version "$POLICY_VERSION" --expected-epoch "$POLICY_EPOCH" \
  --admin "$ADMIN_ID" \
  --require-check "refs/heads/main:refs/heads/ci-main:$PUBLISHER_ID:$GRAPH_ROOT:build"
```

`GRAPH_ROOT` is the exact lowercase 64-character graph commitment from the
intended workflow run. The five components are target ref, source ref, publisher,
graph root and job. Splitting stops before the job, so colons in a UTF-8 job name
remain part of that name. Repeat the option for multiple requirements. Preserve
all existing administrators, reviewers and check selectors intended to remain
in the replacement. `--clear` explicitly disables all branch requirements while
retaining administrators, and is exclusive with review and check entries.

To require both reviews and CI, also retain the branch's `--require-reviewer`
options. The default requires every configured independent reviewer; an explicit
`--require-approvals TARGET_REF:N` requires N approvals from that branch's
eligible reviewers. See [review quorums](REVIEW_QUORUM_PROTECTION.md) for exact
candidate binding, latest-vote behavior and unchanged default identities.
All configured workflow checks remain mandatory alongside that review count.
Checks cannot count as approvals or satisfy reviewer independence.
A branch with reviewers still refuses ordinary direct ref updates. A branch
protected only by checks permits a direct `Set` after all checks pass, including
creation of a previously unborn protected branch. Deletion is always refused
while that branch remains protected.

The [HTTP protection API](HTTP_PROTECTION_API.md) accepts repeated
`required_check=TARGET_REF_HEX:SOURCE_REF_HEX:PUBLISHER:GRAPH_HEX:JOB_UTF8_HEX`
fields alongside reviewer requirements. Encoding the job as UTF-8 hex preserves
colons, Unicode and form metacharacters exactly. The current authenticated
administrator and explicit gateway grants still authorize the replacement.

The [MCP administrator profile](MCP_REVIEW_PROTECTION.md) uses structured
`required_checks` arrays. Every branch must include the array explicitly, even
when empty, so an older client cannot silently discard configured checks while
editing a complete policy. Each element contains `source_ref_hex`, `publisher`,
`graph_root` and `job`. Policy reads return all selectors.

The PR page's protection panel can add, edit and remove required workflow
checks directly. Each branch rule has structured fields for the exact CI source
reference hex, publisher, graph commitment and job name. Leave its reviewer list
empty to create a check-only rule, or combine checks with a reviewer quorum.
The complete-policy preview enumerates check additions and removals before an
explicit freeze and submission. Editing a protected target carries that row's
checks to the renamed target while retaining their exact CI source identity.
Removing the branch rule intentionally removes all of its requirements.

The standalone protection editor still preserves existing selectors when
editing reviewer rows and uses `-` for the reviewer column of a check-only
branch. The CLI, HTTP/MCP APIs and complete JSON policy file accepted by the
[remote operator](REMOTE_REVIEW_PROTECTION.md) also support selector changes.

An empty check list retains the historical review-only representation. Removing
the last check from a branch with no reviewers is refused; explicitly remove
the branch rule to remove its protection. Both clients use the native selector
bounds without truncation or normalization of job text. The PR panel freezes
all selector controls with the original request; uncertain retries retain the
original body and idempotency key.

## Canonical encoding and bounds

`RequiredWorkflowCheck` is defined in
`crates/fgit-forge/src/event/protection.rs`. The per-branch limit is 32 checks,
alongside the existing limits of 32 reviewers and 64 branches. A protected
branch must have at least one reviewer or check. Source refs retain the native
1,024-byte branch bound. A job must be nonempty, at most 1,024 UTF-8 bytes and
contain no Unicode control characters. Selectors are strictly sorted and unique
by source-reference bytes, publisher bytes, graph bytes and UTF-8 job bytes.

Historical review-only policy encoding stays byte-for-byte unchanged at event
tag 9. Policies containing any checks use required event tag 13, which includes
a check vector for every branch. Tag 13 without any checks is refused as a
noncanonical spelling. Both forms use the same protection aggregate and
transaction command. Every selector field participates in immutable event
bytes and transaction identity. Clearing all checks restores the original
review-only encoding when the remaining policy is otherwise identical.

The browser and operator normalizers omit empty check properties from their
legacy saved-intent representation. Existing review-only intent digests,
request bodies and retry keys therefore remain valid. Nonempty check selectors
are fully committed to new intents; changing a selector cannot reuse an old
command identity.

The admission scan is bounded to 4,096 authenticated history steps, 65,536
event batches, 65,536 events and 128 MiB of aggregate frame bytes. Empty event
batches consume the batch budget too. Missing or corrupt required history,
exhausted scan budgets and cancellation produce unavailable errors, not an
implicit allow or a fabricated policy refusal. A complete scan proving that a
required result is absent or nonpassing produces the existing canonical
`ProtectedRefTransitionDenied` refusal. A long-lived deployment whose retained
history exceeds this bounded profile needs an explicitly retained newer result
or future authenticated indexing; an unchecked cache cannot grant permission.

## Verification entrypoints

```sh
cargo test --locked -p fgit-forge event::protection
cargo test --locked -p fgit-node --lib configured_checks_bind_exact_candidates_and_latest_publisher_results_on_every_path -- --test-threads=1
cargo test --locked -p fgit-cli --bin fg protection::tests
cargo test --locked -p fgit-cli --bin fg mcp::backend::protection
cargo test --locked -p fgit-node --lib smart_http::server::protection
node --test tests/browser/protection.test.mjs tests/browser/protection-standalone.test.mjs tests/operator/review_protection.test.mjs
```

The new native test definitions exercise actual retained workflow execution
and publication with persisted authority in both Git hash formats, each with
a fast-forward and a two-parent candidate. They cover missing results, every
selector mismatch, source-only success, later real execution failure, a successful
rerun, an untrusted publisher's later failure, stale policy replacement, current
CI-ref deletion, direct creation, protected deletion, terminal retries,
cancellation and reopen. Schema tests cover old tag-9 bytes, required tag 13,
truncation, canonical ordering, identity material and administrator authority.

The focused Node.js lanes completed 102 tests: 58 browser-client tests, 22
standalone-page tests and 22 operator tests, including real loopback HTTP reads.
These cover the new selectors and compatibility with existing review-only
receipts and intents. The pinned nightly parsed the final Rust changes, but the
broader native check stopped in the `asupersync` dependency after shared memory
exhaustion on an earlier attempt and filesystem exhaustion on a later attempt.
Native gate execution remains pending. Adapter tests and source/API review do
not establish a full Rust build or native admission-test pass.
