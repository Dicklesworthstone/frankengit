# Automatic CI for exact native PR merge candidates

`fg workflow watch` can prepare a native PR's actual merge or squash commit,
publish it on an explicitly selected CI branch, and execute that exact combined
tree. Optional canonical check publication makes those results usable by the
existing [required-check protection](REQUIRED_WORKFLOW_CHECK_PROTECTION.md).
The operator supplies the publication identity, branch and deterministic commit
metadata. Neither PR branch is changed by the watcher.

This is the same Linux trusted-host execution profile as ordinary native CI.
Trust every future selected script with the host account's privileges. It is
not a sandbox for untrusted contributors, a GitHub event adapter or an automatic
PR merge service.

## Select a fixed CI branch and explicit identity

```sh
fg --timeout-secs 300 workflow watch NODE TENANT REPOSITORY refs/heads/topic \
  --trusted-local --pull-request 7 --expected-incarnation INCARNATION \
  --workflow ci --input ci --input src --run-parent /private/merge-runs \
  --merge-candidate-ref refs/heads/ci-main --merge-principal CI_WRITER \
  --merge-author 'CI <ci@example.test>' \
  --merge-committer 'CI <ci@example.test>' \
  --merge-timestamp 1700000000 --merge-message 'Test the exact candidate' \
  --merge-method merge-commit --merge-profile path \
  --publish-checks --principal-id CHECK_PUBLISHER \
  --polls 100 --interval-ms 1000
```

Replace the repository, principal and incarnation placeholders with their exact
identifiers. Use `--object-format sha256` for a SHA-256 repository. The existing
continuous lifetime, stop-file, signal drain, finite attempts and artifact flags
also apply; see [native workflow watch](NATIVE_REF_WORKFLOW_WATCH.md).

The entire merge option group requires `--pull-request` and
`--expected-incarnation`. Author, committer, positive Unix timestamp, message,
publication principal and CI branch are mandatory. There is no ambient Git
identity or current-time default. `--merge-method` defaults to `merge-commit`
and also accepts `squash`; `--merge-profile` defaults to `path` and also accepts
`exact-renames`. These are the existing bounded native preparation algorithms.
Use `--merge-candidate-ref-hex` instead of the text ref option for raw branch
bytes. The branch must differ from both source and target PR refs.

The CI writer and check publisher are independently selected principals. Running
the candidate does not publish a check unless both `--publish-checks` and
`--principal-id` are present. These options neither install protection nor grant
a publisher permission to satisfy a policy that does not already trust it.

Choose a fixed CI branch that matches the policy's `source_ref` selector. The
watcher may create or replace that branch through ordinary sealed admission,
using its original exact-old tip. Ref protection and repository policy still
apply to this publication. A separate branch per event would not match a static
required-check selector. If several controllers share a CI branch, coordinate
their ownership: moving it makes older checks inapplicable to protected merges.

## Prepare, admit, execute and report one candidate

1. Read the open native same-repository PR and its current source/target tips
   at one canonical authority head. The watched source must match that PR.
2. Require the PR's recorded tips to equal those current tips. Stale metadata
   returns `pull_request_stale` before reservation. Explicitly update the native
   PR metadata before selecting the new review subject; CI never changes it.
3. Prepare the actual merge/squash tree and commit using the supplied metadata.
   A conflict returns `merge_conflicted`; an already-up-to-date subject yields
   `merge_up_to_date`. None of these states executes a script or creates a CI ref.
4. Persist the exact candidate bundle, original CI tip, publication identity and
   event coordinates before admitting the CI ref. Admission requires the same
   prepared authority head, then keeps that original basis across CAS retries.
5. Revalidate the original PR subject after publication and execute the admitted
   CI commit through the ordinary canonical workflow dispatcher. A later source,
   target, visibility or policy change cannot silently substitute another input.
6. If requested, publish retained job evidence under the CI branch and the actual
   candidate commit through the existing canonical check admission path.

Definitions and copied files come from the combined candidate tree. Only
`pull_request` definitions are selected. Branch filters still match the original
PR target branch, and path filters still inspect the incoming source changes
against their merge base. They do not match the CI branch or count unrelated
target-only changes as incoming changes.

The event receipt records the candidate commit, tree, base, ordered parents,
method, profile, original expected-old CI tip, publication principal/key, bundle
digest and exact metadata. Run provenance correctly records a canonical admitted
commit. The retained `candidate.bundle` advertises the CI ref; its commit and pack
remain the prepared candidate. Review or prepare a target-branch publication with
the same metadata to retain that exact commit identity.

## Exact checks gate the later protected merge

An administrator can require `refs/heads/ci-main`, the selected publisher, the
actual workflow graph commitment and job on the protected target branch. A
source-head success cannot satisfy the requirement for a different merge commit.
The CI branch must still point to that exact proposed commit when the protected
merge is admitted. Existing reviewer requirements remain in force alongside CI.

Use identical source/target tips, parent style, profile, author, committer,
timestamp and message when preparing the later protected merge. Changing any
commit input can select a different commit that needs its own passing checks.
The watcher supplies CI; the operator still submits the protected PR merge.

A refused merge keeps its terminal refusal under its original key even after a
new successful check. Resolve that refusal, then use a deliberate new key for a
new merge command. Reusing the old key cannot convert it into success.

`fg pr checks` continues to select the PR's recorded source-head coordinates.
Candidate checks belong to the CI branch/candidate and are not relabeled as
source-head results. Use the watch's canonical publication receipts and retained
candidate evidence for these results. A dedicated candidate-check PR view is
outside this slice.

## Restart and refusal behavior

Retain the entire private run parent, including bundles, publication receipts,
execution journals and check handoffs. Merge-candidate watches have a separate
custody namespace from ordinary source-head and push watches. Within that scope,
the merge configuration is permanently bound; changing it refuses instead of
escaping an unresolved event under a fresh identity.

Settled events do not rerun scripts on restart. Check publication can be enabled
later to report original settled executions without repeating them. Existing
publisher binding, stable check keys and terminal-decision recovery still apply.
Closing a PR stops new execution but does not erase original reporting custody.

Any failure after event reservation retains the original bundle, key and old-tip
lease and blocks later work until reconciled. The watcher does not refresh a
refused lease, invent replacement keys or replay scripts after ambiguous effects.
This includes malformed definitions found after candidate publication: the CI ref
may already have been admitted even though no script ran. Inspect the original
candidate-publication receipt and retained event before taking further action.

Conflict and stale-metadata observations are non-green: a foreground watch exits
1 even though no dispatch ran. Infrastructure/output errors retain their existing
exit-2 behavior. A clean idle or up-to-date poll is not proof of passing CI. The
existing 1024-event custody bound and latest-state coalescing remain unchanged.

## Focused verification entrypoints

```sh
cargo test --locked -p fgit-node --test trusted_pull_request_merge_watch -- --test-threads=1
cargo test --locked -p fgit-cli --bin fg workflow_merge_watch
cargo test --locked -p fgit-cli --bin fg workflow_command::watch
FG_BIN=/absolute/path/to/fg scripts/e2e/suites/workflow/pull_request_merge_watch.sh
```

The test definitions cover SHA-1 and SHA-256, both parent styles, actual combined
content, PR branch/path filtering, unchanged PR refs, canonical checks, restart
without script replay, conflicts, stale metadata, configuration changes and
retained failed-publication custody. The E2E campaign uses the real compiled
`FG_BIN`, independent native object/commit identities and protected-merge
refusal followed by acceptance after exact-candidate check publication. It is a
functional campaign, not a pinned upstream-Git differential lane or a release
verification claim. These entrypoints are not a statement that an untested
revision has passed them.
