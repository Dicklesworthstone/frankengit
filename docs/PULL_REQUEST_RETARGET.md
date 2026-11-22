# Change an existing pull request's target branch

Retarget an open native PR to a release or integration branch while keeping its
PR number, original opener, conversation and labels. This is an explicit
metadata action. It does not rewrite source history or move any Git branch.

## CLI, HTTP, MCP and browser

Supply the current positive PR version, the unchanged source branch, a different
target branch, both explicit current tips, and the complete title/body:

```bash
fg pr retarget "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 7 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key 'pr-7-release-target' --expected-version 3 \
  --source-ref refs/heads/topic --expected-source "$SOURCE_COMMIT" \
  --target-ref refs/heads/release --expected-target "$RELEASE_COMMIT" \
  --title 'Review the topic branch' --body-file ./pr-body.md
```

`--source-ref-hex` and `--target-ref-hex` preserve non-UTF-8 branch bytes; the
usual mutually exclusive text/hex and body/body-file rules apply. SHA-1 and
SHA-256 use the same typed native command.

HTTP is `POST /REPOSITORY_ROUTE/api/v1/pulls/NUMBER/retarget`, with a PR-write
credential, original `Idempotency-Key` and the same complete form fields as
Open/Update. `pulls-read` alone cannot retarget. The browser's PR metadata form
includes **Change target branch**; prepare the complete request, review its
saved fields, then send it. The selected PR snapshot is refreshed explicitly.
The durable `scripts/remote_pull.mjs` client also accepts action `retarget` with
complete metadata and an exact positive `expected_version`.

MCP tool `frankengit_pull_retarget` uses the existing independent PR-write launch
grant. Its inputs match `frankengit_pull_update`, including both full reference
encodings, current tip OIDs, literal title/body and original durable key. Canonical
sponsored agents additionally need `pulls-write`; this grants no review, merge,
source-write or artifact permission.

## State and recovery

The source branch identity cannot change. An explicit refreshed source tip may
be supplied, but admission verifies it against current authority. The new target
must exist at the supplied tip. Missing old targets are allowed; current hidden-ref
policy still applies to the source, old target and new target. Retargeting to the
same branch, retargeting a closed/merged PR, stale versions, stale source/new-target
tips and implicit retargeting through Update/Reopen refuse.

A successful retarget advances the content version. All previous approvals stay
historical and become stale, including when the old and new target refs point to
the same commit. Prepare and review the new exact subject before merging. Existing
comments and their original source anchors remain intact; source anchors are not
silently moved to the new comparison. Queued entries bound to the old PR subject
also cannot authorize landing under the new one.

A reviewer can withdraw an old approval using its original subject and candidate
after retargeting. Notification replay verifies that exact prior reviewer event.
The inbox's activity prefix retains every historical target as a disclosure
coordinate: hiding an old target also hides that thread and denies preference
changes, even when its current source and target remain visible.

Retain the exact command and original key after a lost response. A retry resolves
that original canonical decision, even after another retarget, closure or node
restart. It never substitutes the latest version/tips, changes the actor, or
publishes another event. Deliberately changing the target again requires a new
key and the new exact PR version.

## Codec and verification scope

Retarget is required lifecycle action code 5, not an Update alias. Existing action
codes 1–4 and saved requests retain their bytes. Upgrade all readers before
publishing code 5; older readers correctly refuse the unknown required action.

Focused tests cover the native codec and transition matrix, real file-backed
metadata/outbox publication, conversation retention, current visibility on all
three relevant refs, cancellation, native exact-candidate approval invalidation,
original-key recovery after restart, CLI and MCP parsing/dispatch, sponsored
scope, the live HTTP route in both Git formats, browser recovery and the durable
remote client. These are bounded tests; they do not claim distributed or
process-kill conformance. Native compilation and test results are reported by
the integration verifier, not inferred from this document.
