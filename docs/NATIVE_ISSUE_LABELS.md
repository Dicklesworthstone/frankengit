# Add issue labels without replacing concurrent work

Use `add-labels` when a person or agent needs to add labels while other writers
may be updating the issue. Admission combines the requested set with current
labels and preserves the title, body, state, discussion lock, assignments,
milestone and comments. It selects the issue version at publication time.

```sh
fg issue add-labels "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" 17 \
  --trusted-local --principal "$PRINCIPAL_ID" \
  --idempotency-key issue-17-triage-1 \
  --label bug --label transport
```

This command rejects `--expected-version`. Supply 1–32 distinct labels, each
nonblank and at most 64 UTF-8 bytes, without control characters. Input order
is canonicalized; duplicate labels refuse. SHA-256 repositories require the
existing `--object-format sha256` option.

The complete resulting issue can hold at most 32 labels. Existing labels do
not consume another slot when named again. An addition that would exceed the
limit records a `ResourceBudgetExceeded` refusal without partially changing
the issue. Additions work on closed and locked issues. They do not confer any
permission or make issue metadata authoritative for Git changes.

## Concurrent changes and exact replacements

If two writers add `bug` and `transport`, both can commit and the issue retains
both labels. Their requests keep their original identities while admission
revalidates the current state after a race. Other concurrent edits remain
intact. At the cardinality limit, admission orders the competing additions
and refuses any request whose complete union does not fit.

`fg issue edit --expected-version V --label ...` continues to replace the
whole label set; `--clear-labels` continues to clear it. A stale replacement
refuses. Choose replacement explicitly when removal is intended. Addition
does not turn replacement or removal into a commutative operation.

## HTTP and recovery

`POST {REPO_URL}/api/v1/issues/{number}/add-labels` accepts the ordinary
URL-encoded issue form with repeated `label` fields, the original
`Idempotency-Key`, and the authenticated bearer credential. It uses the
existing issue-write deployment setting and token grant. It rejects
`expected_version`, empty sets, duplicate fields other than repeated labels,
and inapplicable command or authority fields. No new permission is implied.

Terminal receipts identify `action: "add-labels"`, `expected_version: null`
and `command_profile: "issue.add-labels.v1"`. Native CLI receipts identify
the same profile and the action under `action.name`. Issue history contains
the exact versioned `add-labels` delta, not a guessed replacement set.

Retain the identical issue, principal, set and key after an interrupted request.
A retry returns its original terminal outcome even after restart. If someone
later removes one of those labels, retrying the old addition does **not** add it
back. The same rule preserves a recorded capacity refusal after space is freed.
A new addition or a changed request needs a new key. Outcome lookup with the
original principal and key does not re-execute the mutation.

The node API is `OneNode::admit_issue_labels_durable_in` with
`IssueLabelsIntent`. HTTP/CLI reads, search and notifications derive labels
from the same canonical event stream. No secondary issue store is introduced.

## Browser, MCP, and remote operator

The issue browser offers **Add labels** beside **Edit issue**. It starts with an
empty addition set, disables the expected-version field, and preserves existing
labels. Preparing a change sends nothing. After an uncertain response, retain
the saved receipt and recover or retry its original request.

MCP exposes `frankengit_issue_add_labels` through the existing issue-write grant.
Supply `number`, a `labels` array, and the original `idempotency_key`; the tool
rejects `expected_version` and caller-supplied identity or authority fields.
Its terminal receipt uses the same profile as HTTP and native CLI admission.

The remote operator accepts the same operation:

```sh
node scripts/forge_issues.mjs add-labels \
  --url https://HOST/REPOSITORY_ROUTE/ui/issues/ \
  --tenant-id "$TENANT_ID" --repository-id "$REPOSITORY_ID" \
  --token-file ./private-token --record ./private-records/issue-17-labels.json \
  --number 17 --label bug --label transport
```

Use a new private record path for a new request. The operator verifies the
repository and issue, synchronizes the exact token-free recovery record before
sending, and supports the existing `status` and `retry` commands with that
original record. Issue archives replay additive label deltas in both archive
versions, including across pagination and later strict replacement or clearing.

## Compatibility and validation

This extends the required native issue-action vocabulary. Old action encodings,
strict edit requests, and their retry identities remain unchanged. Readers
predating action tag 12 refuse histories containing it; upgrade readers and
writers together before using the new operation. The authoritative encoding,
identity and replanning rules are
[normative §20.2.6](NORMATIVE_PROTOCOL_CONTRACTS.md#2026-native-issue-label-addition-intents).

Focused coverage lives in the forge label reducer/codec tests, admission
proposal and seal tests, the `native_merge_delivery_faults` label race module,
node issue-label tests, and the native `issue_http` integration target. They
cover both native hash formats, capacity and missing-issue refusal twins,
concurrent unions, stale strict replacements, exact original-outcome recovery,
and interruption. The product campaign is
`scripts/e2e/suites/node/issue_labels.sh`, using an explicitly supplied `FG_BIN`.
These are validation entrypoints, not claims about an unexecuted revision.
