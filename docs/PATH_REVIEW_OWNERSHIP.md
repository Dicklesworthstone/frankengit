# Required reviews for native repository paths

Repository administrators can require an independent reviewer quorum for changes
to an exact path or subtree. These rules use the existing canonical protection
policy and exact-candidate review events. They apply to native merge, squash,
fast-forward and validated queue landing. Every matching path rule is required
in addition to the branch's global reviewer quorum, workflow checks, queue
requirement and reference policy.

The contract is [normative §20.6](NORMATIVE_PROTOCOL_CONTRACTS.md#206-native-path-specific-required-reviews).
The node derives paths from the verified **current target tree to actual candidate
tree** on each admission attempt. Neither a caller's path list nor the PR's
source/merge-base diff can substitute for that evidence. This includes changes
introduced by a manually resolved candidate, even when they do not occur in the
source branch's diff.

## Select paths and reviewers

Each `path_reviews` rule has four fields:

| Field | Meaning |
| --- | --- |
| `path_hex` | Lowercase hex of the exact native Git path bytes. No Unicode normalization. |
| `scope` | `exact` for this entry; `subtree` for this entry and slash-separated descendants. |
| `required_reviewers` | Nonempty eligible principal IDs, at most 32. |
| `required_approvals` | Number of distinct eligible approvals required, from 1 through the reviewer count. |

For example, subtree `src` matches `src`, `src/lib.rs` and
`src/crypto/key.rs`; it does not match `src-old/lib.rs`. Exact `src/lib.rs`
matches changes, creation, deletion, executable-bit changes or replacement of
that entry. An exact directory rule matches structural directory creation,
deletion or replacement. It does not match a directory merely because a child
changed its tree object ID; use `subtree` for ownership of the directory's files.
Renames are accounted for as removal and addition of the native paths. Symlink
and gitlink mode/object changes are entries; the verifier does not follow their
targets. Removing or replacing a directory enumerates its affected descendants,
so an exact rule on a formerly nested file still applies.

Paths are nonempty and at most 4,096 bytes. NUL, empty slash components, `.` and
`..` components refuse. Non-UTF-8 bytes remain supported. There are no wildcard,
glob, precedence, last-match or CODEOWNERS-file import semantics. Every matching
rule applies independently. A reviewer may satisfy more than one overlapping
rule with the same valid exact-candidate approval.

Rules are unique by `(path bytes, scope)`, ordered by raw path bytes and then
`exact` before `subtree`. Repeating a selector with a different quorum is an
error. Limits are 32 rules per branch, 256 rules per repository policy and
64 KiB of combined selector bytes. The existing 64-branch limit remains.

## Configure through the trusted-local CLI

Read the actual policy version and epoch first:

```sh
fg protection show "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" --trusted-local

fg protection set "$STORAGE_ROOT" "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --principal "$ADMIN_ID" \
  --idempotency-key require-source-owners-1 \
  --expected-version "$POLICY_VERSION" --expected-epoch "$POLICY_EPOCH" \
  --admin "$ADMIN_ID" \
  --require-path-review "refs/heads/main:subtree:737263:2:$OWNER_A,$OWNER_B,$OWNER_C"
```

`737263` is the native byte spelling of `src`. Repeat `--require-path-review`
to add independently required rules. The CLI sorts selectors and reviewer IDs
before sealing; duplicate selectors or reviewers refuse. Add
`--object-format sha256` when needed.

**This replaces the complete policy.** Include all administrators, branch-wide
reviewers/counts, ordinary and candidate checks, queue requirements, other path
rules and optional DSL components that must remain. Omitted path rules are
removed. Existing administrators authorize the replacement. Installing or changing
rules advances the policy epoch, so earlier approvals cannot satisfy the new
policy. Retain the original complete command and idempotency key when recovering
an uncertain result; do not refresh its predecessor counters during a retry.

A branch may contain only path rules, with no global reviewers and zero global
required approvals. Changes outside those selectors still require the ordinary
validated native PR merge path but do not acquire a path-review requirement.
Direct source writes to that protected branch remain denied, including after a
reviewer approves a PR. Direct writes cannot stand in for the reviewed native
merge transition.

## HTTP, MCP and operator client

The existing HTTP protection endpoint accepts repeated form fields:

```text
required_path_review=TARGET_REF_HEX:exact|subtree:PATH_HEX:COUNT:REVIEWER_ID[,REVIEWER_ID...]
```

HTTP sorts the selector and reviewer sets, retains every native path byte, and
rejects duplicates. `GET /api/v1/protection` returns each branch's complete
`path_reviews` array, including an empty array. Existing protection-read/write
grants, administrator authorization and remote bootstrap refusal are unchanged.

`frankengit_protection_set` accepts the same JSON rule objects in each branch's
optional `path_reviews` array. MCP requires rules and reviewer IDs to be strictly
sorted and unique before sealing. `required_checks` must still be included,
even when empty. A path-only branch has `required_reviewers: []`,
`required_checks: []`, and zero or omitted global `required_approvals`.
`frankengit_protection_show` returns all path rules. Omitting the array in a
complete replacement removes it; an empty array preserves the historical
path-free policy's canonical identity.

Path-bearing MCP requests can use the existing 256 KiB protection envelope.
Only the bounded path hex strings and optional policy source/frame receive
the exception; unrelated arguments retain ordinary input/string limits. The
existing JSON depth, item and node limits remain. No transport truncates a rule
set to fit a limit. HTTP and CLI complete requests also remain bounded.

The Node operator protection client accepts these JSON rules, shows additions
and removals in its preview, and preserves them in the original saved intent,
form bytes and retry key. Changing source policy evidence or a replacement rule
invalidates a saved receipt instead of silently issuing a different request.

## Browser administration

The independent `/ui/protection/` page displays and edits all path rules. Its
complete path rule textarea takes one row per rule:

```text
BRANCH_HEX exact|subtree PATH_HEX COUNT REVIEWER_ID[,REVIEWER_ID...]
```

The protected branch must also appear in the branch-rule textarea. Use `-`
reviewers and `0` approvals there for path-only protection. Inspection populates
the current path rows; clearing the path textarea removes those requirements
from the proposed complete replacement. Removing or renaming a branch requires
explicitly removing or retargeting its path rows. The frozen preview lists path
rule additions and removals before submission.

The PR page's smaller protection panel displays and preserves existing path
rules while other fields are edited. Use the independent administration page,
CLI or API to change the rules themselves. Both browser surfaces share the
same original request/receipt identity and native authorization boundary.

## Enforcement and limits

Approvals bind the exact PR version, source and target refs/tips, merge base,
actual candidate commit and current policy epoch. The original PR opener and
merge submitter cannot contribute approvals. Every configured review frontier
is authenticated; selected missing/corrupt evidence or cancellation fails
closed. A request-changes or withdrawal event contributes no approval, using
the existing branch quorum semantics. Path rules do not invent a separate veto.

The verified structural delta is private typed evidence: only the native object
verifier constructs it, and admission compares all merge coordinates before
using it. Legacy low-level merge protection entry points without this evidence
refuse when path rules apply. Candidate closure, current target/source leases,
queue proof, current protection and canonical votes are still revalidated at
the exact publication basis on retries.

Path verification is bounded by the existing object/tree work limits and by
4,096 changed paths, 1 MiB of combined changed-path bytes, 4,096 bytes per path
and 64 path components. Exceeding a bound or failing to read complete verified
evidence returns unavailable; it does not skip an unmatched portion or publish
a partial candidate. This feature is not an unbounded tree scan or an index
used as authorization.

Path policies use required canonical event kind 26; all path-free historical
encodings remain unchanged. Upgrade every writer before activation. Older
readers refuse the unknown required kind. The existing trusted operator and
authority-store deployment boundaries still apply; this change does not make
arbitrary lower-level database writers safe.

Focused source coverage lives in `fgit-forge` path-review codec tests,
`fgit-admission/tests/native_merge_paths.rs`,
`fgit-node/tests/path_review_publication.rs`, the native HTTP protection tests,
CLI/MCP parser tests, and browser/operator protection path-review suites.
