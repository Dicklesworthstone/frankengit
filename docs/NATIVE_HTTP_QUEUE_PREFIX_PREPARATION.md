# Prepare an exact multi-PR queue prefix over HTTP

`POST {REPO_URL}/api/v1/queues/{number}/prepare-prefix` constructs an ordered
prefix of up to 16 current queue entries at one authenticated repository head.
The first PR merges onto the original target; later PRs merge onto the preceding
unpublished candidate. A complete clean result contains the actual native
commits, their projected parents and trees, and one downloadable bundle.

Preparation stages no objects, advances no refs, changes no PR or queue events,
and creates no transaction, review, check or synthetic ref. **Batch publication
is not supported by this profile.** Results have `publication_supported: false`
and no landing template. The existing [single-head preparation and landing
flow](NATIVE_HTTP_QUEUE_PREPARATION.md) remains separate.

## Authentication and bounds

Use the existing `--allow-pulls --allow-queues` switches and a single bearer
credential with **`read,pulls-read,queues-read`**. Separate credentials cannot
combine their grants. A token with no ref-write permission can prepare; queue
membership or landing permissions do not imply these reads. No new deployment
switch or scope is introduced.

Do not send an `Idempotency-Key`. Authentication, grants, deployment flags,
declared size limits, read quota and bounded body-work admission precede
`100 Continue`. Fixed-length and chunked form bodies are supported. The complete
encoded form is bounded to 256 KiB. One native preparation budget covers the
whole prefix; budgets do not reset for each PR.

## Exact original subjects

Content type is `application/x-www-form-urlencoded`, optionally with
`charset=utf-8`. The queue number is in the URL. Common fields are:

| Field | Required value |
|---|---|
| `expected_incarnation`, `object_format` | Exact current repository incarnation and `sha1` or `sha256`. |
| `expected_version`, `expected_policy_epoch` | Exact positive queue version and current policy epoch. |
| `target_ref` or `target_ref_hex` | Exactly one encoding of the original queue/PR target branch. |
| `expected_target_tip` | Original target commit, shared by every PR subject. |
| `entry_count` | Canonical decimal integer from 1 through 16. |
| `author`, `committer`, `timestamp` | Explicit native commit identities and positive timestamp; offset is `+0000`. |
| `message` or `message_hex` | Exactly one encoding of the nonempty message, at most 64 KiB decoded, without NUL. |
| `profile` | Optional `path-merge-v1` or `exact-renames-v1`; default is `path-merge-v1`. |
| `method` | Optional `merge-commit`, the only supported method. |

For each zero-based index `i`, supply all four coordinates below. For two PRs,
the suffixes are `_0` and `_1`.

| Indexed field | Meaning |
|---|---|
| `pull_request_i` | Positive original PR number at exactly this queue position. |
| `expected_pull_request_version_i` | Exact positive version of that open PR. |
| `source_ref_i` or `source_ref_hex_i` | Exactly one encoding of its source branch. |
| `expected_source_tip_i` | Its exact original source commit. |

References must be distinct source/target `refs/heads/...` names. Hex preserves
non-UTF-8 reference and message bytes; plain messages are UTF-8. Object IDs use
the repository's native width and lowercase hexadecimal spelling. Common commit
metadata applies to every step; it is content, not an actor or approval claim.

The submitted members must be the exact current queue prefix, in order. Queue
order/version, every open PR version and recorded subject, live source/target
tips, policy epoch and current visibility must agree at one authority basis.
An active batch, stale guard or reordered selection refuses. Unknown fields,
duplicates, missing indices, `_00` aliases, extra members and duplicate PR
numbers refuse. Stale coordinates are never silently refreshed.

Replace the variables below with actual observed coordinates. The private
header file contains the bearer authorization header. This saves the multipart
response, whose binary bundle must subsequently be extracted as MIME.

```sh
curl --fail-with-body --header @/secure/queue-preparation.headers \
  --data-urlencode "expected_incarnation=$INCARNATION" \
  --data-urlencode "object_format=$OBJECT_FORMAT" \
  --data-urlencode "expected_version=$QUEUE_VERSION" \
  --data-urlencode "expected_policy_epoch=$POLICY_EPOCH" \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode "expected_target_tip=$TARGET_TIP" \
  --data-urlencode 'entry_count=2' \
  --data-urlencode "pull_request_0=$FIRST_PR" \
  --data-urlencode "expected_pull_request_version_0=$FIRST_PR_VERSION" \
  --data-urlencode "source_ref_0=$FIRST_SOURCE_REF" \
  --data-urlencode "expected_source_tip_0=$FIRST_SOURCE_TIP" \
  --data-urlencode "pull_request_1=$SECOND_PR" \
  --data-urlencode "expected_pull_request_version_1=$SECOND_PR_VERSION" \
  --data-urlencode "source_ref_1=$SECOND_SOURCE_REF" \
  --data-urlencode "expected_source_tip_1=$SECOND_SOURCE_TIP" \
  --data-urlencode 'author=Developer <developer@example.invalid>' \
  --data-urlencode 'committer=Developer <developer@example.invalid>' \
  --data-urlencode 'timestamp=1700000000' \
  --data-urlencode 'message=Speculative queue prefix' \
  --dump-header prefix.headers --output prefix.body \
  "$REPO_URL/api/v1/queues/$QUEUE_NUMBER/prepare-prefix"
```

## Complete artifacts and projected coordinates

A clean result is HTTP 200 `multipart/mixed`, using the existing JSON `metadata`
and binary `bundle` parts. The latter is `application/x-git-bundle`, filename
`candidate.bundle`. The encoder uses exact content length, a collision-checked
boundary and no-store headers, and avoids a second combined bundle-sized
response allocation. The shared limits are 64 MiB of bundle and 2 MiB of
metadata, narrowed by the operator's response limit.

Metadata type is `queue_prefix_preparation`, schema version 1:

| Field | Interpretation |
|---|---|
| Repository fields, `source_head`, `snapshot_token` | Exact authenticated source coordinates. |
| `queue`, `entry_count`, `profile`, `method` | Queue/version and construction profile. |
| `original_subjects` | Indexed original PR numbers, versions, policy, refs and tips. Every target remains the original canonical target. |
| `projected_steps` | Indexed `source_tip`, `projected_target_tip`, `merge_base`, `commit` and `tree`. |
| `candidate` | Final commit, tree and deduplicated new-object count. |
| `bundle` | Byte length and SHA-256 transport checksum. |
| `preparation_id` | Digest binding repository/incarnation, authority head, ordered original subjects, explicit metadata, profile, projected results and artifact digest. |
| `state`, `stop` | `clean` and `null` for a complete result. |

Each candidate has two ordered parents: projected target first, that step's
source second. The bundle advertises the final commit at the original target
ref, lists original target/source histories as prerequisites, and contains the
generated objects needed by the complete prefix.

Original subjects and projected parents remain separate. An ordinary approval
of the second PR against the original target does not approve a different
candidate whose first parent is the first projected merge. This profile supplies
construction and inspection data, without a batch evidence or landing protocol.
Its preparation digest is not an idempotency key or publication credential.

## Stopped and stale preparations

If any entry conflicts or is already integrated into the projected prefix, the
whole request returns HTTP 409 JSON with `state: "stopped"`, `candidate: null`,
`bundle: null` and `preparation_id: null`. Earlier completed steps remain
diagnostic `projected_steps`; no shortened successful bundle returns.

`stop` identifies the zero-based index, PR number, source and projected target,
and reason `conflicted` or `already_integrated`. Conflicts include the merge
base and bounded exact-byte `path_hex`, kind and base/ours/theirs entries.
Already-integrated diagnostics have no conflict entries or merge base. Changing
the requested prefix requires an explicit new read with complete guards.

Stale queue/PR/tip/policy coordinates return 409 `preparation_subject_moved`;
missing or hidden subjects return 404. Native graph and rename refusals keep
their explicit error codes. Syntax, authorization, resource, timeout and
infrastructure errors retain the read-only error envelope with
`outcome_unknown: false`. No response creates a canonical landing refusal.
