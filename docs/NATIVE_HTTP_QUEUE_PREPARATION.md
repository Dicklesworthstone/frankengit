# Prepare an exact queue-head candidate over HTTP

`POST {REPO_URL}/api/v1/queues/{number}/prepare` constructs a two-parent native
merge candidate for the exact first PR in a queue. Queue order/version, the open
PR and its version, both branches/tips, and policy epoch must agree at one
authenticated authority head. This adds queue-aware selection to the existing
HTTP candidate preparation and binary bundle transport.

Preparation is a read-only operation with a request body. It stages no objects,
creates no transaction or idempotency binding, publishes no check or review,
and changes neither refs nor queue/PR metadata. The downloaded artifact can be
inspected and reviewed through the existing PR APIs. Actual publication uses
the separately authorized queue `land-candidate` endpoint and its native guards.

## Enable the endpoint and authorize reads

Enable the existing PR and queue services:

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-pulls --allow-queues
```

The same bearer credential must grant **`read,pulls-read,queues-read`**. Code
fetch, PR disclosure and queue disclosure are independent permissions; separate
tokens for the same principal do not combine their grants. Neither membership
writes nor queue landing, reviews, ordinary PR merging or Git receive grants
these reads. A credential whose ref-write ceiling is `none` can prepare.

No additional service flag or credential scope is introduced. Preparation does
not require `--allow-receive`, `--allow-source` or `--allow-queue-landings`.
Credential rotation, revocation, incarnation binding and current hidden-ref
rules retain their existing behavior. Queue routes require bearer authorization.

Do not send an `Idempotency-Key`. Preparation rejects it because no transaction
is created. Authentication, all three grants, deployment switches, declared
input limits, read quota and bounded body-work admission precede `100 Continue`
and body processing. Errors have type `merge_queue_error` and
`outcome_unknown: false`; a failed read is not a canonical landing refusal.

## Supply every original coordinate

Use `application/x-www-form-urlencoded`, optionally with `charset=utf-8`.
Fixed-length and chunked framing are supported. The complete encoded form is
bounded to 256 KiB. Unknown fields, duplicate scalar fields, query parameters,
malformed encodings and noncanonical integer/object-ID spellings are refused.

The queue number comes from the URL. The required form fields are:

| Field | Meaning |
|---|---|
| `expected_incarnation` | Current repository incarnation, lowercase hexadecimal. |
| `object_format` | `sha1` or `sha256`, matching the repository. |
| `expected_version` | Exact positive queue version, with room for the two landing events. |
| `pull_request` | Exact positive PR number at the queue head. |
| `expected_pull_request_version` | Exact positive open-PR version, with room for its merge event. |
| `expected_policy_epoch` | Exact positive current policy epoch. |
| `source_ref` or `source_ref_hex` | Exactly one encoding of the PR's source branch. |
| `target_ref` or `target_ref_hex` | Exactly one encoding of the queue/PR target branch. |
| `expected_source_tip`, `expected_target_tip` | Exact nonzero lowercase native commit IDs. |
| `author`, `committer` | Explicit Git identities in `Name <address>` form. |
| `timestamp` | Explicit positive Git timestamp; the candidate uses offset `+0000`. |
| `message` or `message_hex` | Exactly one encoding of the nonempty commit-message bytes. |

Hex references preserve exact non-UTF-8 branch names; text and hex cannot both
name the same field. Source and target must be distinct full `refs/heads/...`
branches. `message` supplies UTF-8 text; lowercase `message_hex` preserves exact
bytes, including non-UTF-8 content. Decoded messages are bounded to 64 KiB and
cannot contain NUL. Author/committer metadata is commit content and never an
authenticated principal or authorization claim.

Optional `profile` is `path-merge-v1` (the default) or `exact-renames-v1`.
Optional `method` can only be `merge-commit`, also the default. Squash,
fast-forward, automatic conflict resolution and arbitrary parent shapes are
not queue preparation methods. The ordered parents are target then source.

Obtain the queue and PR coordinates through their independent read APIs. The
PR reviews read API exposes the current policy epoch under its own
`reviews-read` permission, or the operator can provide that coordinate.
Preparation validates the complete supplied subject again; separately observed
coordinates do not authorize silently refreshing a stale queue or PR.

Replace the uppercase variables below with the actual repository URL and exact
observed coordinates. `/secure/queue-preparation.headers` is a private file
containing the bearer authorization header.

```sh
curl --fail-with-body --header @/secure/queue-preparation.headers \
  --data-urlencode "expected_incarnation=$INCARNATION" \
  --data-urlencode "object_format=$OBJECT_FORMAT" \
  --data-urlencode "expected_version=$QUEUE_VERSION" \
  --data-urlencode "pull_request=$PR_NUMBER" \
  --data-urlencode "expected_pull_request_version=$PR_VERSION" \
  --data-urlencode "expected_policy_epoch=$POLICY_EPOCH" \
  --data-urlencode 'source_ref=refs/heads/topic' \
  --data-urlencode 'target_ref=refs/heads/main' \
  --data-urlencode "expected_source_tip=$SOURCE_TIP" \
  --data-urlencode "expected_target_tip=$TARGET_TIP" \
  --data-urlencode 'author=Developer <developer@example.invalid>' \
  --data-urlencode 'committer=Developer <developer@example.invalid>' \
  --data-urlencode 'timestamp=1700000000' \
  --data-urlencode 'message=Queue-head candidate' \
  --dump-header candidate.headers --output candidate.body \
  "$REPO_URL/api/v1/queues/$QUEUE_NUMBER/prepare"
```

## Read the result and preserve its guards

A clean result is HTTP 200 `multipart/mixed`: JSON part `metadata`, followed
by binary part `bundle` with media type `application/x-git-bundle`. The response
uses the existing bounded encoder, exact content length, collision-checked
boundary, no-store headers and separate writes of metadata/bundle/framing. It
does not copy the bundle into a second combined response allocation. The
shared envelope allows at most 64 MiB of bundle bytes and 2 MiB of metadata,
further narrowed by the operator's response limit.

Metadata has type `queue_merge_preparation`, schema version 1, the exact
`source_head` and `snapshot_token`, repository/incarnation/object format,
`profile`, `method`, the complete PR `subject`, and
`queue: {"number": ..., "expected_version": ...}`. The candidate includes its
merge base, commit, tree and new-object count. The bundle descriptor includes
its byte count and SHA-256 transport checksum. The native bundle advertises
the candidate at the target branch and retains its history prerequisites.

Clean queue metadata also contains:

| Field | Use |
|---|---|
| `landing.api_path` | `/api/v1/queues/{number}/land-candidate`, relative to the configured repository route. |
| `landing.command_form` | Complete URL-encoded landing coordinates, including the original queue/PR/policy guards, actual incarnation, both refs as hex, tips, merge base and candidate commit. |

Parse the multipart response as MIME and retain the exact binary bundle.
Preserve `landing.command_form` unchanged alongside it. Generic PR inspection
or review does not replace the original queue version or authorize a different
queue head. Changing deterministic metadata creates a different candidate that
requires its own exact review/check evidence.

All result states carry `read_only: true`, `objects_staged: false`,
`transaction_created: false`, `published: false` and `merge_authorized: false`.
Conflicts return HTTP 409 JSON with bounded diagnostics and no candidate or
bundle. An already integrated source returns HTTP 200 JSON with
`state: "already_up_to_date"` and no candidate or bundle. Both have
`landing: null` and create no canonical decision.

A reordered/changed/empty queue, a non-head PR, active batch, changed PR/tip or
policy coordinate returns 409 `preparation_subject_moved`. Missing or hidden
subjects return 404. Authentication is 401, disabled services or missing grants
403, invalid syntax 400, unsupported media 415, resource bounds 413, throttling
429, and unavailable infrastructure 503. No common ancestor and multiple merge
bases retain their explicit preparation errors. No stale input is refreshed.

## Inspect, review, then land independently

Use the downloaded candidate with the existing
[candidate inspection](HTTP_CANDIDATE_INSPECTION_API.md) and review endpoints.
They retain their own permissions. Preparation provides no successful check
and does not bypass required approvals or queue protection.

When separately authorized to land, write the exact returned
`landing.command_form` into `landing.form`, save the binary part as
`candidate.bundle`, and use the returned API path. Choose a separate original
landing key; it is intentionally absent from the preparation response:

```sh
curl --fail-with-body --header @/secure/queue-landing.headers \
  -H "Idempotency-Key: $LANDING_KEY" \
  -F 'command=<landing.form;type=application/x-www-form-urlencoded' \
  -F 'bundle=@candidate.bundle;type=application/x-git-bundle' \
  "$REPO_URL$LANDING_API_PATH"
```

Landing requires `--allow-queue-landings`, `queues-land`, a target-ref write
ceiling and the current native protection/evidence checks. If its response is
lost, retain that original key and exact command; absence of a response does
not establish rollback. Known-terminal recovery may omit the bundle under the
existing [queue landing contract](NATIVE_HTTP_QUEUES.md). Do not substitute a
new queue version, tip, candidate or key to escape a stale/refused decision.

The relevant real HTTP campaign is `queue_preparation_http`, alongside existing
`candidate_preparation_http` and `queue_landing_http` compatibility coverage.
These are validation entrypoints, not a claim that an unexecuted revision has
passed.
