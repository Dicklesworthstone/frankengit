# Candidate reviews and reviewed merges over HTTP

The opt-in PR service now exposes native candidate review and reviewed merge
publication. It calls the existing `admit_candidate_review_durable_in`,
`read_reviews_in`, and `apply_reviewed_merge_bundle_durable_in` node APIs. There
is no HTTP approval database, alternate Git engine, or ref-only merge fallback.

A vote checks the actual submitted Git bundle without importing its objects.
A merge stages the native candidate through production quarantine, then uses the
existing reviewed merge driver to publish the target ref, PR transition and
outbox obligation at one authority CAS. Staging a rejected candidate is not
publication. Existing mandatory repository review protection still applies.

This is an implementation interface, not evidence of a passing Rust build or
live acceptance campaign. The gateway remains bounded, loopback-only and
operator-managed, not the complete fastapi_rust/OpenAPI, organization/team IAM,
TLS, cross-repository PR or hosted deployment product.

## Deliberate permissions

Use the existing PR service switch; existing grants do not gain new authority:

```sh
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file /secure/http-grants \
  --allow-pulls --allow-outcomes
```

`--allow-outcomes` is optional and independently enables lost-response recovery.
The new explicit credential scopes, appended to the canonical scope order, are:

```text
read,receive,issues-read,issues-write,outcomes-read,pulls-read,pulls-write,reviews-read,reviews-write,merges-write
```

| Scope | Authority |
|---|---|
| `reviews-read` | Read visible review streams, including exact candidate coordinates and retained snapshots. |
| `reviews-write` | Submit or withdraw this authenticated principal's own exact-candidate vote. |
| `merges-write` | Submit a reviewed merge and choose its additional nonempty named-reviewer requirements. |

No scope implies another. PR metadata access does not grant review or merge
access. Merge permission grants neither voting nor reading reviews. Git push
permission does not grant the reviewed merge API. The `merges-write` grant is
an explicit CODE-PUBLICATION capability even when Git receive-pack is disabled:
`--allow-receive` gates Git pushes, not this separately granted native operation.
All routes still require `--allow-pulls`; older serving entry points disable them.

A merger must be trusted to select additional reviewer requirements. The core
rejects empty sets, duplicate reviewers and submitter/opener self-approval.
Mandatory protected-branch requirements cannot be removed by submitting a
smaller list. Only explicitly required and mandatory reviewers are enforced;
this is not an implicit veto by every principal who has ever reviewed a PR.
There is no remote protection-administration endpoint in this change.

Credential files retain their existing exact tenant/repository/incarnation
binding and per-authentication reload. Rotation preserves identity when the
principal remains unchanged; revocation affects subsequent authentications,
not already authenticated bounded requests. Static tokens receive no new grant.
See [HTTP_PULL_REQUEST_API.md](HTTP_PULL_REQUEST_API.md) for provisioning and
[HTTP_OUTCOME_API.md](HTTP_OUTCOME_API.md) for independent recovery permissions.

## Endpoints and semantic fields

```text
GET  {REPO_URL}/api/v1/pulls/{number}/reviews
POST {REPO_URL}/api/v1/pulls/{number}/reviews/approve
POST {REPO_URL}/api/v1/pulls/{number}/reviews/request-changes
POST {REPO_URL}/api/v1/pulls/{number}/reviews/withdraw
POST {REPO_URL}/api/v1/pulls/{number}/merge
```

Every POST requires an original, client-selected `Idempotency-Key`. A reviewer
identity is never accepted in the form: the authenticated grant supplies it.
The caller supplies these nine common fields explicitly:

| Field | Meaning |
|---|---|
| `object_format` | Exactly `sha1` or `sha256`, matching the repository. |
| `pull_request_version` | Exact positive PR aggregate version under review. |
| `policy_epoch` | Exact positive policy epoch bound to the review/merge. |
| `source_ref`, `target_ref` | Distinct full `refs/heads/...` branch names. |
| `source_tip`, `target_tip` | Exact nonzero lowercase native commit OIDs. |
| `merge_base` | Exact native base commit of the candidate. |
| `candidate_commit` | Exact proposed merge commit, including its tree and metadata. |

Review actions also require `expected_version`, the predecessor version of
THIS REVIEWER'S stream (`0` for its first vote), and `reason`. Withdrawal needs
a positive predecessor version and the exact subject and candidate of the vote
being withdrawn. Reasons are bounded to 16 KiB of UTF-8; request-changes and
withdrawal require nonblank text. The PR version and review-stream version are
independent: casting a vote does not increment the PR's metadata version.

Merge commands instead require one to 32 repeated `required_reviewer` fields,
each a lowercase 32-hex-character principal ID. The set is sorted canonically;
duplicates and the submitter are rejected. It is sealed together with the
candidate and policy epoch. Changing the set is not an identical retry.

All fields are explicit. No endpoint reads latest state to fill omitted values
or refresh a stale command. Unknown or duplicate scalar fields, wrong hash
domains, zero OIDs, inapplicable fields, invalid UTF-8, NUL and malformed percent
escapes are rejected. Ref/PR/policy freshness and candidate correctness remain
checks inside the native admission engines, not assumptions made by HTTP.

## Upload the actual candidate

For approval, request-changes and an initial merge attempt, send multipart form
data with a URL-encoded `command` part and a binary `bundle` part. Either part
order is accepted. The command contains the fields above, not JSON. A local
`OneNode::prepare_merge_bundle_in` result supplies the supported two-parent Git
bundle; this HTTP extension does not expose candidate preparation itself.

With the exact command saved as URL-encoded bytes in `review.form`:

```sh
curl --fail-with-body --header @/secure/reviewer.headers \
  --header 'Idempotency-Key: review-candidate-attempt-1' \
  --form 'command=<review.form;type=application/x-www-form-urlencoded' \
  --form 'bundle=@candidate.bundle;type=application/x-git-bundle' \
  "$REPO_URL/api/v1/pulls/41/reviews/approve"
```

Use the same binary bundle and a separately prepared `merge.form` containing
common fields plus the required reviewers:

```sh
curl --fail-with-body --header @/secure/merger.headers \
  --header 'Idempotency-Key: merge-candidate-attempt-1' \
  --form 'command=<merge.form;type=application/x-www-form-urlencoded' \
  --form 'bundle=@candidate.bundle;type=application/x-git-bundle' \
  "$REPO_URL/api/v1/pulls/41/merge"
```

These are separate independently authenticated principals. A displayed approval,
source-only vote, supplied diff, or object-presence observation cannot replace
native validation of the exact candidate. The merge driver checks current
reviewer decisions and mandatory protection again after losing a CAS.

Withdrawal uses `application/x-www-form-urlencoded` directly, with no bundle:

```sh
curl --fail-with-body --header @/secure/reviewer.headers \
  --header 'Idempotency-Key: withdraw-candidate-attempt-1' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary @withdraw.form \
  "$REPO_URL/api/v1/pulls/41/reviews/withdraw"
```

Form-only approval/request-changes/merge requests are also accepted as the
native terminal-retry path: a previously authenticated decision can be recovered
without resending candidate bytes. This does not allow a new vote or merge to
skip validation. Missing candidate evidence for an undecided operation remains
an error, not a synthetic approval or success. Prefer the independent outcome
lookup when only the old decision is needed.

## Receipts, refusal and recovery

Review results have `type: "candidate_review_publication"`; merge results use
`type: "reviewed_merge_publication"`. They carry the authenticated actor, exact
subject/candidate, review predecessor or named-reviewer set, stable transaction
ID and authenticated terminal decision. HTTP 200 means committed; HTTP 409 with
`outcome: "refused"` is a canonical refusal, not a transport retry instruction.
External delivery is not claimed: `delivery_acknowledged` remains null.

A canonical refusal stays refused after a reviewer later approves. A genuinely
new attempt needs a new key only after that earlier refusal is established.
An identical key and command recover the earlier result, not a freshly evaluated
success. Detected key-reuse rejection has the existing conflict error vocabulary.

Errors use `pull_request_error`, without echoing credentials or raw keys. Local
failure after entering native admission is conservatively `outcome_unknown`,
not proof of rollback. A final response is never followed by another response
because of socket or shutdown failure. Keep the same principal and complete
semantic command when resolving an ambiguous attempt.

The existing bodyless outcome lookup accepts the review or merge's ORIGINAL key:

```text
POST {REPO_URL}/api/v1/outcomes
Authorization: Bearer <token-for-original-principal-with-outcomes-read>
Idempotency-Key: <original-attempt-key>
Content-Length: 0
```

It requires no PR text or bundle, and can be granted after review/merge write
permission is revoked. The lookup itself never reexecutes or publishes work.

## Review pages and historical display

A page uses `review_page` JSON and contains each reviewer's latest event at one
selected head, reviewer-stream version, complete subject, candidate (or null
for a legacy source-only review), decision, reason, freshness and opener status.
There is no approval count over a partial page. `merge_authorized: false` makes
clear that a page is not a publication capability.
Subjects in pages and publication receipts preserve exact native reference bytes
in authoritative lowercase `source_ref_hex` and `target_ref_hex`. `source_ref`
and `target_ref` retain UTF-8 text or are null when those bytes are not UTF-8.

```text
GET {REPO_URL}/api/v1/pulls/41/reviews?limit=50
GET {REPO_URL}/api/v1/pulls/41/reviews?limit=50&after=REVIEWER_ID&expected_head=TOKEN
```

Rows are ordered by principal ID. `after` requires the prior page's snapshot
token. Retained pages use matching historical refs and PR state, while current
credentials and canonical hidden-ref policy still control disclosure. Unknown
or undisclosed PRs return 404 with `found: false`. An old Current vote may remain
visible after withdrawal or merge, but it cannot satisfy a new merge's checks.
The existing 256-transition retained-snapshot/epoch boundaries still apply.

## Explicit resource and interoperability profile

This is a bounded multipart/form-data subset: a single `command` and optional
single `bundle`, no other parts, encodings, nested MIME, preamble or epilogue.
Part headers are limited to 4096 bytes, with explicit Content-Disposition names
and Content-Type. Optional filenames are ignored, never opened or written.
Boundaries are 1–70 ASCII alphanumeric, dash, underscore or dot characters,
optionally quoted. Escaped/ambiguous disposition parameters are refused.

Commands are capped at 256 KiB encoded, bundles at 64 MiB, and complete decoded
uploads at their sum plus 16 KiB framing allowance, further narrowed by the
configured HTTP input ceiling. Wire framing and chunk counts have separate
bounds. HTTP intake must finish before multipart parsing or admission. The
multipart parser borrows the buffered body and uses linear boundary search with
cancellation checkpoints; it does not copy a second bundle. Native quarantine
retains its own existing resource envelope. This is not disk-spooled/unbounded
streaming candidate upload.

Review replies are capped at 16 MiB and the configured response ceiling before
success is emitted. Authentication, independent grants, declared-size checks
and ingress quota run before `100 Continue`. The existing owned blocking-child,
socket deadline, response, cleanup and bounded listener contracts are unchanged.

Focused checks (presence of tests is not a passing-test claim):

```sh
cargo test -p fgit-node --lib smart_http::server::pulls
cargo test -p fgit-node --lib smart_http::server::credentials
cargo test -p fgit-node --test review_merge_http --test pull_request_http \
  --test issue_http --test outcome_http
```

The new TCP tests use actual imported native objects, production candidate
preparation, HTTP requests and the embedded authority in both object formats.
They cover withdrawal versus retained approval, coupled publication, stable
refusals/retries, restart recovery after write revocation, malformed/incomplete
uploads, independent scopes and mandatory protection against weaker request
requirements. Candidate preparation over HTTP, cross-repository PRs, broader
review policy and full product acceptance remain separate work.
