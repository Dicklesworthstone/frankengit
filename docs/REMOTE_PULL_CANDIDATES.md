# Acquire a native pull-request candidate for review

This external operator client closes the read-side gap before
`remote_pull.mjs prepare`: obtain an open PR's recorded coordinates, current
review-policy epoch, a native merge/squash bundle, and the native inspection of
that exact bundle. It does not publish a PR, vote, merge, ref, object, seal, or
transaction. Related work is `frankengit-root-doctrine-x2mv.4.20` and `.4.13`;
neither broad bead is closed by this client.

## Library interface

`capturePullCandidate(input, token, options)` is exported by
`scripts/operator/pull_candidate_capture.mjs`. Supply:

```js
const input = {
  endpoint: 'https://forge.example/repo.git',
  scope: {
    tenant_id: '11111111111111111111111111111111',
    repository_id: '22222222222222222222222222222222',
    repository_incarnation: '33333333333333333333333333333333',
    object_format: 'sha256',
  },
  number: '37',
  metadata: {
    author: 'Developer <developer@example.invalid>',
    committer: 'Developer <developer@example.invalid>',
    timestamp: '1700000000',
    message: 'Explicit proposed merge message.\n',
  },
  method: 'merge-commit', // or explicitly 'squash'
  expected_head: null,   // or an independently retained native snapshot token
};
```

Identity, commit metadata, and method must be explicitly supplied. No ambient
Git configuration, current time, author identity, branch selector or token is
guessed. The same bearer needs the native Git-read and PR-read grants. A read
credential is not a review or merge credential; this capture records no claim
about the reader's principal. Publication remains a separately confirmed action
through the existing remote PR client and the native admission engine.

The client reads the PR and all review pages at one exact snapshot, derives the
subject without updating the PR, and calls `/pulls/NUMBER/prepare`. A clean
response supplies an exact binary bundle plus bounded metadata. The client
checks the bundle checksum and sends it to `/pulls/NUMBER/inspect`. All four
kinds of response must retain the same repository incarnation, object format,
source head and snapshot token. A head change, including an unrelated forge
write, refuses this deliberately strict profile. Nothing refreshes or retries
implicitly. A stale PR is not synchronized as a side effect of preparation.

`state:conflicted` retains the exact native conflict report and has no candidate
or inspection. `state:already_up_to_date` likewise has no candidate. Neither is
an empty successful merge. `path-merge-v1` is the only construction profile in
this first client: no rename heuristic, conflict-resolution upload, rebase,
fast-forward substitution or alternate preparation profile is silently selected.

The return value contains `capture`, a detached JSON record of the request and
complete native observations, `bundle` (a detached Buffer or null), and `usage`
with request count and response payload bytes. Captures contain private PR text,
review reasons, raw native path/hunk bytes and commit metadata; they are not
safe for public logging. They contain no bearer token.

## Verification and bounds

The complete, unchanged `pulls-core.mjs` and `pulls-candidate.mjs` validators are
used by both acquisition and `validateCandidateCapture(capture, bundle)`.
Offline validation rechecks the retained observations and bytes without network
access. It reuses the original native multipart validator by framing the retained
metadata/bundle, not by fabricating a new server receipt. Existing commit-body
hash and parent checks, complete diff/hunk checks, and byte-path handling remain
in those shared modules. The acquisition layer adds exact cross-response source
joins, duplicate-key/numeric JSON intake checks, and complete reviewer paging.

This is **not independent authority or ancestry verification**. A bundle checksum
binds transport bytes, not its Git semantics. The native inspector owns closure,
ancestry and diff computation. The client checks the hash of the reported commit
body and consistency of the reports; it does not independently reconstruct the
entire tree or recompute the diff. A native read report is never approval or
permission to merge, and a current review can become stale before publication.
The existing native form API still lacks an atomic incarnation precondition.

The inherited shared-validator profile uses exact safe integers. PR numbers,
versions, policy epochs and timestamps above `9007199254740991` refuse rather
than round. Input number/timestamp are canonical decimal strings. This does not
change the existing mutation client's independent full-u64 support. Byte-only
branch names are readable but cannot enter this UTF-8 preparation form; they
refuse instead of being renamed. Raw changed-file paths remain byte-preserving.

Defaults are one 30-second operation deadline (maximum 300 seconds), eight
review pages of 50 records (maximum 400 reviewers), 64 MiB total response payload,
16 MiB bundle, 2 MiB preparation metadata, 8 MiB per JSON review/inspection reply,
and 16 MiB normalized capture. `maxReviewPages` and `maxWireBytes` can narrow the
cumulative limits. Oversized complete reports refuse; a prefix never becomes a
complete capture. The JSON structure also has finite node/depth bounds. These
are payload/allocation bounds, not a peak RSS or total network-framing claim.

Each request owns and closes one socket. HTTPS verifies hostnames/certificates;
HTTP is limited to explicit numeric loopback. `ca` accepts an explicit bounded
PEM trust root. There are no redirects, ambient credentials, cookies, transaction
keys, proxy credentials, network retries, or arbitrary request routes. `signal`
supports cancellation. All read phases share the one deadline, including final
validation; synchronous local parsing/hashing and OS DNS cannot promise hard
preemption. Errors expose bounded codes and phase/status, not server prose.

## Executed test profile

```sh
node --test tests/operator/pull_candidate_capture.test.mjs
```

Node 22.16.0 passes 89 focused tests using complete production dependencies,
real HTTP/TLS sockets and explicit native-schema peers. Test-only Git 2.39.2
constructs and verifies real SHA-1/SHA-256 bundles and commit bodies for both
parent styles; production code never invokes Git. The peer's native inspection
JSON is still a contract fixture, not an executed Rust server. Coverage includes
review paging, all noncandidate outcomes, head/scope corruption, binary MIME,
commit/parent/hunk corruption, certificates, cancellation, deadline and exact
cumulative byte bounds. Disabling the cross-response head join makes four
snapshot regressions fail; the restored implementation passes. Rust compilation,
live-fg native authorization/ancestry, full-workspace and deployment verification
have not been executed in this environment.
