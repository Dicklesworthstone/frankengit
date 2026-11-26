# Acquire a native pull-request candidate for review

This external operator client closes the read-side gap before
`remote_pull.mjs prepare`: obtain an open PR's recorded coordinates, current
review-policy epoch, a native merge/squash or whole-series rebase bundle, and the native inspection of
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

For an explicit rebase, replace `method` and `metadata` with:

```js
method: 'rebase',
metadata: {
  upstream: 'EXACT_RAW_ORIGINAL_COMMON_BASE_OID',
  committer: 'Maintainer <maintainer@example.invalid>',
  timestamp: '1700000000',
  empty: 'stop', // explicitly stop, drop, or keep newly empty commits
},
```

Replace the illustrative upstream with the exact lowercase 40- or 64-character
native object ID. Rebase preserves original authors and messages; replacement
author/message fields are refused. Its explicit upstream, committer, timestamp,
and empty policy are retained in the same capture schema as the other methods.

Identity, commit metadata, and method must be explicitly supplied. No ambient
Git configuration, current time, author identity, branch selector or token is
guessed. The same bearer needs the native Git-read and PR-read grants. A read
credential is not a review or merge credential; this capture records no claim
about the reader's principal. Publication remains a separately confirmed action
through the existing remote PR client and the native admission engine.

The client reads the PR and all review pages at one exact snapshot, derives the
subject without updating the PR, and calls `/pulls/NUMBER/prepare` for an ordinary
candidate or `/pulls/NUMBER/prepare-rebase` for the explicit `path-v1` replay. A clean
response supplies an exact binary bundle plus bounded metadata. The client
checks the bundle checksum and sends those exact bytes to `/pulls/NUMBER/inspect`
or `/pulls/NUMBER/inspect-rebase`, respectively. All four
kinds of response must retain the same repository incarnation, object format,
source head and snapshot token. A head change, including an unrelated forge
write, refuses this deliberately strict profile. Nothing refreshes or retries
implicitly. A stale PR is not synchronized as a side effect of preparation.

`state:conflicted` retains the exact native conflict report and has no candidate
or inspection. `state:already_up_to_date` likewise has no ordinary candidate.
A rebase can also stop at `state:became_empty`; this retains its original stopped
commit and completed provisional steps, with no bundle, inspection or reviewable
candidate. These are not successful empty merges. No rename heuristic,
fast-forward substitution or alternate preparation profile is silently selected.

Clean rebase inspection retains every rewritten native commit body, every
parent-to-child diff and the separate original-source comparison. A path added
and removed by different intermediate commits remains visible even if the final
tree comparison is empty. The preparation's ordered original-to-rewritten steps
must match the inspected commit IDs and trees exactly, including continuity of
dropped empty steps. Every actual rewritten committer header must match the
explicit request. This is the existing native `verified-linear-series-v1`
inspection, not a new artifact or independently recomputed Git history.

The ordinary `resolvePullCandidate` API and CLI resolution path accept merge and
squash conflicts. Rebase resolution needs cumulative recipes keyed by original
commit, so this client refuses that path explicitly. Rebase stopped packages
remain inspectable; the existing native/browser rebase workflow supports those
recipes. No ordinary path-only choice list is silently interpreted as a series
resolution, and a capture is never automatically retried with another empty
policy.

The return value contains `capture`, a detached JSON record of the request and
complete native observations, `bundle` (a detached Buffer or null), and `usage`
with request count and response payload bytes. Captures contain private PR text,
review reasons, raw native path/hunk bytes and commit metadata; they are not
safe for public logging. They contain no bearer token.

## Verification and bounds

The complete shared `pulls-core.mjs`, `pulls-candidate.mjs` and `pulls-rebase.mjs` validators are
used by both acquisition and `validateCandidateCapture(capture, bundle)`.
Offline validation rechecks the retained observations and bytes without network
access. It reuses the original native multipart validator by framing the retained
metadata/bundle, not by fabricating a new server receipt. Existing commit-body
hash and parent checks, complete diff/hunk checks, and byte-path handling remain
in those shared modules. The acquisition layer adds exact cross-response source
joins, duplicate-key/numeric JSON intake checks, complete reviewer paging, and
preparation-to-inspection series/metadata joins. Rebase capture rejects missing
native preservation flags, unsolicited resolution receipts, upstream objects
misreported as replayed originals, partial series and final-tree-only reports.

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
change the existing mutation client's independent full-u64 support. Candidate
preparation and inspection send byte-only branch names as lowercase hex in
`source_ref_hex` or `target_ref_hex`. Durable review and merge drafts also use
the retained hex bytes for branch labels containing C1 controls. Other text
branch names keep their original wire encoding. Raw changed-file paths remain
byte-preserving.

Defaults are one 30-second operation deadline (maximum 300 seconds), eight
review pages of 50 records (maximum 400 reviewers), 64 MiB total response payload,
16 MiB bundle, 2 MiB preparation metadata, 8 MiB per JSON review/inspection reply,
and 16 MiB normalized capture. `maxReviewPages` and `maxWireBytes` can narrow the
cumulative limits. Oversized complete reports refuse; a prefix never becomes a
complete capture. The JSON structure also has finite node/depth bounds. These
are payload/allocation bounds, not a peak RSS or total network-framing claim.
Rebase additionally inherits 256 original/rewritten commits, 2 MiB per commit
body, 16 MiB aggregate commit bodies, 512 changed-path entries, 4096 hunks,
64 text-file comparisons and 2 MiB cumulative path/hunk payload. The enclosing
8 MiB JSON and 16 MiB capture ceilings can refuse a series below those individual
limits; they never truncate the inspection.

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

The existing acquisition suite uses complete production dependencies, real
HTTP/TLS sockets and explicit native-schema peers. Its test-only Git fixture
executor requires the verified Git 2.54.0 pin and receipt inside Bubblewrap;
missing namespace capabilities or the pinned oracle refuse rather than using
ambient Git. The peer's inspection JSON remains a contract fixture, not an
executed Rust server. Coverage includes reviewer paging, noncandidate outcomes,
head/scope corruption, MIME, commit/parent/hunk corruption, certificates,
cancellation, deadlines and cumulative byte bounds.

The rebase client lane runs independently of that oracle:

```sh
node --test --test-concurrency=1 tests/operator/pull_candidate_rebase.test.mjs \
  tests/operator/pull_candidate_commit.test.mjs
```

Its controlled native-schema peers use real computed SHA-1/SHA-256 commit-body
identities and deliberately opaque bundle fixtures. They test exact bundle
custody, complete intermediate-path disclosure, actual executable CLI
capture/inspect/stage, private packages, explicit review/merge methods, stopped
outcomes, stale reviewer streams, raw refs and tampered-series refusal. They also
retain ordinary merge/squash request and review compatibility. These tests do
not establish native bundle admission, independent ancestry/replay equivalence,
Rust-node execution or full-workspace verification.
