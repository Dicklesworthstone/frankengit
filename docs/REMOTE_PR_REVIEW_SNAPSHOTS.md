# Snapshot-pinned remote PR review inspection

`scripts/operator/pull_review_snapshot.mjs` fills the read side of the remote
review-to-merge workflow. It obtains one PR and every visible retained reviewer
row through the existing native PR and review GET endpoints. It requires no
canonical-storage access, outcome-read grant, or mutation grant. Related product
work is `frankengit-root-doctrine-x2mv.4.13` and `.4.20`; neither is closed here.

```js
import { capturePullReviews } from './scripts/operator/pull_review_snapshot.mjs';
const capture = await capturePullReviews({
  endpoint: 'https://forge.example/repo.git',
  scope: { tenant_id: '11111111111111111111111111111111',
    repository_id: '22222222222222222222222222222222',
    repository_incarnation: '33333333333333333333333333333333',
    object_format: 'sha1' },
  number: '37', expected_head: null,
}, token, { pageLimit: 50, timeoutMs: 30000 });
```

Supply the actual independently selected scope and an explicit scoped token.
The example IDs are placeholders. `expected_head` can pin an already observed
`alg:...` snapshot. Otherwise the first PR reply selects the snapshot. Every
review page must agree on that token, source-head identity, PR version, repository
incarnation/hash domain and policy epoch. Each continuation carries the original
snapshot and exact previous reviewer cursor. A moved/unavailable snapshot stops
the whole capture: no latest-state retry, hidden restart or successful prefix.

The result contains `pull` and complete `review_pages`, retaining original
review subjects, candidate identities, freshness and per-reviewer versions.
Native u64 counters are normalized to exact decimal strings; Git OIDs stay
algorithm-qualified. Native byte-only reference names remain hex plus null text,
never lossy UTF-8. Missing PRs, existing PRs with no reviews, closed PRs and
merge-only legacy records are distinct. Generic HTTP errors are not absence.
Rendering is not requested; all repository text is data, not executable HTML.

`complete:true` means pagination of this server's visible retained reviewer
projection was exhausted, NOT all historical review events, independent
cryptographic verification, fresh branch-tip validation or complete authorization
knowledge. The client cannot detect a server that lies consistently about the
last page. `merge_authorized` remains **false** even when every vote says approve
and current. The native admission engine still owns policy and publication.

`validateReviewCapture` checks a detached saved result, including every page,
join, continuation and final exhaustion condition. `reviewCanonical` serializes
it with escaped control/bidirectional formatting characters, and `reviewHash`
computes a SHA-256 integrity pin. These are local observations, not authority,
signatures or rollback protection. Captures contain private PR/review text;
token-free does not mean arbitrary repository text has been secret-redacted.

## Bounded transport and execution

The only requests are GET for the chosen PR and its reviews. There are no
arbitrary routes, idempotency keys, request bodies, redirects, cookies, ambient
credentials, TLS-disable options, connection pools or automatic network retries.
HTTPS verifies certificates/hostnames; cleartext permits only canonical numeric
loopback endpoints. Optional `ca` is a copied PEM buffer capped at 128 KiB.

One operation deadline covers all requests and validation (default 30 seconds,
maximum 300 seconds), and `signal` cancels owned sockets. Each request closes
before completion is returned. Blocking local computation/platform work is not
a hard real-time preemption guarantee. Errors omit raw server response prose.

Default bounds: 50 reviews/page, 32 review pages, 1,024 reviewers, 2 MiB/reply,
8 MiB total response payload and 8 MiB normalized capture. `pageLimit` (1..100),
`maxPages`, `maxReviewers` and `maxWireBytes` may select smaller bounded profiles.
The wire counter measures response bodies, not HTTP/TLS framing. Bounds can
refuse an otherwise valid native response; they never truncate it into success.
JSON duplicate keys, unsafe numeric syntax, depth over 16 and excessive structure
also refuse. The profile recognizes the current unrendered native-v1 fields;
unrecognized fields do not silently gain semantics.

## Validation boundary

Run `node --test tests/operator/pull_review_snapshot.test.mjs` on Node 22.16.0.
Tests import complete production code and exercise actual HTTP/TLS sockets,
private test certificates, both Git hash domains, exact large counters, paged
joins, malformed responses, cancellation and paired resource-bound cases.
The peers encode the inspected Rust JSON contract; they are not a running Rust
`fg` server or an authorization/policy oracle. No Rust, native admission,
real-browser, full-workspace or deployment verification is claimed.

## Capture, inspect, and draft through the CLI

The executable reads credentials only for `capture`. It accepts a private
selection JSON containing the five fields in the library example above. Use
actual IDs and a decimal-string PR number. Put credentials in a private mode
0600 file; do not pass a token on the command line. Its optional final newline
is accepted. The immediate parent directory must be mode 0700 and owner-owned,
outside a Git worktree, with no aliased parents.

```sh
node scripts/fg_pull_review.mjs capture --input /private/selection.json \
  --token-file /private/token --output /private/pr-37-review.json
node scripts/fg_pull_review.mjs inspect --capture /private/pr-37-review.json \
  --sha256 CAPTURE_SHA256_FROM_CAPTURE
```

Capture emits a compact receipt with the file's SHA-256, snapshot token, found
flag and reviewer count. It does not print PR bodies or review reasons. Keep the
hash separately: subsequent inspection and drafting require it, verify the
entire file, and repeat all schema/page-join/completeness checks offline.
`inspect` deliberately prints the private contents. Neither inspect nor draft
accepts a token or connects to the server.

Choose an action explicitly in a separate private JSON file. For example:

```json
{
  "action": "approve",
  "principal_id": "44444444444444444444444444444444",
  "merge_base": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "candidate_commit": "cccccccccccccccccccccccccccccccccccccccc",
  "reason": "I inspected this exact candidate."
}
```

Those are illustrative placeholders, not candidate generation or verification.
Use the actual native OIDs of the candidate you inspected. For a SHA-256
repository, both OIDs have 64 hex characters. The principal selects which
retained review-stream predecessor to use; it does not impersonate that
principal or claim authentication. The existing sender authenticates it through
its native outcome preflight before publication.

```sh
node scripts/fg_pull_review.mjs draft --capture /private/pr-37-review.json \
  --sha256 CAPTURE_SHA256_FROM_CAPTURE --input /private/choice.json \
  --output /private/pr-37-command.json
node scripts/remote_pull.mjs prepare --input /private/pr-37-command.json \
  --token-file /private/reviewer-token --bundle /private/inspected-candidate.bundle \
  --request-dir /private/pr-37-review-request
```

Then inspect and explicitly send that request using the existing
[reviewed-command workflow](REMOTE_REVIEWED_MERGES.md). Drafting itself does not
create a key, save a publication intent, upload the candidate, approve or merge.
The draft is the existing `prepare` input shape, not a new mutation protocol.
The CLI's draft receipt records the source capture hash; the native command
carries the observed PR/reviewer versions and policy epoch, not that local hash.
This adapter's tests verify the inspected native command vocabulary and output
shape; they do not execute the separate remote sender or Rust admission.

For `approve` and `request-changes`, the exact predecessor is selected from all
captured pages, or zero only after the complete visible stream has been read.
The subject uses the captured PR metadata and policy epoch. It does not assert
that those recorded tips still equal the current branch tips; native admission
can refuse a stale subject. A first-page omission must never become a guessed
zero predecessor. New reviews require an open PR with ordinary metadata.

For `withdraw`, provide only `action`, `principal_id` and `reason`. The draft
retains that principal's original subject, policy epoch and candidate even when
they are stale. A missing, already withdrawn or legacy candidate-less review
refuses; no substitute subject is invented. No bundle is required by withdrawal.

For `merge`, provide explicit `merge_base`, `candidate_commit`,
`required_reviewers` and `method` (`merge-commit` or `squash`) instead of a reason.
The nonempty unique reviewer set may not contain the submitting principal. It
is not inferred from votes, and its members need not appear approved in the
capture: only the native merge driver can decide eligibility, independence,
ancestry and current protection. There is no readiness or merge-permission flag.
No strategy or expected version is automatically refreshed.

Byte-only branches remain inspectable but refuse drafting, because the existing
native mutation forms require UTF-8 refs. Exhausted u64 stream versions refuse
rather than wrapping. Closed or merge-only PRs can be inspected, not turned into
new-review/merge drafts.

## File publication and interrupted reads

Outputs are private, complete, synced JSON published under a new name using a
create-only link, followed by staging-link removal and directory synchronization.
An existing destination always refuses. No output is published if acquisition
fails on a later review page. A failed final-name race cannot overwrite the
winner. Partial/private `.pending` residue is retained after interrupted file
publication; it is not selected or repaired automatically. Linked, public,
special, changed and oversized files refuse on read. This is a cooperating,
operator-owned filesystem profile, not hostile-parent confinement, authentication
of local files, or universal hardware power-loss durability.

SIGTERM/SIGINT stop the owned read; SIGKILL can leave staging residue. No failure
is labeled a completed capture. A lost stdout after completed file publication
leaves the file in place and includes the saved hash/path in the diagnostic when
stderr still works. Retain those files rather than overwriting them. All control
output labels `publication_attempted:false`; this executable contains no mutation
route. The capture deadline bounds network acquisition and validation; local
file reads/writes are bounded in size, not preemptible wall-clock time.

Exit 0 means a completed capture, inspection or draft; a typed missing PR is a
successful read with `found:false`, not a draftable object. Exit 2 means invalid
local input before work starts; exit 3 means incomplete network, file publication
or output. Inspect/draft errors cannot mutate the repository.

Run the whole focused suite:

```sh
bash scripts/verify_pull_review_snapshots.sh
```

The executed profile is Node 22.16.0. In addition to the core HTTP/TLS cases,
these tests drive real CLI processes and private files, exact later-page review
predecessors, stale withdrawal subjects, both merge methods, missing/byte-only
records, corruption/pins, concurrent output writers, signals and broken stdout.
No live `fg`, native policy, sender integration, full workspace or production
readiness is claimed.
