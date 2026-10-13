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
