# Remote, scoped event acquisition

Owning integration: `frankengit-root-doctrine-x2mv.4.35`, FG-046; plan sections
24 and 31. `scripts/operator/event_feed.mjs` consumes the existing native
`GET <repository-url>/api/v1/events` API. It is external operator tooling, not
a Rust truth process, another native codec, a subscription authority or a
replacement for the server's disclosure checks.

`readEventPage` retrieves one bounded page. `captureEventPages` traverses up to
64 pages with one operation deadline and a cumulative 32 MiB response budget.
Defaults are 16 pages and 30 seconds. `validateEventCapture` rechecks saved JSON
against an independently retained configuration without network access.

The complete configuration is explicit:

```json
{
  "type": "frankengit_event_subscription",
  "schema_version": 1,
  "endpoint": "https://forge.example/repo.git",
  "scope": {
    "tenant_id": "11111111111111111111111111111111",
    "repository_id": "22222222222222222222222222222222",
    "repository_incarnation": "33333333333333333333333333333333",
    "object_format": "sha1",
    "issues_read": true,
    "pulls_read": false
  },
  "after": "0",
  "page_size": 20
}
```

Pass a separately provisioned 64-character lowercase hex Bearer credential.
The endpoint must be exact, without credentials, query, fragment, encoded path
aliases or trailing slash. Cleartext is admitted only for numeric loopback;
remote endpoints require certificate- and hostname-verified HTTPS. The optional
API `ca` is an explicitly supplied, bounded PEM buffer; verification cannot be
disabled. Redirects, cookies, ambient proxies, mutation routes, idempotency keys,
unsupported encodings, duplicate JSON keys and lossy numeric forms refuse.

Every page uses the complete unchanged browser `activityPage` validator.
Repository identity, incarnation, native object format and the exact grant
intersection must equal the independently selected configuration. Coordinates
remain canonical u64/u32 decimal strings; they are never converted to floating
point. Original `event_frame_hex` bytes remain untouched and opaque. The local
JSON envelope has deterministic key order; original HTTP JSON whitespace is
not retained.

Pagination follows `resume_after`, including on a fully filtered empty page.
`has_more`, not a nonempty result array, determines continuation. Reads are
append-stable and intentionally unpinned across pages: each page retains its
own authority-head observation, and the capture is **not** one immutable-head
snapshot. A page/byte/deadline limit cannot manufacture EOF. A returned capture
may still have `has_more:true`; network errors are not retried automatically.
Server errors or a changed scope produce no apparently complete batch.

The native profile omits event families other than its authorized issues and
pull requests, and cursor gaps reveal repository activity. Earlier events
skipped under a narrower grant are not backfilled by a later cursor. A changed
scope requires an explicitly new consumer/backfill, not silent continuation.
Server policy changes within unchanged grants are not detectable as a complete
ACL history by this protocol. Remote observations are not proof of authority,
absence, disclosure completeness, native frame authenticity or Git identity.
No delivery is acknowledged and no canonical outbox obligation is settled.

## Focused verification

```sh
node --test tests/operator/event_feed.test.mjs
```

The suite uses real HTTP/TLS sockets and explicitly constructed native-schema
peers, **not a live Rust `fg` server**. TLS tests use OpenSSL only to generate
an ephemeral test certificate. Production imports use Node built-ins and the
complete checked-in browser validator, with no added package dependency.
Tests cover SHA-1/SHA-256 labels, full-width cursor values, filtered progression,
independent scope pins, refusal/no-retry behavior, exact byte limits, strict
JSON, chunked/truncated responses, timeout/cancellation/socket drain, and TLS
trust/hostname validation. They establish the consumer boundary only; Rust,
real-binary integration and independent batch verification remain separate.
