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

The selected deadline includes socket closure and final capture revalidation.
Successful completion checks monotonic elapsed time, so a delayed timer callback
cannot admit an overdue response. Final revalidation also checks cancellation
before returning a capture. Synchronous validation cannot be preempted, but
crossing the original deadline refuses with `event_timeout` when it finishes;
the timeout is never renewed for the final page.

The legacy configuration remains explicit and selects `issues-pulls-v1`:

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

For collaboration history, use `schema_version:2`, add
`"disclosure_profile":"collaboration-v2"` and include explicit
`discussions_read` and `reviews_read` booleans in `scope`. All four read grants
must match the credential/endpoint intersection; a discussion-only or
review-only subscription is supported. The [archive guide](REMOTE_EVENT_ARCHIVE.md#collaboration-history)
contains a complete example and the event-family mapping. Native response
envelopes remain schema 1. Profile substitution, a missing grant field, or any
changed grant refuses. Schema-1 configurations gain no additional fields, so
their existing saved captures and archive bindings retain their exact bytes.

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

The legacy profile includes authorized issue and PR lifecycle history.
`collaboration-v2` additionally includes milestones, discussions, PR
conversations and review votes under their independent native grants. Both
profiles omit unrelated families, and cursor gaps reveal repository activity. Earlier events
skipped under a narrower grant are not backfilled by a later cursor. A changed
scope requires an explicitly new consumer/backfill, not silent continuation.
Server policy changes within unchanged grants are not detectable as a complete
ACL history by this protocol. Remote observations are not proof of authority,
absence, disclosure completeness, native frame authenticity or Git identity.
No delivery is acknowledged and no canonical outbox obligation is settled.

## Bounded native waits

`readEventPage` and `captureEventPages` accept `waitMs` from 0 through 30,000.
The default is 0 and preserves the existing immediate request. Positive values
send native `wait_ms`; the service waits only at an empty tail and returns
immediately for any cursor progress, including fully filtered pages. Successful
quiet waits retain the original cursor, while failures remain failures and are
never converted to empty pages or retried implicitly.

Waiting shares the original `timeoutMs` budget. Each request caps its requested
wait below its remaining transport deadline; capture neither renews that
deadline nor grants each page another full timeout. Leave time for network and
response work, for example `{ waitMs: 25000, timeoutMs: 30000 }`. The native wait
is an upper bound on idle time, not a completion guarantee. Cancellation still
closes the request before returning. `waitMs` is not configuration identity and
does not change saved-capture or archive bindings.

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
trust/hostname validation. Delayed timer delivery and synchronous revalidation
controls also check that late work cannot bypass the original deadline or a
cancellation request. They establish the consumer boundary only; Rust,
real-binary integration and independent batch verification remain separate.

## Restartable command and durable storage

[The remote event archive](REMOTE_EVENT_ARCHIVE.md) connects this acquisition
API to `scripts/fg_events.mjs init|capture|watch|inspect`. Complete pages and
their exact resume watermarks publish together before receipt output; restart
validates the retained chain instead of trusting a cursor-only checkpoint.
