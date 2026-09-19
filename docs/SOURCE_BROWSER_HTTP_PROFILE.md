# Read-only source browser

The explicitly source-enabled one-node HTTP gateway serves a browser at
`<repository-route>/ui/`. The trailing slash is required. The other gateway
profiles keep it disabled. This is a bounded local product surface, not the
complete forge UI, hosted IAM, a new authority, or a proof-verified client.

## Use and boundaries

Open the repository's `/ui/` URL, supply an operator-provisioned read token,
select a full reference such as `refs/heads/main`, and select SHA-1 or SHA-256.
The public static shell contains no repository data. Every tree, blob and
search request goes through the existing authenticated source API, canonical
hidden-ref policy and independent read quota. Source reads use POST framing but
create no transaction or idempotency binding. The browser has no write actions.

Directory pagination and navigation preserve raw filename bytes. Blob previews
show bounded byte ranges, not rendered HTML/SVG. Symlinks show target bytes and
are not followed. Binary or split UTF-8 ranges use hex. Literal search supports
exact bytes or ASCII-insensitive matching; match-limit results are visibly
partial, and a result opens the corresponding file range.

After the first read, subsequent requests carry both the authority snapshot
and selected commit comparisons. A moved snapshot is an error; reopen the
reference to explicitly select a new view rather than combine generations.

Tokens remain in page memory only, are removed from the password input on
submit, and are discarded on disconnect/page exit. Requests stay same-origin,
omit ambient browser credentials, reject redirects, and never place tokens in
URLs. Superseded responses cannot restore cleared repository data or discard a
newer credential. Source strings use text nodes rather than HTML interpolation.
The shell ships no third-party assets, adds no dependency/build pipeline, and
has a restrictive content security policy. Existing loopback-only listener and
external TLS requirements are unchanged. Use HTTPS beyond trusted loopback.

## Verification

Run `node --test tests/browser/*.test.mjs` with Node 22 or newer. The initial
browser slice has 24 passing JavaScript tests at delivery, including DOM/fetch
contract tests using test doubles. Three Rust route/security regression tests
are included in `smart_http::server::browser::tests`.

Rust/Cargo, real Chromium rendering, live-node interoperability and full
workspace verification were not available in the implementation environment.
These test doubles are not browser E2E or upstream Git conformance evidence.
Run the repository-owned Rust lanes and a real source-enabled listener/browser
scenario before advancing the release or compatibility claim. No historical
README test result establishes a gate for this revision.
