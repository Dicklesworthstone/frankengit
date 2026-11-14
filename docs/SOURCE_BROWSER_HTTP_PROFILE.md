# Read-only source browser

The explicitly source-enabled one-node HTTP gateway serves a browser at
`<repository-route>/ui/`. The trailing slash is required. The other gateway
profiles keep it disabled. This is a bounded local product surface, not the
complete forge UI, hosted IAM, a new authority, or a proof-verified client.

## Use and boundaries

Open the repository's `/ui/` URL, supply an operator-provisioned read token,
select a full reference such as `refs/heads/main`, and select SHA-1 or SHA-256.
The public static shell contains no repository data. Every tree, blob, archive
and search request goes through the existing authenticated source API, canonical
hidden-ref policy and independent read quota. Source reads use POST framing but
create no transaction or idempotency binding. The browser has no write actions.

Directory pagination and navigation preserve raw filename bytes. Blob previews
show bounded byte ranges, not rendered HTML/SVG. Symlinks show target bytes and
are not followed. Binary or split UTF-8 ranges use hex. Literal search supports
exact bytes or ASCII-insensitive matching; match-limit results are visibly
partial, and a result opens the corresponding file range.

**Download directory** requests the complete currently selected directory through
the [authenticated archive endpoint](SOURCE_TREE_ARCHIVES.md#authenticated-http-downloads),
including entries beyond the visible listing page. It carries the current
snapshot and commit comparisons and checks the returned root and selected-tree
identities. The browser verifies the archive profile, exact bounded response
length and attachment metadata before creating a download link. Cancellation,
truncation, a changed selection or a stale response cannot publish a partial
download. Download URLs are revoked on replacement, disconnect and page exit.
The metadata comparisons are not independent cryptographic archive verification.

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

Run `node --test tests/browser/*.test.mjs` with the version pinned in
`tests/node-version`. The source archive tests include metadata and body bounds,
snapshot mismatches, cancellation, truncated transfers and stale responses.
DOM and fetch contract tests use doubles; they are not live-browser evidence.
The Rust static-route tests remain in `smart_http::server::browser::tests`,
with archive parsing and real TCP/node tests described in
[source tree archives](SOURCE_TREE_ARCHIVES.md#bounds-and-tests).

The implementation's native build lost its execution host before completion.
Current Rust, live Chromium interoperability and full-workspace gates remain
pending. Run the repository-owned lanes and a real source-enabled listener/browser
scenario before advancing a release or compatibility claim. Historical test
results do not establish a gate for this revision.
