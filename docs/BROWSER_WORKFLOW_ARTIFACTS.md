# Browser workflow artifact inspection and download

The existing browser reference client can inspect a retained workflow artifact
and download its verified bytes at:

```text
<repository-route>/ui/artifacts/
```

The source home page links to **Workflow artifacts**. The artifact page and its
own copies of the shared transport and stylesheet are also usable when source,
issue and pull-request browsing are disabled. On Linux, the node serves these
static assets when its existing workflow artifact root is configured. The shell
contains no repository data and grants no API capability. It adds no dependency,
frontend build step, storage service or new native artifact endpoint.

## Open a retained output

1. Obtain the exact artifact ID and repository incarnation from the retained
   workflow receipt, a pinned artifact link, or the node's readiness information.
   An artifact ID is 64 lowercase hexadecimal characters. The incarnation is
   32 lowercase hexadecimal characters. A payload hash or filename does not
   identify its artifact container.
2. Enter an ordinary bearer credential with the independent **`artifact-read`**
   grant and the expected incarnation. **Connect** installs it only in page
   memory; no read is sent until you choose **Inspect metadata**.
3. Enter the artifact ID. Optionally supply both a payload SHA-256 and exact byte
   count obtained from an independently trusted receipt. These pins must match;
   the browser never substitutes values returned by the server for caller pins.
4. Choose **Inspect metadata**. The page shows the artifact kind, payload size,
   declared media type, retention policy and verification result. Identity and
   retained provenance details are available separately. Inspection accepts
   metadata for the native read profile's complete payload limit, currently
   64 MiB, even when the browser cannot download that artifact.
5. For an artifact within the **16 MiB browser download limit**, choose
   **Load and verify complete bytes**. Only after verification succeeds does a
   bounded text preview appear and **Download verified bytes** become available.
   Download is another explicit action. It uses `application/octet-stream` and
   the filename `artifact-<id>`, irrespective of the artifact's declared media
   type. No archive is extracted, no script is executed and no permissions are
   installed.

The preview displays at most 4,096 original bytes after the **entire payload**
has been verified. Control and bidirectional formatting characters are escaped;
non-UTF-8 prefixes are represented as byte escapes. A clipped preview does not
mean a partial or truncated download. Empty artifacts are valid and downloadable.

Use the existing native CLI or operator download client for larger outputs; see
[HTTP workflow artifacts](HTTP_WORKFLOW_ARTIFACTS.md). The browser does not issue
a content request for an artifact over its limit and does not fall back to
unverified streaming, ranges or external URLs.

## Identity, scope and verification

The client uses only the existing bodyless requests:

```text
GET <repository-route>/api/v1/artifacts/<artifact-id>
GET <repository-route>/api/v1/artifacts/<artifact-id>/content
```

The dedicated shared-transport profile accepts no other path, query parameter,
HTTP method, request body, idempotency key, outcome recovery mode or sponsored
source-read credential. Other browser profiles do not gain an artifact route.
Requests use same-origin HTTPS, or trusted loopback HTTP, omit cookies, refuse
redirects, suppress referrers and bypass the cache. The native server continues
to authorize each request before disclosing repository data.

On metadata inspection the client requires the exact closed native schema,
expected artifact ID, expected incarnation and fixed
`trusted-workflow-local-owner` trust domain. It independently recomputes:

- The native artifact identity SHA-256 from the payload hash, exact byte length,
  kind, media type, optional build/check/source commitments and canonical
  retention encoding.
- The custody namespace SHA-256 from tenant, repository, incarnation and trust
  domain.

These preimages are the formats owned by `fgit-object-fabric`'s `ArtifactIdentity`
and `ArtifactScope`; the page introduces no alternate identity algorithm. Once a
namespace has been observed, further inspections on that connection must match
all its fields. Changing namespace requires an explicit reconnect. A supplied
payload hash and length are checked independently of these commitments.

Loading bytes revalidates metadata first. The transport checks inert response
headers, counts decoded bytes while reading the stream, enforces the selected
length and browser ceiling, and refuses truncation or overflow. The client hashes
the complete bounded payload using SHA-256 and compares it to the already
verified metadata. Because the binary endpoint does not carry an incarnation
header, the client then re-reads and revalidates the same metadata before exposing
the bytes. A replacement incarnation or credential revocation observed during
the transfer refuses the result. These separate observations do not create a
new atomic server transaction or promise knowledge of future revocation.

All metadata reads, body reads and asynchronous hashing in one operation share a
30-second default deadline. Metadata is limited to 16 KiB; payload buffering is
limited to 16 MiB; preview input is limited to 4 KiB. No unbounded artifact listing
or whole-repository scan is available. The browser necessarily retains the
complete bounded payload for hashing and binary download; it is not a resumable
large-file streaming client.

## Sharing and credential lifetime

After inspection the page provides a token-free link of this form:

```text
<repository-route>/ui/artifacts/#artifact=<id>&incarnation=<incarnation>
```

Opening the link only prefills the artifact and incarnation. It never connects,
fetches or downloads automatically. A credential is supplied separately, and a
link cannot silently reconnect to a different incarnation. The fragment contains
no credential, server root, producer token or payload. Unsupported fragment or
query fields refuse before credential use.

Disconnect, page navigation and fragment changes abort pending reads, invalidate
late completions, clear credentials and visible private results, zero held byte
buffers and revoke the current download object URL. Editing the artifact or
receipt pins clears the current selection and requires another inspection.
Editing connection details disconnects the current credential. An observed
HTTP 401 or 403 also disconnects and clears all retained results. Cancellation
does not wait for a remote source's cleanup promise to settle. Download URLs are
revoked on replacement, session cleanup, or after 30 seconds.

## What the result establishes

The artifact-read grant covers the configured repository incarnation's whole
retained workflow custody namespace, including hidden-reference and unpublished
candidate outputs. Source-read, issue-read, PR-read or merge grants do not imply
this access. The page offers no artifact enumeration, upload, deletion, root
selection or permission expansion.

Successful verification establishes agreement between the selected native
artifact identity, namespace metadata and complete payload bytes. It does not
authenticate a producer, establish check success, prove a build ran, authorize a
merge, publish canonical repository state or enforce retention. Optional
build-capsule, check-receipt and source-RCR values remain retained assertions.
Use the existing canonical workflow-check evidence surface when those authority
claims are needed. Arbitrary artifact content is never promoted to trusted
workflow evidence by this page.

## Focused regression coverage

The browser tests exercise the actual transport, protocol verifier, client and
view controller with bounded HTTP, DOM and download-URL doubles. They cover a
usable inspect/verify/download flow, exact downloaded bytes, empty and binary
payloads, all four retention variants, independent receipt pins, artifact/scope
substitution, corrupt/truncated/oversized streams, stale incarnation, forbidden
or revoked access, late responses, deadline expiry, cancellation, inert rendering
and object-URL cleanup. They are not full browser-engine or native-node HTTP
integration tests.

`tests/browser/artifacts-native-vectors.json` is shared with a Rust test that
constructs the real `ArtifactIdentity` and `ArtifactScope` and checks their
commitments, including optional provenance fields and exact 64-bit retention
values. The Rust static-route tests cover independent enablement, exact route
matching, request framing and asset budgets.

Run the focused JavaScript feature and shared-transport regressions with:

```sh
node --max-old-space-size=192 --test --test-concurrency=1 \
  tests/browser/artifacts.test.mjs tests/browser/artifacts-view.test.mjs \
  tests/browser/transport-cleanup.test.mjs tests/browser/recovery-transport.test.mjs
```

The native test filter is `smart_http::server::browser::artifacts::tests` in
`fgit-node`. Existing artifact HTTP coverage remains in
`crates/fgit-node/tests/artifact_http.rs`.
