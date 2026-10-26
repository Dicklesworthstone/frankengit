# Authenticated workflow artifact downloads

The Linux `fg serve-http` profile can inspect and download exact retained workflow
artifacts. It uses the same immutable `LocalArtifactStore` as the trusted workflow
runner and `fg artifact`, with complete payload verification before a successful
HTTP response starts. No Git subprocess, alternate container format or repository
mutation is involved.

## Enable the custody namespace explicitly

Start the existing repository with its existing absolute private artifact root:

```sh
fg serve-http "$NODE" "$TENANT_ID" "$REPOSITORY_ID" 127.0.0.1:9419 \
  --trusted-local --credentials-file "$CREDENTIALS_FILE" \
  --artifact-root "$ARTIFACT_ROOT" --expected-incarnation "$INCARNATION_ID"
```

The root must already be a nonsymlink directory with mode `0700`. Protect it and
its ancestors as operator-owned storage. Startup validates the root before the
listener publishes readiness; validation and reads do not create a missing
namespace. The readiness record includes `artifacts_enabled`. Omitting the flag
keeps this profile disabled. No additional `--allow-source` or forge API switch
is required.

Provision the existing incarnation-bound credential table with an explicit
`artifact-read` scope. The header can be obtained without opening a listener:

```sh
fg serve-http "$NODE" "$TENANT_ID" "$REPOSITORY_ID" 127.0.0.1:0 \
  --trusted-local --print-credentials-header --expected-incarnation "$INCARNATION_ID"
```

A table has this format; the row stores the SHA-256 of the exact 64-character
lowercase hexadecimal bearer token, never the token itself:

```text
frankengit-http-credentials-v1 <tenant-id> <repository-id> <incarnation-id>
<sha256-of-token> <principal-id> artifact-read
```

Keep the regular credential file private (`0600` or stricter), and atomically
replace it for rotation or revocation. Each request reloads and authenticates one
complete table. A malformed table or a different repository incarnation fails
closed. Already authenticated requests keep their finite in-flight grant.
`--token-file` is the original Git-only mode and cannot enable this API.

When combining grants, `artifact-read` is last in the canonical scope order,
after `lfs-write`. Existing Git, source, issue, PR, review, merge, protection,
outcome and LFS grants do not imply artifact access. An artifact-only credential
cannot read Git refs or publish source, checks or forge metadata.

**This grant reads the entire selected repository incarnation's
`trusted-workflow-local-owner` artifact namespace, including outputs and
provenance produced from hidden refs or unpublished candidates.** It is suitable
only for principals authorized for that complete custody namespace. Ordinary
Git ref visibility does not narrow this separate grant. A client cannot select a
filesystem root, tenant, repository incarnation or different trust domain.

## Obtain the exact ID from the producing workflow

A completed workflow result's `artifacts` array provides each selected output's
`artifact_id_sha256`, `payload_sha256`, `payload_bytes` and executable flag.
Its `manifest_id_sha256` selects the retained provenance manifest. The same IDs
are retained in the attempt's create-only `job-NNN-artifacts.json` receipts.
See [Retained outputs from trusted workflows](TRUSTED_WORKFLOW_ARTIFACTS.md).

Use `artifact_id_sha256` or `manifest_id_sha256` as the selector. The raw payload
digest is a different identity and does not select the container. IDs are exactly
64 lowercase hexadecimal characters. Possession of an ID, a guessed producer,
a manifest's source ref, or a check receipt assertion never grants access.

## Inspect and download

The repository URL is the `url` from the normal HTTP readiness record. The API
has two routes:

| Method and suffix | Result |
| --- | --- |
| `GET /api/v1/artifacts/{id}` | Bounded JSON metadata after verification of the complete stored payload. |
| `GET /api/v1/artifacts/{id}/content` | The complete verified payload as a binary attachment. |

For example:

```sh
curl --fail --silent --show-error \
  -H "Authorization: Bearer $ARTIFACT_TOKEN" \
  "$REPOSITORY_URL/api/v1/artifacts/$ARTIFACT_ID"

curl --fail --silent --show-error \
  -H "Authorization: Bearer $ARTIFACT_TOKEN" \
  --output "$EXPORT_PARENT/selected-output.part" \
  "$REPOSITORY_URL/api/v1/artifacts/$ARTIFACT_ID/content"
```

Choose a new download destination. A network interruption can leave a partial
client file even though the server verified the complete stored object. Require
successful HTTP completion and compare the downloaded length and raw SHA-256 to
the selected metadata or saved workflow receipt before installing or executing
it. Retrying a read uses the same ID; no idempotency key or workflow rerun is
needed. File execute permissions are not applied by the download endpoint.

The metadata representation is shared with MCP. It includes `artifact_id`,
`payload_sha256`, `payload_bytes`, original `media_type` and `kind`, complete
selected scope and its commitment, optional producer/check/source commitments,
and the exact canonical retention encoding. It records
`payload_verified: true`, `read_only: true`,
`provenance_authenticated: false`, `canonical_repository_published: false` and
`retention_enforced: false`. Retained producer and check fields are assertions;
they do not authenticate a producer, promote a failed job to success, authorize
a cache hit or publish a required check. The workflow journal and canonical
check admission remain the owners of execution and publication decisions.

Content always uses `application/octet-stream` and
`Content-Disposition: attachment; filename="artifact-{id}"`, even when stored
metadata says HTML. Metadata and content responses have exact `Content-Length`,
`Cache-Control: no-store`, `Vary: Authorization` and
`X-Content-Type-Options: nosniff`. These prevent the custody endpoint from turning
retained content into an active browser document. Successful reads return `200`
and close the connection after the framed response.

## Bounds and refusal behavior

This profile is limited to 64 MiB per payload, including metadata inspection.
The complete verified download is retained in bounded memory before any HTTP
success bytes escape; it is not an unverified stream. The service's existing
response bound can narrow this further. Existing finite request deadlines,
connection limits and the per-principal source-read quota also apply. Artifact
reads do not take a writer slot and never advance the canonical head.

Requests must use an explicit Bearer token and a bodyless `GET`. Empty or zero
`Content-Length` is allowed. Query parameters, extra path components, encoded or
uppercase IDs, `Expect`, `Git-Protocol` and `Idempotency-Key` are refused. There is
no listing, upload, delete, range/resume or client-selected scope API.

| HTTP status | Meaning |
| --- | --- |
| `400` | Invalid selector or request fields/body. |
| `401` | Missing, unknown or revoked Bearer token. |
| `403` | Artifact profile disabled or authenticated credential lacks `artifact-read`. |
| `404` | No such exact ID in the configured namespace, or a different repository route. |
| `405` | Unsupported method; `Allow: GET` is returned. |
| `408` | Request deadline or cancellation observed before the response. |
| `413` | Stored payload or response exceeds the finite selected bound. |
| `429` | Existing read quota exhausted; `Retry-After: 60` is returned. |
| `503` | Credential configuration, repository/incarnation, custody storage or integrity unavailable. |

Adapter refusals are bounded JSON with `type: "artifact_error"`, a stable code,
`read_only: true` and `outcome_unknown: false`. They never include host paths,
raw storage diagnostics or unverified payload bytes. A corrupt container refuses
both metadata and content; no payload prefix escapes before that refusal. A
failed response closes its repository read lane instead of reusing uncertain
output state. Retrying the same read remains safe.

Storage retention remains an explicit local custody policy. The endpoint does
not create garbage-collection roots, enforce TTL deletion or attest backup
coverage. See [Native immutable artifact commands](NATIVE_ARTIFACT_COMMANDS.md)
and [Local artifact storage](LOCAL_ARTIFACT_STORAGE.md) for local export,
container validation and retention semantics.

## Implementation coverage

`smart_http::server::artifacts` unit tests cover strict selectors and request
framing, independent grants, pre-lease quota refusal, output failure/retry,
deadline expiry, bounded responses and binary attachment headers.
`crates/fgit-node/tests/artifact_http.rs` drives a real TCP listener for SHA-1 and
SHA-256 repositories, checking exact metadata/bytes, live grant replacement,
Git-scope separation, all four namespace dimensions, corruption without a leaked
prefix, and restart without repository publication. CLI tests cover explicit
credential/root selection and preservation of the disabled default.
