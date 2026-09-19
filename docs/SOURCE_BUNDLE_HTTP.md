# Native repository bundles over authenticated HTTP

The source service exposes the existing pure-Rust bundle engine, not an alternate
Git store. This is Git-object/ref interchange under FG-058, not a Repository
Capsule, forge-state backup, account transfer, or completion of the full import /
export compatibility matrix. No external Git process runs in production.

## Export one selected snapshot

`POST {repository-route}/api/v1/source/bundle/export` accepts a fixed-length or
chunked `application/x-www-form-urlencoded` body. `object_format=sha1` or `sha256`
is required and must match the repository. The only other field is optional
`expected_head`, containing a previous response's `X-Fgit-Snapshot` token. A
changed head returns 409 rather than substituting another snapshot, including
when an intervening transaction changed only forge metadata.

The source service must be enabled and the credential must have `read` scope.
Receive, issue, PR and review grants do not imply this permission. Do not supply
an Idempotency-Key: export never seals or publishes a transaction. Credentials,
source-service switches and existing per-principal source quotas are reused.
The listener retains its loopback / external-TLS-termination deployment boundary.

The native engine selects all currently visible direct refs and their complete
Git object closure. Canonically hidden refs and objects reachable only from
hidden/deleted refs are not export roots. HEAD is only a transport hint. The
response is a binary `application/x-git-bundle` attachment, version 2 for SHA-1
or version 3 for SHA-256, with fixed Content-Length and no-store caching policy.
It is not JSON, a patch candidate, an incremental bundle, or an archive of host
files. The selected profile is bounded to 128 MiB plus the existing native pack,
object, reference, request deadline and configured response ceilings; it does
not promise streaming construction for an unbounded repository.

Response headers identify the tenant, repository, incarnation, object format,
exact source head, reusable snapshot token and SHA-256 of the whole artifact.
`X-Fgit-Read-Only: true` labels the operation, not a new authority capability.
The digest detects transport corruption; it is not an independent signature or
an authenticated backup root. Native construction, output bounds and digest finish
before success is emitted. Socket failure stops delivery and closes the session.

Example for an operator-configured TLS endpoint or protected loopback:

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_TOKEN}" \
  --data-urlencode 'object_format=sha1' \
  --dump-header repository.bundle.headers \
  --output repository.bundle \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/bundle/export"
```

## Verification boundary

`source_bundle_http` exercises real imported SHA-1/SHA-256 repositories, byte
comparison against the native exporter, fixed/chunked HTTP, snapshot conflicts,
independent grants, authentication before 100 Continue, and reopened-node
read-only behavior. Unit tests cover strict routes/forms and broken writers.
The implementation session did not have Rust/Cargo, so these Rust tests and
compilation have not been executed. No live-node, compatibility or release gate
is claimed from static inspection.

```bash
cargo test --locked -p fgit-node --test source_bundle_http
cargo test --locked -p fgit-node --lib smart_http::server::source
```
