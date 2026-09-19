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

## Atomic import into absent ref names

`POST {repository-route}/api/v1/source/bundle/import` accepts fixed-length or
chunked `multipart/form-data` containing exactly two nonempty parts: `command`
(`application/x-www-form-urlencoded`) and `bundle` (`application/x-git-bundle`
or `application/octet-stream`). The parts may occur in either order. Multipart
filenames are ignored, never opened or used as repository ref names.

The command has exactly these required fields:

- `object_format`: the destination repository's `sha1` or `sha256` format.
- `artifact_sha256`: 64 lowercase hex characters, SHA-256 of the exact bundle
  part. An encoding change requires its matching digest. This expectation is
  transport validation, not a signature, permission or transaction identity.

Source service enablement, `allow_receive`, an independently granted `receive`
credential and an explicit `Idempotency-Key` are all required. A read grant does
not permit import. Authentication, route/incarnation binding, intake ceilings
and mutation quota are checked before 100 Continue or retaining an upload.

A fresh import creates **every** advertised direct ref under an expected-absent
lease and publishes them through one native atomic admission. Existing names
are not overwritten, even when their tip already equals the offered object.
One conflicting destination refuses the whole ref set; it cannot publish a
prefix of the import. The native engine verifies the self-contained pack and
all selected native object edges before admitting it. No preexisting object is
borrowed to turn an incomplete bundle into a valid full import. Bundle HEAD does
not rewrite default-branch configuration; forge metadata, accounts, policy and
credentials are not imported.

For example, with the operator's exact digest in `FG_BUNDLE_SHA256`:

```bash
curl --fail-with-body --silent --show-error \
  -H "Authorization: Bearer ${FG_WRITE_TOKEN}" \
  -H "Idempotency-Key: ${FG_TRANSFER_KEY}" \
  -F "command=object_format=sha1&artifact_sha256=${FG_BUNDLE_SHA256};type=application/x-www-form-urlencoded" \
  -F 'bundle=@repository.bundle;type=application/x-git-bundle' \
  "${FG_URL}${FG_REPOSITORY_ROUTE}/api/v1/source/bundle/import"
```

## Mapped fetch with exact old-tip leases

`POST {repository-route}/api/v1/source/bundle/fetch` uses the same authentication,
key, upload and artifact requirements. The command also requires 1–64 repeated
`mapping` fields. Each value is exactly:

```text
<source-ref-lowercase-hex>:<destination-ref-lowercase-hex>:<old-native-oid-or-absent>
```

Both ref names are lossless hexadecimal encodings of their complete raw `refs/`
name. Destinations must be branches, remote-tracking refs or tags. `absent`
explicitly requires an absent destination; otherwise the final component is
the complete, nonzero, lowercase SHA-1/SHA-256 old tip. Zero OIDs, omitted leases,
wildcards, duplicate destinations and unknown fields refuse. One advertised
source may feed multiple distinct destinations. Source refs and exact native
targets are selected from the submitted bundle, not from host paths or a URL.

Only mapped refs and their selected object closure enter the destination.
Unselected refs and their exclusive objects are not imported. Updates to
branches/remote-tracking refs must fast-forward; tags may be created or
reasserted but not replaced. The native engine retains hidden-ref restrictions,
repository protection and exact-basis admission. There is no implicit force,
prune, ref deletion, fresh-tip lookup or default-branch rewrite. All mappings
share one atomic terminal decision.

## Write limits, receipts and retry recovery

The upload deliberately retains the existing candidate/source multipart limits:
**64 MiB of bundle payload**, 256 KiB of command data, and 16 KiB of MIME overhead,
further narrowed by configured HTTP/native pack and admission limits. This is
smaller than the export engine's 128 MiB ceiling: an export above 64 MiB is not
accepted by these HTTP write endpoints. No shared review/candidate intake
ceiling is silently widened. Streaming construction or unbounded repository
migration is not implemented by this profile. Incremental/prerequisite bundles
and unsupported bundle capabilities refuse on these full-bundle endpoints.

Complete HTTP and multipart framing, the command grammar, artifact digest and
bundle envelope precede native intake. The service does not compute or refresh
current destination expectations before calling the native engine. Native
terminal lookup for the exact semantic request precedes fresh object validation
and current-ref checks; retrying a successful expected-absent import or an older
fetch cannot reinterpret its leases against later destination state. A different
semantic request with the same principal/key is rejected, not another mutation.

A returned `source_bundle_publication` JSON receipt identifies the destination
scope, principal, operation, transaction, decision sequence, command count and
one atomic terminal outcome. HTTP 200 reports `committed`; a canonical refusal
uses HTTP 409 and includes its refusal identity/code. A pre-decision
`idempotency_key_reuse` rejection is also 409 but is not a terminal receipt.
The receipt states that forge/default-branch state was not transferred and does
not claim the transport was revalidated on terminal replay. It carries the
native transaction result, not an inference from object placement.

Invalid uploads return request errors, not canonical refusal receipts.
Infrastructure failures after native intake may return 503 `outcome_unknown`;
the gateway conservatively retains this classification for native failures not
known to be pre-decision rejections. A missing response, timeout, or disconnected
client never proves rollback. Reuse the **original key and semantic command** to
resolve/retry, or use the existing independently authorized outcome endpoint.
Do not substitute a new key after an ambiguous response. A canonical outcome
that was returned by the node wins over a subsequent transport timeout, and
receipt-delivery failure retains the transaction for recovery.

## Verification boundary

`source_bundle_http` exercises real imported SHA-1/SHA-256 repositories, byte
comparison against the native exporter, fixed/chunked HTTP, snapshot conflicts,
independent grants, authentication before 100 Continue, and reopened-node
read-only behavior. Import/fetch integration tests cover two-ref atomic transfer,
collision refusal with no ref prefix, mapped-only object admission, fast-forward
leases, corrupt native pack checks despite a correct transport digest, valid
retry, and original-key recovery after a disconnected response. Unit tests cover
strict routes/forms/mappings, artifact expectations, uncertainty and broken writers.
The implementation session did not have Rust/Cargo, so these Rust tests and
compilation have not been executed. No live-node, compatibility or release gate
is claimed from static inspection.

```bash
cargo test --locked -p fgit-node --test source_bundle_http
cargo test --locked -p fgit-node --lib smart_http::server::source
```
