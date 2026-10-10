# Independently pinned, complete blob reads

`fg verify-read` verifies a complete repository file against a head commitment
supplied independently by the caller. It accepts a canonical proof file or
fetches a proof from the authenticated native HTTP service. It releases blob
bytes only after checking the exact head, reference, path, and every native Git
object identity needed to reach that file. Both SHA-1 and SHA-256 repositories
are supported without translating their native object IDs.

The wire contract is [Normative Protocol Contracts §16.4](NORMATIVE_PROTOCOL_CONTRACTS.md#164-ref-anchored-complete-blob-proofs).
`fgit-verified-read::blob` owns the bounded codec and verifier;
`OneNode::verified_blob_in` owns proof construction from one selected native
authority basis. The HTTP and CLI adapters do not introduce another authority
root or trust a head merely because it arrived with a response.

## Create a repository with the required ref layout

The inclusion proof requires a Merkle ref layout. Choose it explicitly when
creating a **new** repository:

```sh
fg init "$STORAGE" "$TENANT" "$REPOSITORY" sha256 \
  --root-layout ref-merkle-v1

fg import "$STORAGE" "$TENANT" "$REPOSITORY" "$PRINCIPAL" \
  initial-source "$SOURCE_GIT_DIRECTORY"
```

`--root-layout legacy` is also accepted. Omitting the option preserves the
existing legacy default. The selected layout is committed in repository
configuration and retained on reopen. The option also works with
`--creation-idempotency-key`; an exact retry must retain the original layout.
It does not migrate an existing repository or reinterpret a historical root.
An existing legacy repository returns the typed HTTP 409
`verified_blob_layout_unavailable` when asked for this proof profile.

## Obtain a trusted head separately

The required `--trusted-head` is an exact algorithm-qualified authority-head
commitment, such as `alg:1:<64 lowercase hexadecimal characters>`. It must come
from a source the caller already trusts. A response's own head body is evidence
to verify against this pin, not a reason to trust that pin.

For a local operator who already trusts the node storage, a separate native
source read can supply the pin. This example assumes the imported ref contains
`README.md` and uses the repository's actual object format:

```sh
fg show "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --object-format sha256 --ref refs/heads/main --path README.md \
  --max-bytes 1 > trusted-source.json

PIN=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["snapshot_token"])' \
  < trusted-source.json)
```

An embedding can instead distribute the independently authenticated head ID
through its own trusted channel. The CLI has no automatic head discovery or
“trust the latest response” option. A commit ID alone cannot replace the head
commitment because the head also selects repository configuration and ref state.

## Enable authenticated proof serving

Proof requests use the existing source-read deployment switch and repository
`read` credential grant. See [the source HTTP profile](HTTP_SOURCE_API.md#enable-source-access-deliberately)
for credential rotation and the incarnation-bound credential table. A receive
or metadata grant does not imply source read access.

For new private credential files, the following creates a read-only token and
binds its hash to the chosen principal. The credential parent directory must
already be controlled by the operator, and the token file must not exist:

```sh
umask 077
fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --print-credentials-header > "$CREDENTIALS"

python3 - "$READER_TOKEN" "$CREDENTIALS" "$PRINCIPAL" <<'PY'
import hashlib, pathlib, secrets, sys
token = secrets.token_hex(32)
with pathlib.Path(sys.argv[1]).open("x") as output:
    output.write(token + "\n")
with pathlib.Path(sys.argv[2]).open("a") as output:
    output.write(f"{hashlib.sha256(token.encode()).hexdigest()} {sys.argv[3]} read\n")
PY

fg serve-http "$STORAGE" "$TENANT" "$REPOSITORY" 127.0.0.1:8080 \
  --trusted-local --credentials-file "$CREDENTIALS" --allow-source \
  --continuous --stop-file "$STOP_FILE"
```

Take `REPO_URL` from the server's `smart_http_listening` record. The stop file
must initially be absent; creating it requests the existing bounded service
drain. Static-token Git-only serving does not enable source endpoints.

HTTP source credentials authorize repository reads, subject to current
canonical hidden-ref policy. A proof contains complete original trees along
the selected path, including sibling entry names and OIDs in those trees.
This is therefore a repository-read interface, not a path-attenuated
`TreeCapability` endpoint. Denied refs are refused before their object proof is
constructed or disclosed. Hidden and absent selections do not produce absence
proofs.

## Fetch and verify exact bytes

```sh
fg --timeout-secs 60 verify-read --url "$REPO_URL" \
  --token-file "$READER_TOKEN" --trusted-head "$PIN" \
  --ref refs/heads/main --path README.md --output README.verified
```

The URL must be explicit numeric-loopback HTTP, for example
`http://127.0.0.1:8080/repository.git` or `http://[::1]:8080/repository.git`.
The client owns one bounded TCP connection. It does not resolve DNS, follow
redirects, downgrade HTTPS, use ambient credentials, or send the token to a
second origin. A remote TLS deployment needs a separate client or an explicitly
managed local gateway; this command implements the native loopback profile.

`--token-file` is required in URL mode and forbidden in input-file mode. It
contains exactly 64 lowercase hexadecimal characters, optionally followed by
one LF or CRLF. The file must be regular; on Unix it must have no group or other
permission bits. The client checks opened-file and path metadata before and
after reading and refuses detectable replacement or modification.

Without `--output`, stdout is the exact verified blob bytes, including NUL,
non-UTF-8 data, original newlines, and an absent final newline. No receipt is
mixed into that stream. Use `--path-hex` or `--ref-hex` for raw byte names;
exactly one text or hex spelling is required for each. Hex is lowercase.

`--output` creates a new regular file without replacing an existing path, then
emits a JSON receipt containing `verified: true`, `output_state: "published"`,
`source_head`, `source_commit`, `object_id`, native `kind`, byte count, and output
path. Executable and symlink kinds remain explicit in the receipt, but the
command writes an ordinary data file. It neither sets executable permissions
nor creates or follows a symlink.

## The binary HTTP endpoint and saved proof files

```text
GET {REPO_URL}/api/v1/source/verified-blob?ref_hex=HEX&path_hex=HEX&expected_head=PIN
Authorization: Bearer TOKEN
```

All three query fields are mandatory and must occur once. Unknown fields,
`Idempotency-Key`, `Git-Protocol`, a content type, a nonempty request body, and
methods other than GET are refused. There is no arbitrary-object selector or
historical `mode` field. Authorization still comes from the credential grant,
never the query or a forwarded identity header.

Successful replies use `application/vnd.frankengit.verified-blob` with one
bounded `Content-Length`, `Connection: close`, and `Cache-Control: no-store`.
The complete proof is built before the success header. The CLI rejects
ambiguous lengths, duplicate headers, chunked or compressed responses,
redirects, truncated bodies, and trailing bytes. HTTP failure bodies cannot
provide a trusted head or be mistaken for a proof.

A client can preserve the canonical response body and verify it later:

```sh
fg verify-read --input source.proof --trusted-head "$PIN" \
  --ref refs/heads/main --path README.md --output README.offline
```

The input must be a bounded regular canonical proof file, not a JSON source
response, a raw blob, or a pack. It is read with deadline and stable-file checks.
Native embeddings can call `encode_verified_blob_envelope` to save the result
of `OneNode::verified_blob_in`, or use `decode_verified_blob_envelope` followed
by `verify_blob_against_head` with their independently selected head, ref, and
path. The cancellation-aware verifier accepts a caller-owned liveness callback.

## What verification establishes

The verifier rehashes the returned authority-head body and requires equality
with the independent pin. It authenticates the selected repository
configuration and exact ref inclusion under that head, then verifies the
original commit body, every original tree body in root-to-parent order, and
the complete blob in the selected native Git hash domain. Each path component
must select one child; intermediate entries must be directories. Partial byte
ranges, missing or extra tree bodies, ambiguous commit trees, wrong domains,
directories, and gitlinks cannot satisfy the blob profile.

Paths remain repository byte paths. Empty, absolute, repeated-slash, `.` or
`..` components, NUL, and over-limit components are refused. No Unicode or host
path normalization substitutes another path. Symlink contents are literal
bytes and cannot redirect traversal.

The current HTTP endpoint requires the supplied head to equal its current
selected authority basis. Any canonical head movement, even with an unchanged
branch tip, causes HTTP 409. The client must obtain a new independent pin
before requesting current content again. An old file proof can still verify
under its explicitly trusted old pin; it cannot answer a different new pin.
Cryptographic validity at that head does not establish present freshness,
authorship, signatures, or current access permission. Retained historical proof
serving and browser D2 integration are separate work.

## Bounds and output outcomes

| Resource | Closed limit |
|---|---:|
| Complete canonical proof frame | 32 MiB + 128 KiB |
| Complete blob | 16 MiB |
| Original commit and all tree bodies combined | 16 MiB |
| Nested canonical ref proof | 64 KiB |
| Tree entries across all original tree bodies | 100,000 |
| Native path | 4,096 bytes, 64 components, 255 bytes per component |
| Reference bytes | 1,024 |
| HTTP request target, including route and complete query | 4,096 encoded bytes |
| HTTP response headers | 16 KiB, 64 fields, 4,096 bytes per field |

Hex encoding doubles reference and path byte lengths. A valid native path can
therefore exceed the HTTP target ceiling; the CLI preflights the exact target
before connecting or sending credentials and returns `http_target_limit`.
File/native verification retains the full 4,096-byte path limit. The endpoint
also respects the server's configured response and native object ceilings,
which may be lower than the proof profile. Tree witness size is linear in the
original traversed tree bytes; this profile does not invent an OID-preserving
logarithmic proof for a native Git tree.

The command returns exit 0 only after verified output and flush succeed. Exit 2
emits a typed `verified_read_error` JSON record on stderr. `verified` records
whether the complete proof succeeded; `output_state` separately reports `none`
before verification, `not_published` when a new output file was not created,
`published` when the complete file became visible, or `partial_or_unwritten`
after a stdout output failure. A failed receipt or temporary-file cleanup after
publication retains `verified: true` and `output_state: "published"`.

The global timeout covers file or HTTP input, verification, and output
checkpoints. Regular-file reads, hashing, staging, and stdout output use bounded
chunks. Before the create-only output link, cancellation removes only the
private staging file. File publication synchronizes completed file contents;
it does not claim parent-directory synchronization or crash durability.
Filesystem operations and a blocked output write are cooperative boundaries,
not preemptible I/O. No failed proof writes any blob bytes, while a later output
failure can leave a verified prefix on stdout or a complete published file.

## Verification entry points

```sh
cargo test -p fgit-verified-read --lib blob
cargo test -p fgit-node --lib smart_http::server::source::verified_blob
cargo test -p fgit-node --test verified_blob --test verified_blob_http
cargo test -p fgit-cli --bin fg verify_read
cargo test -p fgit-cli --lib init_root_layout

FG_BIN=/absolute/path/to/prebuilt/fg \
  scripts/e2e/suites/verify/verified_blob_http.sh
```

The node TCP tests use real imported native objects in both hash formats,
including binary/raw-name files, nested paths, empty and executable files,
symlink data, grant denial, stale pins, legacy-layout refusal, and unchanged
authority after reads. CLI tests exercise complete verification before output,
tamper refusal, exact query/credential transport, framing, target limits,
create-only publication, cancellation cleanup, and receipt write/flush failures.

The discovered E2E suite uses the real prebuilt `fg serve-http` and
`fg verify-read` processes. Its pin comes from a separate trusted-local native
read. It records proof size and client process timing for SHA-1, SHA-256, and a
10,000-entry SHA-256 tree, refuses tampered proofs and stale pins, exercises
file verification, and requires server drain. Test presence and syntax checks
do not establish an executed pass; attach actual revision-specific results.
