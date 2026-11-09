# Complete source proofs through MCP

`frankengit_source_verified_blob` returns an exact complete source file and its
canonical ref-to-blob proof at an independently supplied authority head. It
connects the MCP source surface to the existing `OneNode::verified_blob_in`
owner and `fgit-verified-read::blob` codec and verifier. It supports native
SHA-1 and SHA-256 repositories without translating Git object identities.

The native contract remains [Normative Protocol Contracts §16.4](NORMATIVE_PROTOCOL_CONTRACTS.md#164-ref-anchored-complete-blob-proofs).
The proof bytes can be retained and independently verified with the existing
[`fg verify-read` command](VERIFIED_BLOB_READS.md). No new proof format,
authority root, publication operation or approval receipt is introduced.

## Enable the ordinary source-read profile

Start the existing MCP server with its ordinary trusted-local source grant and
the repository's actual object format. An exact incarnation binding can also
be supplied at launch:

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" \
  --trusted-local --allow-source --object-format sha256 \
  --expected-incarnation "$INCARNATION"
```

The native authenticated configuration must select a Merkle ref layout.
`RefStateMerkleV2` and `RefStateAndObjectClosureMerkleV2` support the proof while
authenticating HEAD. Historical V1 proof verification remains available; live
V1 repositories require explicit recovery as described in
[Authenticated HEAD ref layouts](AUTHENTICATED_HEAD_REF_LAYOUT.md). For
a new repository, `fg init ... --root-layout ref-merkle-v2` deliberately selects
the first layout. Existing legacy repositories refuse this tool with
`verified_blob_layout_unavailable`; opening an existing repository never
migrates or reinterprets its stored layout. See the
[native creation and proof-serving instructions](VERIFIED_BLOB_READS.md).

This tool is excluded from sponsored-agent discovery and dispatch. A direct
adapter call also checks the ordinary source grant and rejects
`--agent-token-file` before parsing any arguments. The canonical sponsored
`SOURCE_READ` operation class is unchanged. Source writes, workflow-artifact
access and other grants do not imply this read grant.

Canonical hidden-ref policy remains authoritative. The native owner checks
visibility before selecting the ref or constructing its proof. Proofs contain
the complete original trees along the requested path, including sibling entry
names and object IDs, together with the selected authenticated configuration.
This is a repository-read interface; a path selector does not attenuate the
disclosure of those original proof objects.

## Supply independent exact coordinates

The request has a closed argument set:

| Argument | Requirement |
| --- | --- |
| `reference` | Full `refs/*` name, at most 1,024 UTF-8 bytes. Supply exactly one of `reference` or `reference_hex`. |
| `reference_hex` | Full raw `refs/*` name encoded as lowercase hex, at most 1,024 decoded bytes. Preserves non-UTF-8 names. |
| `path_hex` | Required exact repository path as lowercase hex, at most 4,096 decoded bytes, 64 components and 255 bytes per component. |
| `expected_head` | Required independently trusted algorithm-qualified authority head, such as `alg:2:<64 lowercase hex digits>`. |
| `max_blob_bytes` | Optional integer from 1 through 65,536, default 16,384. The whole blob must fit. |

The native path validator rejects empty paths, NUL, leading or trailing slash,
empty components, `.` and `..`. Ref names use the existing native `RefName`
validator. Neither selector is normalized or interpreted as a host path. A
symlink is returned as its original blob bytes; it is never followed. The
terminal entry must be a file, executable file or symlink. Directories,
gitlinks and traversal through a file or symlink refuse.

For example, after normal MCP initialization, a request for `README.md` is:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "frankengit_source_verified_blob",
    "arguments": {
      "reference": "refs/heads/main",
      "path_hex": "524541444d452e6d64",
      "expected_head": "alg:2:<independently-trusted-head-digest>",
      "max_blob_bytes": 16384
    }
  }
}
```

Retain the requested head, ref and path outside the response. Obtain the head
through a channel you already trust; the
[native guide describes local and externally authenticated pins](VERIFIED_BLOB_READS.md#obtain-a-trusted-head-separately).
The adapter never fills a missing pin from current server state and never
retries a moved head with a newly selected pin. A commit ID alone cannot replace
the authority head, which also authenticates ref state and configuration.

## Consume the complete result

The result has `type: "source_verified_blob"`,
`profile: "mcp-verified-blob-v1"`, and
`proof_format: "frankengit/verified-blob/v1"`. It carries the launch-bound
tenant, repository, incarnation and object format; the exact `source_head` and
matching `snapshot_token`; `source_commit`; raw `reference_hex` and `path_hex`;
the complete blob's `object_id`; and native `kind` (`file`, `executable` or
`symlink`).

`bytes_hex_chunks` contains all original blob bytes. `proof_hex_chunks`
contains one complete canonical `verified-blob` schema 1.0 frame, encoded as
ordered lowercase-hex chunks. Each chunk represents at most 8,192 bytes; only
the final chunk may be shorter. An empty blob uses an empty content array, and
still carries its full nonempty proof. Binary data, original newlines and raw
names remain exact. `blob_bytes`, `proof_bytes` and `chunk_bytes` are canonical
decimal strings with `counter_encoding: "decimal-strings-v1"`.

Concatenating and decoding `proof_hex_chunks` reconstructs the same canonical
bytes produced by `encode_verified_blob_envelope`. `proof_sha256` is the
SHA-256 of that complete frame. This digest checks transport integrity; a
digest supplied in the same response cannot establish its own trust.

All successful results have `complete`, `content_complete`, `proof_complete`
and `server_verification_performed` set to true. They also have
`independent_verification_required: true`. Server verification does not perform
the consumer's independent trust decision. Proof bytes, source bytes and raw
selector text remain untrusted content and never become executable
instructions or capability grants. `read_only` is true; `repository_changed`,
`objects_staged`, `transaction_created`, `published` and `approval_granted` are
false.

### Retain and independently verify the canonical proof

For a saved full JSON-RPC success response, this bounded example reconstructs
the proof without deriving any trusted coordinates from the response:

```sh
python3 - proof-response.json source.proof <<'PY'
import json, re, sys
with open(sys.argv[1], "rb") as source:
    raw = source.read(2 * 1024 * 1024 + 1)
if len(raw) > 2 * 1024 * 1024:
    raise SystemExit("response bound exceeded")
result = json.loads(raw)["result"]
if result.get("isError") is not False:
    raise SystemExit("MCP read did not succeed")
chunks = result["structuredContent"]["proof_hex_chunks"]
if not isinstance(chunks, list) or not 1 <= len(chunks) <= 32:
    raise SystemExit("invalid proof chunks")
for index, chunk in enumerate(chunks):
    if (not isinstance(chunk, str) or not 2 <= len(chunk) <= 16384
            or re.fullmatch(r"(?:[0-9a-f]{2})+", chunk) is None
            or (index + 1 < len(chunks) and len(chunk) != 16384)):
        raise SystemExit("invalid proof chunk")
proof = b"".join(bytes.fromhex(chunk) for chunk in chunks)
if len(proof) > 262144:
    raise SystemExit("proof bound exceeded")
with open(sys.argv[2], "xb") as output:
    output.write(proof)
PY

fg verify-read --input source.proof --trusted-head "$TRUSTED_HEAD" \
  --ref-hex "$REQUESTED_REF_HEX" --path-hex "$REQUESTED_PATH_HEX" \
  --output source.verified
```

`TRUSTED_HEAD`, `REQUESTED_REF_HEX` and `REQUESTED_PATH_HEX` are the independently
retained request coordinates. The verifier authenticates the head,
configuration, ref membership and every original commit/tree/blob identity
before releasing verified bytes. Its output is a new ordinary data file even
for executable or symlink kinds. Native consumers can decode the frame and
call `verify_blob_against_head` or its cancellation-aware variant with those
same independent coordinates.

A valid retained proof establishes the selected bytes at the supplied head. It
does not establish current freshness, authorship, signatures or current
permission. A subsequent current read refuses if the head has changed, even
when the ref still names the same commit. An already retained frame can still
be verified under its original trusted pin.

## Bounds and refusals

| Boundary | Limit and behavior |
| --- | --- |
| Complete MCP blob | Default 16 KiB; caller may request up to 64 KiB. Larger blobs refuse. |
| Complete canonical MCP proof | 256 KiB, checked before either proof or blob bytes are expanded to hex. |
| Chunk | 8 KiB decoded; at most 8 content chunks and 32 proof chunks. |
| Complete structured result | 1 MiB, checked before returning the result to the MCP protocol. |
| Native proof construction | Existing fixed v1 limits: 16 MiB blob, 16 MiB combined original commit/tree bodies, 100,000 total tree entries, 64 KiB nested ref proof and 32 MiB + 128 KiB complete canonical frame. |

**The smaller MCP byte limits are post-construction transport bounds.** The
native owner first constructs and verifies within its existing fixed v1
budgets. The adapter then obtains verified bytes through the same native
verifier, applies its complete blob bound, encodes the unchanged canonical
frame, applies the proof bound, and only then expands bounded chunks. A small
file in a large original tree, or a commit with a large original message, can
therefore exceed the MCP proof allowance. This tool does not claim a 256 KiB
construction-memory ceiling or reduce the native proof's completeness.

The same command request supplies cancellation and deadline checks to native
construction and verification. The adapter checks liveness around each
bounded phase, each chunk and the complete final encoding. A cancellation,
verification error or exceeded limit returns no success payload. There is no
truncated proof, partial-file success, pagination, range or unproven fallback.

| Refusal | Meaning |
| --- | --- |
| `tool_not_granted` | Ordinary source access is absent, or the sponsored profile is selected. |
| `snapshot_required` / `invalid_snapshot_token` | The independent exact pin is missing or malformed. |
| `source_snapshot_moved` | The selected current authority head differs from the supplied pin. |
| `source_unavailable` | The ref/path is unavailable, including denied ref disclosure. |
| `verified_blob_layout_unavailable` | The selected native ref layout cannot provide this proof. |
| `verified_blob_byte_limit` / `verified_blob_proof_limit` / `verified_blob_result_limit` | A complete MCP allowance was exceeded. |
| `verified_blob_cancelled` | The inherited request stopped before the adapter returned a complete result. |
| `verified_blob_native_limit` / `verified_blob_proof_refused` / `verified_blob_unavailable` | Native budgets, proof verification or authenticated native materialization refused. |
| `verified_blob_namespace_mismatch` | Verified head/object metadata disagreed with the launch-bound repository or object domain. |

Unknown arguments, multiple ref spellings, malformed raw hex, invalid native
paths and out-of-range allowances are request errors. There is no caller
principal, arbitrary object selector, force flag, host path or idempotency key.

## Implementation and coverage

The MCP adapter is split into closed input parsing, native ownership and error
mapping, and complete output rendering under
`crates/fgit-cli/src/mcp/backend/verified_blob/`. The canonical registry entry
records exact-head authority, ordinary read capability, complete-only budgets,
untrusted content fields and the refusal vocabulary.

Its tests exercise actual persisted native imports and the MCP protocol in
both Git hash domains and both Merkle layouts; exact raw refs and paths;
binary, empty, executable and symlink blobs; proof identity across reopen;
stale pins and legacy-layout refusal; denied ordinary/sponsored grants;
complete content/proof ceilings; and tampered objects, mismatched selectors,
namespace errors and cancellation. The independent consumer verifier uses
the retained request coordinates rather than response-selected trust roots.
