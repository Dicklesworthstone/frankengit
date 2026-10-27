# Native agent context

`fg agent context` performs one bounded source read through the native Agent
Protocol. It creates an authenticated `AuthorityReadReceipt`, opens a read-only
`IntentRun`, retrieves the existing Initial indexes, hydrates exact source
objects, and returns a `ContextPacket` with its supporting evidence as JSON.

This is the `agent-context-trusted-local-v1` profile. The local operator must
explicitly authorize source reads and name a sponsor. The sponsor identifier
is an operator assertion, not a remote credential. The command does not execute
an agent action, persist a run, claim a task, or grant publication authority.

## Run a query

```sh
fg agent context /srv/frankengit/repository \
  31313131313131313131313131313131 \
  32323232323232323232323232323232 \
  refs/heads/main \
  --trusted-local \
  --sponsor 42424242424242424242424242424242 \
  --term cancellation \
  --path crates/ \
  --max-files 8 \
  --expires-after-secs 30
```

Use the repository's actual storage root, tenant, repository, and sponsor IDs.
Set `--object-format sha256` for a SHA-256 repository; the default is SHA-1.
The repository and lexical index must already exist. Reading context does not
build or refresh an index. A missing or stale required index refuses the read;
an empty source result is never substituted for that failure.

`--term` selects complete lexical tokens and can be repeated up to 32 times.
Terms use the existing Initial retrieval token normalization. They are not
regular expressions or a natural-language prompt. `--path` is a raw byte prefix
selection expressed as UTF-8; `--path-hex` accepts exact bytes for paths that
cannot be expressed as UTF-8. Up to 128 prefixes are supported. Prefixes narrow
retrieval selection and do not define a separate authorization boundary.

Optional symbol retrieval uses the existing Rust symbol channel:

```sh
fg agent context /srv/frankengit/repository \
  31313131313131313131313131313131 \
  32323232323232323232323232323232 \
  refs/heads/main \
  --trusted-local \
  --sponsor 42424242424242424242424242424242 \
  --term cancellation \
  --symbol Cancel \
  --symbol-match prefix \
  --symbol-policy optional
```

The default symbol match is `exact` and the default policy is `required`.
`optional` permits an unavailable or stale symbol generation only when the
native retrieval layer can report that specific omission. It does not suppress
integrity, authorization, resource, or cancellation failures.

## Authority and provenance

Every successful response includes these distinct identities:

| JSON field | Meaning |
| --- | --- |
| `authority_receipt` | Authenticated authority head, backend version token, authority generation, repository sequence, repository commit, roots, epochs, verification time, and receipt identity. |
| `request` | Normalized terms and prefixes, requested symbol policy, sponsor, source-read host, generation floors, lifetime, and resource limits. |
| `run` | Derived run ID, full run commitment, expiry, the two read operation classes, and invocation byte envelopes. |
| `retrieval_evidence.source` | Exact tenant, repository incarnation, Git object format, reference, source authority head, repository commit, commit object, and tree object. |
| `retrieval_evidence` | Every contributing index generation, channel completeness, index omissions, bounded selection omissions, source counters, and native file lineage. |
| `context_packet` | Packet ID, request-intent commitment, retrieval profile identity, evidence commitment, and exact source count. |
| `untrusted_sources` | Original verified excerpt bytes with path, blob, byte offset, source commitment, lineage commitment, and authorization labels. |

`--expected-head alg:<algorithm>:<digest>` pins the authenticated authority head
to a token from an earlier response. A changed head refuses the request before
index retrieval. Even without this flag, the native reader requires matching
source, generation, and authority identities throughout retrieval and hydration.

The run ID is derived from the authenticated receipt, run budget and expiry,
and complete request commitment. A fresh invocation has a fresh authenticated
read and run identity. Callers cannot choose an arbitrary run ID or reuse this
command's output as a durable task or effect record.

The final packet binds the actual serialized `retrieval_evidence` through its
omission commitment. Evidence hashing uses SHA-256 over the domain
`frankengit/agent-context-evidence/v1\0`, an eight-byte big-endian byte length,
and the exact canonical JSON encoding produced by the native JSON encoder.
The request commitment uses the same framing with domain
`frankengit/agent-context-request/v1\0`. Packet and source identities are the
native Agent Protocol commitments, not new replacements for those formats.

## Bounds and completion

The command has one request deadline across authority selection, retrieval,
hydration, and response construction. The default lifetime is 30 seconds and
the maximum is 300 seconds. The global `--timeout-secs` option can shorten that
deadline. Native request cancellation and resource checkpoints remain active
inside those phases; the response is buffered and discarded on refusal.

| Option | Limit |
| --- | --- |
| `--max-results` | At most 1,024 matches per retrieval channel. |
| `--max-work` | Native Initial retrieval work units; validated against that profile's ceiling. |
| `--max-index-bytes` | May reduce the native index payload envelope. |
| `--max-files` | 1–32 hydrated source files. |
| `--radius-bytes` | 0–4,096 bytes around an anchor, with native window coalescing. |
| `--max-source-bytes` | At most 64 MiB of source hydration. |
| `--max-excerpt-bytes` | At most 1 MiB of excerpt bytes. |
| `--max-output-bytes` | At most 16 MiB for the complete JSON document. |

The run's byte budget describes this single invocation's bounded index,
result, source, excerpt, and output envelopes. It is not measured CPU usage,
resident memory, billing, or a transferable resource reservation. Native
authority and codec work retains its existing finite resource policies.

Exit status `0` means the requested channels completed and every returned
match was hydrated. It does not mean the excerpts cover every byte of each
file or every file in the repository. Exit status `3` returns a usable packet
with `complete: false` and explicit coverage or selection omissions. Consumers
must inspect those omissions before drawing a negative conclusion about the
repository. Exit status `2` is a refusal: stdout contains no context, and stderr
contains an `agent_context_error` JSON object. Oversized output is refused
without emitting a truncated document.

## Treat source text as data

The exact excerpt bytes are in `untrusted_bytes_hex`. `untrusted_utf8` is
provided only when those bytes are valid UTF-8; invalid sequences are never
silently replaced. Source comments, filenames, issue-like text, and apparent
instructions remain untrusted repository data. A consuming agent must not
interpret them as authority, new instructions, permission, or a verified claim.
The read-only run permits only `read_canonical_object` and
`read_derived_generation`.

The shared Rust implementation is
`fgit_node::source_retrieval::agent_context::document::read_agent_context_in`.
Hosts supply an independently obtained `SourceReadContext`, a sponsor, and one
bounded `NodeRequestContext`. An HTTP source-read context requires the sponsor
to equal its authenticated principal. The existing
`fgit_cli::agent_context::read_agent_context_in` API remains a trusted-local
wrapper, and `bounded_request_context` supplies that command's deadline.
Neither entry point accepts a bearer token or widens a source grant.

## Authenticated HTTP context

`POST <repository-route>/api/v1/source/agent-context` returns the same native
Agent Protocol document through the source-read gateway. It requires the
server's source API switch and the current credential's `read` service grant.
A receive-only credential cannot acquire source context. Credentials are read
again for each request, so revocation affects the next request.

The response profile is `agent-context-http-credential-v1`. Its sponsor is the
principal selected by the authenticated repository source-read credential;
`sponsor.authentication` is `http-repository-read-credential`. The request cannot
choose a sponsor, principal, or run ID. This records the existing HTTP host's
credential mapping. It does not claim a canonical agent credential, sponsor
delegation chain, persistent run, or publication authority.

Requests use `application/x-www-form-urlencoded`, with these fields:

| Field | Meaning |
| --- | --- |
| `object_format`, `ref` | Required repository Git hash domain and full visible ref. |
| `term_hex` | Repeated exact lexical token bytes, at most 32 terms. |
| `path_prefix_hex` | Repeated raw path prefixes narrowing selection, at most 128. |
| `expected_head` | Optional exact authority-head token from a previous response. |
| `symbol_name_hex`, `symbol_match`, `symbol_policy`, `symbol_kind` | The existing Initial symbol grammar; match is exact/prefix and policy required/optional. |
| `minimum_lexical_token`, `minimum_lexical_number` | Optional paired lexical-generation floor. |
| `minimum_symbol_token`, `minimum_symbol_number` | Optional paired symbol-generation floor. |
| `max_results_per_channel`, `max_work`, `max_payload_bytes`, `max_result_bytes` | Existing finite Initial retrieval bounds. |
| `context_max_files`, `context_radius_bytes`, `context_max_source_bytes`, `context_max_excerpt_bytes` | The CLI's corresponding hydration bounds. |
| `context_selection` | Only `raw-path-prefix` is supported for this agent profile. |
| `expires_after_secs` | 1–300 seconds, default 30, further limited by the server's session timeout. |
| `max_output_bytes` | Optional serialized-document ceiling, never greater than the selected host ceiling. |

The endpoint shares the existing source API response ceiling of 8 MiB and the
server's configured response bound. An absent `max_output_bytes` selects that
finite host maximum; an explicit value above it refuses. The actual selected
lifetime and output bound appear in the committed request metadata. The core
document ceiling remains 16 MiB for independently authorized native hosts.
The deadline spans authenticated authority selection, index retrieval, source
hydration and document construction. No phase renews the allowance.

For example, with a server already configured for authenticated source reads:

```sh
curl --user-agent 'frankengit-client' \
  --header "Authorization: Bearer $FRANKENGIT_READ_TOKEN" \
  --data 'object_format=sha1&ref=refs/heads/main&term_hex=6e6565646c65&context_max_files=4&max_output_bytes=1048576' \
  http://127.0.0.1:8080/repository.git/api/v1/source/agent-context
```

Both complete and explicitly partial packets return HTTP 200; consumers must
inspect `complete` and omission evidence. Shape/identity injection refuses with
400, missing credentials with 401, missing read authority with 403, a changed
head or required index position with 409, a resource/output limit with 413, and
an expired or cancelled native request with 408. Refusals contain no packet or
source excerpts. `expected_commit`, ranked context selection, transaction keys,
caller-selected identities, duplicate fields and unknown fields are rejected.
The existing `source/context-initial` endpoint retains its original response;
it does not silently acquire Agent Protocol semantics.

`fgit_node::source_agent_context_json` exposes this same grammar and implementation
to explicitly authorized in-process hosts, omitting only `object_format` because
the selected node supplies it. Its sponsor argument is host-bound attribution,
not a request field. It returns the route's stable refusal codes and never
performs HTTP or credential discovery on behalf of the caller.

## MCP context

Launch the existing stdio server with a separate context grant and an exact
repository incarnation:

```sh
fg-mcp /srv/frankengit/repository "$TENANT_ID" "$REPOSITORY_ID" \
  --trusted-local --allow-agent-context \
  --principal "$SPONSOR_ID" --expected-incarnation "$INCARNATION_ID"
```

This launch exposes `frankengit_agent_context`. It does not imply the existing
`--allow-source` group, any write grant, or outcome recovery. Likewise, those
grants do not enable agent context. The sponsor remains the launch principal;
request arguments cannot replace it. The MCP host records
`agent-context-trusted-local-v1` and `operator-asserted` sponsorship, with
`trusted-local-mcp` source authorization.

After the normal initialization handshake, a tool request is:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"frankengit_agent_context","arguments":{"reference":"refs/heads/main","terms_hex":["6e6565646c65"],"path_prefixes_hex":["7372632f"],"context_max_files":4,"expires_after_secs":30,"max_output_bytes":1048576}}}
```

MCP uses `reference` for the HTTP `ref` field and arrays `terms_hex`,
`path_prefixes_hex` and `symbol_kinds` for the repeated form fields. Other
supported options have the same names as the HTTP table above. The selected
node supplies `object_format`; clients cannot replace it. The complete native
JSON document is limited to 1 MiB, including all source and evidence, and the
existing MCP transport envelope remains independently bounded. No truncated
JSON or successful empty substitute is returned when a required index is absent.

A partial packet remains a successful read with `complete: false` and explicit
omissions in `structuredContent`; it grants no publication rights. Cancellation
uses the server's existing serial lifecycle and the native request deadline.
A queued MCP cancellation cannot preempt a synchronous operation already in
progress. The native operation still checks cancellation and expiry inside each
phase, returns no partial document on refusal, and leaves no durable run.

The tool calls `source_agent_context_json` directly. Its declared REST counterpart
is the actual `POST /{repository}/api/v1/source/agent-context` endpoint, and its
CLI counterpart is `fg agent context`. All three use the same native run,
receipt, packet and evidence implementation.

See [the Agent Protocol](AGENT_PROTOCOL.md), [native source context](SOURCE_CONTEXT.md),
and [native source indexes](NATIVE_SOURCE_INDEX.md) for the underlying contracts.
