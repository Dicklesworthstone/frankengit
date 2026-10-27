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

The shared Rust entry point is `fgit_cli::agent_context::read_agent_context_in`.
Trusted-local hosts must supply an independently obtained `SourceReadContext`,
a launch-bound or operator-selected sponsor, and a bounded `NodeRequestContext`.
`bounded_request_context` supplies the command profile's deadline. The public
helper does not accept a bearer token, choose a remote identity, or widen a
source grant.

See [the Agent Protocol](AGENT_PROTOCOL.md), [native source context](SOURCE_CONTEXT.md),
and [native source indexes](NATIVE_SOURCE_INDEX.md) for the underlying contracts.
