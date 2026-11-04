# Native release tags through MCP

The ordinary source MCP profile can inspect native tag chains, create lightweight
or annotated tags, and delete an exact tag ref. These tools use the same native
read, quarantine, sealed admission and recovery engines as `fg tag` and the
[HTTP tag API](HTTP_TAG_API.md). Repository identity, object format and mutation
principal come from the server launch. Tagger, message and signature content
cannot select an authenticated principal or widen its authority.

## Launch and independent grants

```sh
fg-mcp "$STORAGE" "$TENANT" "$REPOSITORY" --trusted-local \
  --object-format sha256 --allow-source --allow-source-writes --allow-outcomes \
  --principal "$PRINCIPAL" --expected-incarnation "$INCARNATION"
```

Each grant is independent:

| Grant | Tag operations |
| --- | --- |
| `--allow-source` | `frankengit_tag_inspect`; existing `frankengit_ref_list` with `namespace: "tags"` inventories visible tag refs. |
| `--allow-source-writes` | `frankengit_tag_create`, `frankengit_tag_annotate`, `frankengit_tag_delete`. |
| `--allow-outcomes` | Existing `frankengit_transaction_outcome` reads the original principal's decision using the original key. |

Writes and outcome recovery require both the launch-bound `--principal` and
`--expected-incarnation`. Source-write permission does not imply source-read or
outcome permission. Issue, pull-request, review and merge grants imply none of
these source operations. All four tag tools remain excluded from the closed
sponsored-agent catalogue, including when that profile grants current source
reads. This addition creates no agent operation or new authentication profile.

The trusted-local operator owns the stdio launch and explicitly sponsors its
client as the bound principal. Existing hidden-ref rules, target visibility,
protected-ref admission and publication budgets remain mandatory.

## Exact names, object IDs and request keys

Every tag tool requires **exactly one** of:

- `reference`: the full UTF-8 `refs/tags/...` name, at most **1,024 bytes**;
- `reference_hex`: the complete raw ref bytes in canonical lowercase hex, at
  most **2,048 characters** and 1,024 decoded bytes.

Raw hexadecimal names preserve non-UTF-8 refs. Names must satisfy native ref and
tag rules; they are never filesystem paths or URLs. Responses use
`reference_hex` as the lossless representation. Unknown and inapplicable fields,
duplicate JSON fields, ambiguous name encodings, and invalid names refuse.

Object IDs are exact nonzero lowercase hex in the launch-bound hash domain:
40 digits for SHA-1, 64 for SHA-256. No per-call `object_format`, caller principal,
implicit current tip, force flag or replacement option is accepted. An OID
alone grants no right to read or publish otherwise undisclosed original data.

Every mutation also requires `idempotency_key`: **1–256 printable ASCII bytes**.
Choose it before sending and retain the complete original command. A new
JSON-RPC request ID does not create a new durable operation. Reusing the same
key for different operands is not an update.

## Create a lightweight tag

Call `frankengit_tag_create` with `target` and the common name/key fields:

```json
{
  "reference": "refs/tags/v1.0.0",
  "target": "<exact native object ID>",
  "idempotency_key": "release-v1-lightweight-1"
}
```

The destination must be absent. The target may be an already visible native
commit, tree, blob or tag object; this operation imports no original objects and
creates no annotation body. A lightweight alias of an annotated tag exposes
that existing tag chain when inspected. The target's original bytes and visible
reachability remain native checks, not assumptions based on the supplied ID.

## Create an annotated tag

Call `frankengit_tag_annotate` with the common name/key fields plus all of:

| Field | Contract |
| --- | --- |
| `target` | Exact visible native target OID. |
| `target_kind` | `commit`, `tree`, `blob` or `tag`; quarantine checks the actual kind. |
| `tagger` | Explicit native `Name <email>` metadata, at most 1,024 UTF-8 bytes. |
| `timestamp` | Canonical decimal **string** of UTC Unix seconds, from `"0"` through `"9223372036854775807"`. |
| `message_hex` | Exact lowercase hex message, at most **8,192 decoded bytes** / 16,384 characters. Empty is valid; NUL refuses. |

```json
{
  "reference": "refs/tags/v1.0.0-annotated",
  "target": "<exact native object ID>",
  "target_kind": "commit",
  "tagger": "Release Author <release@example.invalid>",
  "timestamp": "1790000000",
  "message_hex": "52656c656173652076310a",
  "idempotency_key": "release-v1-annotated-1"
}
```

The example message is the original bytes `Release v1\n`. CRLF, non-UTF-8 message
bytes and a missing final newline are preserved. There is no trimming, implicit
newline, ambient author or current-clock substitution. The destination must be
absent. The native constructor binds all authored metadata into the new tag
object; quarantine checks that object before ordinary sealed ref admission.

The 8 KiB message cap preserves the ordinary MCP 16 KiB JSON-string limit. It is
smaller than the local/HTTP message profile. This tool neither signs tags nor
cryptographically verifies signature-looking message content. Tagger metadata
is independent of the launch-bound publication principal.

## Inspect a complete native tag chain

Call `frankengit_tag_inspect` with the exact tag name and optional comparison
pins or narrower limits:

```json
{
  "reference": "refs/tags/v1.0.0-annotated",
  "expected_head": "<algorithm-qualified snapshot_token>",
  "expected_object": "<outer tag ref object ID>",
  "max_tags": 16
}
```

Both pins may be omitted on an initial read. `expected_head` compares with the
current authority head; this is not a retained-history selector. An intervening
publication, including an unrelated forge change, produces `snapshot_moved`.
`expected_object` compares the outer ref value and produces `tag_object_moved`
on mismatch. It cannot authorize an arbitrary object lookup. The native read
starts at the currently visible tag ref.

| Bound | MCP maximum/default |
| --- | --- |
| `max_tags` | 64 recursively peeled annotation objects |
| `max_object_bytes` | 262,144 original bytes per object |
| `max_total_bytes` | 524,288 original bytes over the complete read |
| Complete encoded tag result | 1,048,576 bytes |

The three optional limit arguments are positive JSON integers and can only
narrow their ceilings. The terminal non-tag object also consumes both relevant
byte budgets, although its body is not returned. Hashes, declared kinds and
chain edges are checked before disclosure. Cycles, corrupt/missing objects,
exhausted limits and cancellation refuse without a truncated successful chain.

The encoded-result ceiling is independent: hexadecimal expansion and metadata
can produce `tag_result_limit` even when the native read fits its 512 KiB budget.
The broader MCP protocol's existing 2 MiB result allowance remains unchanged;
this tool enforces the registry's narrower 1 MiB bound.

A successful `source_tag` result includes the launch-selected repository,
incarnation and format; `snapshot_token` and `source_head`; `reference_hex`;
outer `object_id`; `peeled_object` and `peeled_kind`; and the complete
outer-to-inner `annotations` array. Annotation rows retain `object_id`, `target`,
`target_kind`, decimal-string `body_bytes` and exact `body_hex`. The annotation
count is also a decimal string. Hashing original bodies with native
`tag <length>\0` framing reproduces their object IDs.

Each annotation reports `signature` as `absent` or `opaque_unverifiable`.
`signature_verified` and `tagger_is_authenticated_principal` remain false.
Object identity, chain completeness, signature presence and human authorship
are separate facts. Inspection returns no terminal blob/tree/commit payload,
creates no transaction and makes no repository change.

## Delete the exact outer tag value

Call `frankengit_tag_delete` with `expected_object` and the common name/key
fields. For an annotated tag, the expected object is the **tag object**, not its
peeled commit. The native command carries this exact old-value lease into
canonical admission. A stale lease can produce a canonical refusal; the adapter
never refreshes it or substitutes a current value.

Deletion removes the named ref, preserving any bytes still reachable through
other aliases or outer tags. It does not rewrite pull requests or synthesize
forge metadata events.

## Terminal decisions and recovery

A terminal `tag_publication` result contains the original `tx_id`,
`decision_sequence`, `outcome` (`committed` or `refused`), and the corresponding
`repository_commit_id` or `refusal_record_id`/`refusal_code`. It also records the
operation (`lightweight`, `annotated`, `delete`), exact raw ref, original
`expected_object` and `new_object`, launch-bound principal and repository
coordinates. A null expected object denotes absent-ref creation; a null new
object denotes deletion. `force` is false and `atomic` is true.

`historical_outcome: true` and `current_refs_asserted: false` distinguish that
receipt from a fresh read. An identical retry after later tag deletion returns
its original decision; it does not recreate the tag. Preserve the original
target, expected outer object, annotation bytes and key across retries.

For read-only recovery, call `frankengit_transaction_outcome` with only the
original `idempotency_key` under `--allow-outcomes` and the original bound
principal. No tag body, current ref, or mutation grant is required. A different
principal has a separate key namespace. See
[MCP outcome recovery](MCP_METADATA_WRITES.md#outcome-tool).

Transport loss, cancellation, `tag_mutation_outcome_unknown`,
`tag_receipt_output_limit`, or a nonterminal outcome lookup never proves
non-commit. A failed response after admission does not undo a canonical
decision. Use a new JSON-RPC ID with the original key for an exact retry, or
query that key without replaying publication.

## Verification boundary

Focused adapter tests cover closed argument schemas, registry/served-field
parity, grant separation, raw names and both native hash formats, chain and
signature non-trust, output bounds, and stable publication receipts. Persisted
node/protocol tests exercise actual native admission, reopen, inspection and
recovery. Checked-in tests are not an execution claim; use the revision-bound
native verification result before treating this implementation as validated.
