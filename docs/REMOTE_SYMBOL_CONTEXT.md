# Symbol-aware remote source context

The existing `scripts/fg_source_context.mjs` capture/inspect operator now accepts
an explicit `symbols` object in `frankengit-source-context-query-v1`. It still
uses one authenticated `context-initial` request. It neither scans a local
checkout nor initializes, refreshes or mutates the remote indexes.

Add this object to the private query file described in
[REMOTE_SOURCE_CONTEXT.md](REMOTE_SOURCE_CONTEXT.md):

```json
{
  "symbols": {
    "name": "Recover",
    "match": "prefix",
    "policy": "required",
    "kinds": ["function", "struct"]
  }
}
```

This is a fragment, not a complete query: retain the independently supplied
`schema`, complete `scope`, full `reference`, lexical `terms`, and any original
source pins. Symbol names are case-sensitive ASCII identifiers (without `r#`).
Lexical terms remain ASCII-folded whole tokens. `match` defaults to `exact`;
`policy` defaults to `optional`; omitted `kinds` means all eight native declaration
kinds. Kinds are deduplicated and sorted, and all channels use the same byte-path
prefixes. Unknown options, additional path grants, and invalid names fail before
network I/O. Omitting `symbols` preserves the lexical-only request and capture.

The optional `minimum_symbol` object has the same `{ "token": "alg:2:...",
"number": "4" }` shape as `minimum_lexical`, but names the independently observed
symbol generation. Do not copy a lexical checkpoint into it. Counters remain
exact decimal strings even when the server sends a full-width JSON u64.
A symbol floor without a symbol query is rejected. A retained floor is never
removed to make an unavailable index usable.

```bash
node scripts/fg_source_context.mjs capture \
  --endpoint https://forge.example/team/repo.git \
  --query-file /private/context/query.json \
  --token-file /private/context/read-token \
  --output /private/context/new-bundle
```

Use a 0700 input directory and 0600 query/token files. Credentials stay out of
argv, captures and receipts. Non-loopback connections require verified HTTPS;
redirects and automatic retries remain forbidden. The existing local bundle
publication and independently pinned, offline `inspect` protocol are unchanged.

## What the client checks

The symbol response must identify the same namespace, reference, source head,
RCR, commit and tree as both lexical channels, and the exact symbol generation
in the returned vector. Names, kinds, path scope, raw-identifier markers, source
spans and original per-row excerpts are checked against the named native profile.
All three channels retain fixed pre-I/O work and payload shares, even when an
optional channel is unavailable. A failed channel cannot borrow another share.

Hydration includes symbol-only files and deduplicates files shared with lexical
results. It rechecks path/blob identities, known source sizes, selected source
accounting, exact symbol bytes and all overlaps between the symbol table's
excerpt and the hydrated excerpt. Complete returned blobs are independently
native-hash-checked in SHA-1/SHA-256. Partial excerpts do not gain a whole-blob
hash or compiler-resolution claim. Existing lexical evidence checks still run.

Only `uninitialized` and `stale` may be unavailable under optional mode, and only
without a retained symbol floor. They remain explicit, incomplete channel states,
not empty success. Required symbols, unresolved floors, missing/corrupt evidence,
failed budgets and invalid joins refuse the capture. A valid initialized empty
symbol result remains available and may be complete.

Schema-2 symbol omissions retain every bounded native diagnostic and keep
coverage incomplete. They are not source absence. The capture, quoted text and
export/inspection receipts retain symbol query, availability, generation and
coverage; text also retains the omission inventory. `--require-complete` refuses
to publish a partial bundle. No score, excerpt or local hash grants authority.

## Ranked capture and priority-ordered export

Add the optional query field `selection` to use the already-defined native
ranking profile. For example, this is a fragment for the same private query:

```json
{
  "symbols": { "name": "Recover", "match": "prefix", "policy": "required" },
  "selection": "context-weighted-rrf-q16-v1",
  "limits": { "context_max_files": 4 }
}
```

The client sends `context_selection` to the native endpoint. Omitted selection
retains the original request and capture serialization. Explicit `raw-path-prefix`
keeps alphabetical selection; no ranking receipt may appear in that response.
Unknown profiles, extra weights/constants, duplicate control fields at the native
endpoint, and silent downgrade to alphabetical selection are not accepted.
There is no retry with a different selection or increased budget.

The client reconstructs the entire **returned** candidate universe from the
validated content, path, and available symbol channels. Distinct paths receive
one-based ranks per channel in raw-byte order; repeated declarations in one file
contribute once. It recomputes every contribution using the fixed rule:

```text
floor(weight * 65536 / (60 + distinct_document_rank))
weights: content 1, path 1, symbol 2
order: descending total score, then ascending raw path bytes
```

It then checks the complete selected prefix against the received receipt:
positions, native blob identities, candidate paths, per-channel ranks and weights,
individual contributions, total scores, and tie breaks. Merely checking that
supplied scores add up would miss an otherwise self-consistent lower-ranked
substitute. This client rejects that substitute even if its source bytes hash
correctly. It also refuses missing contributors, fabricated optional-symbol
contributions, wrong scope, and incorrect coverage/completeness claims.

`capture.json` retains the native raw-path-ordered `files` inventory. Its summary
adds a freshly recomputed, normalized `ranking`, not a reference to unchecked
server data. `context.txt` records that ranking and presents the selected files
in checked priority order, while keeping every source excerpt quoted as untrusted
data. CLI export and inspection receipts name the selection profile. Offline
inspection recomputes selection and the text projection in addition to checking
the independently retained manifest and payload hashes. It performs no network
read and needs no credential.

Source and excerpt budgets are unchanged. A failed highest-ranked file cannot
be swapped out for another candidate, and `--require-complete` still rejects
partial file selection or incomplete upstream coverage. Ranking covers only
hits actually returned by the bounded channel queries. It does not turn a
truncated result into a complete repository inventory, independently authenticate
ancestry, or grant access. Input ranks are **raw-path order, not relevance order**;
this profile rewards cross-channel agreement, not semantic understanding. No
measured relevance or latency improvement is asserted.

The ranking tests use an independent BigInt arithmetic oracle and literal
contribution expectations. Real operator processes also exercise ranked capture,
priority text, partial-result refusal, offline reopen, and rejection of a
rewritten local score even when supplied with its new manifest hash. That last
case tests semantic revalidation, not a substitute for retaining the original
manifest hash independently.

## Verification boundary

```bash
node --test tests/operator/source_context*.test.mjs
```

Tests execute the production client, normal operator child processes, real
loopback HTTP/TLS and private filesystem publication/reopen. HTTP replies are
explicit native-schema peers derived from the Rust renderer contract, not a live
`fg` node. Rust compilation and live-node interoperability are separate gates.
The existing lexical/TLS/refusal suite is retained without weakened assertions.
