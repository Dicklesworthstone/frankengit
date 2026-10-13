# Same-source context continuation

`continueCapture` in `scripts/operator/source_context_continue.mjs` performs one
explicit follow-up query from an independently pinned private context bundle.
Its consumer is the remote source-context operator and embedding scripts that
need more context without manually copying source and index pins. It uses the
existing `context-initial` service, not a new server session or authority source.

```js
import { continueCapture } from './scripts/operator/source_context_continue.mjs';
import { publishBundle } from './scripts/operator/source_context_export.mjs';

const { capture, continued_from } = await continueCapture(
  priorBundle, retainedManifestSha256, readCredential,
  { terms: ['rollback'], prefixes_hex: ['737263'], limits: { context_max_files: 4 } },
  { signal, timeoutMs: 30000 },
);
const receipt = await publishBundle(newAbsentBundle, capture, { signal });
```

The caller supplies the original manifest hash independently, just as for
`inspect`. Loading validates private-file ownership/mode, manifest and payload
hashes, native response semantics, exact source bytes where fully present, and
the deterministic text projection. `loadBundle` returns the capture from those
same checked payload bytes; continuation never inspects and then reopens an
unbound copy of `capture.json`. The original bundle is never written or removed.

The endpoint, complete repository namespace and full reference are inherited.
`expected_head` and `expected_commit` come from the prior **observed source**, not
merely the optional request pins. The strongest observed lexical checkpoint is
retained, including a later selected head than the generation actually queried.
An available symbol generation becomes an independent symbol floor even when
symbols were originally optional. Full-width u64 numbers remain decimal strings.
The new response must agree with the complete prior source tuple, including RCR
and tree, not just claim the same head and commit.

A follow-up is a closed object with required `terms`. Optional `prefixes_hex`
may only narrow the prior slash-component byte scopes; empty scopes cannot
replace a nonempty prior restriction. Optional `limits` inherit unspecified
values and cannot increase any prior per-request allowance. Optional `symbols`
inherit unspecified prior symbol options; a required policy cannot become
optional, and an observed symbol floor cannot disappear. New explicit symbol
queries are allowed within the same path scope. `selection` may name either
existing fixed profile. Endpoint, scope, ref, source-pin, checkpoint, force,
cursor and arbitrary control overrides are refused.

Changing a search term, symbol name or kind filter is intentional follow-up
selection, not a wider read grant. Server authorization is rechecked on every
request. Scope checks and local hashes do not authenticate authority ancestry,
grant permission, detect prompt injection, or create an Agent ContextPacket.

One deadline starts before bundle verification; file reads, semantic validation
and encoding check it, and only the remaining time is given to the network
acquisition. Filesystem calls already submitted are awaited and handles closed;
this does not promise interrupting an operating-system filesystem call. There
are no redirects, automatic retries, fallback snapshots or index writes. A moved
source, unavailable checkpoint, integrity failure or exhausted allowance refuses
the follow-up and leaves prior evidence intact.

The result is a normal independently exportable capture with all inherited pins
in its query. `continued_from` names the parent manifest/capture hashes and
checkpoint evidence for callers to retain; it is not added to the v1 capture
format and is not a durable linked-session ledger. Keep both receipts when that
relationship matters. Repeating continuation uses the immediately preceding
bundle's narrowed scope and observed checkpoints. Each explicit call has its own
bounded allowance; this is **not** an aggregate multi-query budget reservation.

A follow-up may change the result set and selected index generation while keeping
one exact canonical source. Its completeness belongs to that query alone. It
does not merge answers, fill a previous query's omissions, or convert prior
partial results into a complete repository inventory. Beginning at a changed
source requires a separately explicit new `capture`, not a hidden refresh.

## Verification

```bash
node --test tests/operator/source_context_continue.test.mjs
```

Tests use unchanged production client modules, real private bundle publication
and loading, and actual loopback HTTP sockets with explicit native-schema peers.
They cover both Git hash formats, strongest full-width checkpoints, symbols,
source mismatch, path/budget attenuation, input mutation, cancellation, deadline
and refusal behavior. They do not establish live Rust-node interoperability or
complete Agent Protocol adoption. FG-032 remains open.
