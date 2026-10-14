# Assemble independently reviewed source contributions

`assembleSourceChanges` in `scripts/operator/source_assembly.mjs` combines two
through eight separately reviewed contributions into ONE new standard source
change draft. It fills the gap between parallel source authoring and the existing
single-candidate preparation/staging workflow. It is an external source consumer,
not native merge-queue execution, a task-lease broker or autonomous publication.

Every contribution supplies its source-package bytes, independently retained
expectation, explicit changes, reviewed draft hash and a unique local label.
Labels are not authenticated contributor identities or signatures. The original
review pin is an input to verify, not proof of who reviewed or authorized it.

```js
import { assembleSourceChanges } from './scripts/operator/source_assembly.mjs';
const assembled = await assembleSourceChanges([
  { id: 'parser', packageBytes: parserSource, expected: parserExpectation,
    changes: parserChanges, confirmDraftSha256: reviewedParserDraft },
  { id: 'renderer', packageBytes: rendererSource, expected: rendererExpectation,
    changes: rendererChanges, confirmDraftSha256: reviewedRendererDraft },
], { timeoutMs: 30000 });
// assembled.combined: standard packageBytes, expected and normalized changes.
// assembled.draft: standard patch bytes, reviewed manifest and expected tree.
// assembled.receipt: original review/source/effect attribution and the NEW hash.
```

## Conflict and review contract

All contributions must name the same native SHA-1 or SHA-256 commit and the same
explicit byte/patch profiles (including omitted defaults). Before combining,
each source and draft is verified independently and must match its supplied
review pin. A second package cannot rescue an incomplete first proof.

Attempted write targets must be disjoint, including ancestors and no-op intents.
A rename counts as writes to both source and destination. Identical overlapping
edits are also refused: no contributor is chosen as a winner or silently removed.
Every actual effect must avoid every OTHER contribution's complete selected
read set. That set includes context, no-op inputs and read-only copy sources.
Shared read-only context and copies from one unchanged source are permitted.
Undeclared dependencies cannot be checked; this is not semantic-compatibility
proof, an execution transcript or evidence of policy authority.

The existing package union verifies the combined proof and its ceilings. The
existing authoring engine regenerates all normalized operations together and
checks their combined limits. Every original per-path effect, no-op and explicit
relocation must survive unchanged. The existing whole-tree calculation builds
the result while preserving unmodified subtrees. Inputs are sorted by local
label for deterministic attribution; input array order cannot resolve conflicts.
Changing labels changes attribution, not publication authority.

The result requires NEW review of the complete combined draft and its NEW hash.
Original individual review consent does not authorize the assembly. Use the
combined inputs with `prepare-packed`, `inspect-packed` and `stage-packed` from
`PACK_VERIFIED_SOURCE_FLOW.md`, and separately use the original publication owner.
No journal is created or retargeted by the assembly core. Resolve any uncertain
original publication under its original key; combining proposals cannot decide
whether separately submitted changes already committed. There is no global
cross-journal deduplication or inferred repository/branch ownership.

## Limits and verification

At most eight contributions and 64 MiB of total encoded source plus normalized
expectation/change bytes are admitted. Repeated source packages count repeatedly.
`limits` may only narrow these ceilings. The combined source retains the existing
32 selected files, 128 parent-tree proofs and 8 MiB logical-source limits. The
combined authoring draft retains 32 effects, 1 MiB per file/patch, 4 MiB retained
before/after bytes and existing line/frontier/time ceilings. Separate contributor
budgets cannot be added together to bypass them. Each contribution must contain
a real effect; an all-no-op proposal refuses under the existing authoring kernel.

All input sources, edits, labels, choices and review pins are copied before the
first asynchronous verification. One monotonic deadline spans all source checks,
union and construction; cancellation never returns an assembled subset. Several
owned and decoded packages coexist, so this is not a streaming-memory guarantee.
No network, filesystem, credential, source execution or production Git call lives
in the core. No new codec, native transaction or permission format is introduced.

Run `bash scripts/verify_source_assembly.sh`. The core tests include independently
framed SHA-1/SHA-256 source objects, real Git forward/reverse application, shared
context and near-identical conflicts, binary multi-hunk changes, original pins,
caller mutation and exact resource boundaries. Installed Git is a test oracle,
not a production dependency. These checks do not execute Rust fg, native agent
leases, authorization/admission/CAS, a real browser or a complete repository gate.
