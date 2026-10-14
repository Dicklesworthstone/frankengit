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

## Portable capture and CLI

`scripts/fg_source_assembly.mjs capture` reads an explicit private selection file.
For example (the hash placeholders must be replaced with the actual separately
retained reviewed hashes):

```json
{
  "contributions": [
    {
      "id": "parser",
      "package": "/private/parser-capture/source.json",
      "expect": "/private/parser-capture/expected.json",
      "changes": "/private/parser-capture/changes.json",
      "confirm_draft_sha256": "REVIEWED_PARSER_DRAFT_HASH"
    },
    {
      "id": "renderer",
      "package": "/private/renderer-capture/source.json",
      "expect": "/private/renderer-capture/expected.json",
      "changes": "/private/renderer-capture/changes.json",
      "confirm_draft_sha256": "REVIEWED_RENDERER_DRAFT_HASH"
    }
  ]
}
```

The individual inputs may come from ordinary `fg_source_workspace.mjs capture`
outputs or directly from the authoring workflow. Each selected source package
must stand alone at the same independently chosen commit. The command validates
all input descriptors before reading any referenced file and never discovers
contributors, follows links, runs repository code or loads credentials.

```bash
node scripts/fg_source_assembly.mjs capture \
  --contributions /private/contributions.json \
  --output /private/assembled-change
```

Keep the returned `capture_sha256` independently. Review the new combined
`patch.diff`, `draft.json` and the contribution attribution in `assembly.json`.
The output is an absent-to-created `0700` directory with `0600` files. Original
inputs are never changed. Each contributor's source bytes, normalized expectation
and changes, and regenerated original draft are saved under FIXED indexed names.
The combined `source.json`, `expected.json`, `changes.json`, patch, draft and
assembly receipt follow. `manifest.json` is written last after payload sync and
readback. Labels never become filenames.

```bash
node scripts/fg_source_assembly.mjs inspect \
  --capture /private/assembled-change \
  --sha256 "$RETAINED_CAPTURE_SHA256"
```

Reopening needs no original paths, credentials or network. It checks the complete
bounded inventory, original review pins and every payload hash, then repeats all
contribution verification, conflict checks, package union and combined authoring.
Saved patches, source, draft flags and attribution must equal regenerated bytes,
even under a deliberately rehashed corrupt local manifest. Inspection does not
repair or modify the capture. A root hash binds custody, not a reviewer identity.

The combined inputs work with the EXISTING strict publication preparation flow:

```bash
node scripts/fg_source_changes.mjs prepare-packed \
  --package /private/assembled-change/source.json \
  --expect /private/assembled-change/expected.json \
  --changes /private/assembled-change/changes.json \
  --selection /private/independent-native-target.json \
  --confirm-draft-sha256 "$REVIEWED_COMBINED_DRAFT_SHA256" \
  --token-file /private/read-token \
  --output /private/candidate
```

Then use `inspect-packed` and `stage-packed` with the combined source inputs,
NEW reviewed draft hash, exact candidate hash, explicitly selected original
principal and candidate consent as described in `PACK_VERIFIED_SOURCE_FLOW.md`.
Apply and recover remain separate existing commands. A constituent review hash
fails preparation before network access; it does not authorize the combination.
The existing one-shot journal owns any later lost-response recovery, including
after the original workspaces, contributions, assembly and candidate path are
removed. Assembly never retries a mutation or replaces that responsibility.

All CLI paths must be normalized absolute owner-private POSIX paths, not symlink
aliases; regular input files must have one link. The selection file is at most
128 KiB, with at most 64 KiB of selected host-path bytes. The CLI also caps total
raw input-file bytes at 64 MiB before parsing; the core's normalized input limit
still applies. Captures retain both original and combined full source packages,
including unchanged selected bodies and tree sibling names: keep them private.
The fixed inventory is bounded at 128 MiB total and the manifest at 32 KiB.

Both commands accept `--timeout-ms` from 1 to 300000 (default 30000), plus bounded
receipt delivery. A started file/root write is drained. Cancellation before
reservation leaves no owned output; after reservation it retains an incomplete
or uncertain slot instead of cleaning up or overwriting it. A completed root is
not removed on lost stdout. Exit 0 means completed, 2 refusal, 3 cancellation
without claimed output, and 4 retained or uncertain local result/output. Inspect
the retained pin; do not reinterpret exit 4 as absence. This trusted-local profile
is not hostile same-user parent confinement, an atomic input snapshot, physical
power-loss durability or an authority record.

The capture/CLI tests include private-file corruption with recomputed hashes,
original-pin substitution, forbidden paths/links, concurrent creators, interrupted
payloads, read-only inspection, broken output and SIGTERM during blocked delivery.
The full composition tests use two real local editor captures in both hash domains
through pack-verified preparation, staging and original-key lost-response recovery
with no second upload. HTTP/TLS peers model native schemas and use Git only as a
test oracle; they are not Rust fg or proof of native authority/admission/CAS.
