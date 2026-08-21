# ADR-0004: Segment, Block, and Compaction Profiles Are Measured, Not Chosen Up Front

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1093)**
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (object fabric, search, graph)
- **Scope:** plan decision D5 — source block, microsegment, pack, checkpoint, and graph/search tier sizing, plus the compaction trigger
- **Binds:** `frankengit-fg020-microsegment-kj9`, `frankengit-fg020b-microsegment-evidence-664`, `frankengit-fg079-compaction-protocol-8v5g`, `frankengit-fg077a-raptorq-microsegment-checkpoint-ko1i`, `frankengit-fg032a-search-impl-koh`
- **Spec sections:** plan §D5 and §20 (object fabric), §7 (performance rules) of `AGENTS.md`, `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §9 (publication epochs)

## Context

Every layer of the fabric has a size knob: the source block a blob is split into, the microsegment those blocks are packed into, the checkpoint bundle, and the tier boundaries in the search and graph stores. These knobs interact — a smaller block improves dedup and repair granularity while inflating index cardinality and per-object overhead — and the interaction is workload-dependent, not derivable from first principles.

`AGENTS.md` §7 forbids adopting a performance profile without a mechanism hypothesis and an oracle. A number picked now would be exactly that: a guess wearing a constant's clothing, frozen into a durable format where changing it later is a migration rather than a tuning pass.

## Settled

- Logical identity is invariant across physical re-encoding. A block, segment, or tier boundary change must never change an `InternalObjectId`, a Git object identity, or an anchor identity. This is what makes the decision deferrable at all.
- Compaction publishes through the same authority path as any other change (`docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §9): staged, visible, durable are distinct, and a compaction that has not reached the selected durability profile is not complete.
- Repair and GC read the *authenticated* basis, never a compaction-derived index, so a profile change cannot widen what GC may delete.

## Remaining choice

The numeric profile itself, and the compaction trigger function.

## Decision (proposed)

Do not fix the numbers in this ADR. Fix the **process and the interim profile**, and bind the real choice to measurement.

1. **Collection corpus.** The profile is derived from four traced workloads, each recorded as a replayable artifact rather than a summary statistic: a large monorepo with deep history; a many-small-repository tenant; a binary-heavy repository dominated by large blobs; and an agent-driven workload with high small-write frequency. Traces record object size distribution, delta chain depth, read locality, and write batching.
2. **Interim conservative profile.** Until measurement lands, implementation uses the conservative end of each knob — larger blocks, larger segments, less aggressive compaction. Conservative here means *fewer objects and fewer moving parts*, because the failure mode of an over-fragmented fabric (index blow-up, repair fan-out, GC cost) is materially worse and harder to reverse than the failure mode of an over-coarse one (some wasted bytes).
3. **Decision threshold.** A candidate profile replaces the interim one only when it shows, on at least three of the four corpora, a materially better result on a pre-declared primary metric with no regression beyond noise on the others, and when the equivalence obligations of `AGENTS.md` §7 are discharged — identical output, ordering, and tie-breaks.
4. **Revisit trigger.** The profile is re-opened when any of these is observed: a corpus class appears that is not represented above; measured repair fan-out exceeds its budget; index cardinality growth outpaces object growth; or a compaction run cannot complete inside its durability window.

## Alternatives and why they are rejected

**A. Pick industry-typical constants now.** Rejected: it converts an unmeasured guess into a durable format commitment, and `AGENTS.md` §7 exists precisely to stop that. The numbers would also be inherited from systems with different identity and repair models.

**B. Make every knob runtime-configurable and let operators tune.** Rejected: it multiplies the state space every conformance and repair campaign must cover, and it moves a correctness-adjacent decision to people with no visibility into the repair budget. A profile is a small closed set, not a free parameter.

**C. Derive the profile analytically from a cost model alone.** Rejected as *sufficient*, retained as *input*: a cost model cannot see read locality or delta-chain shape, and §7 requires an oracle and raw samples, not a model result.

**D. Defer the whole fabric until measurement exists.** Rejected: the interim conservative profile is enough to build and test against, and blocking implementation on a tuning input would stall five beads for no correctness gain.

## Evidence required before acceptance

- the four corpus traces, committed as replayable artifacts with their collection method;
- a measured baseline for the interim profile on each corpus;
- for any candidate profile, raw samples and tails rather than means, plus the A-A control §7 requires;
- proof that identity is unchanged across a re-encode at every candidate boundary;
- a repair-fan-out and GC-cost measurement at each candidate, not only a read/write benchmark.

## Migration and rollback

Because logical identity is invariant across physical layout, a profile change is a background re-encode, not a format break. Rollback is re-encoding under the previous profile; both directions must be demonstrated on a populated repository before acceptance, and the demonstration must include an interrupted re-encode that is resumed.

## Dependency, target, and unsafe consequences

None. This decision adds no dependency, changes no target matrix, and introduces no unsafe surface. Tracing tooling is repository-owned and must not add a runtime dependency to the fabric crates.

## Non-claims

- No performance claim is made by this ADR. The interim profile is *conservative*, not *good*, and calling it a baseline would be proof-class inflation.
- The four corpora are a bounded sample of real workloads and do not establish behaviour on workloads unlike them.
- Nothing here claims the interim profile is safe at arbitrary scale; it claims the failure mode is the recoverable one.

## Supersession rule

A future ADR may set the numeric profile once the evidence above exists. It may not weaken the identity-invariance requirement, and it may not adopt a profile whose repair fan-out is unmeasured.
