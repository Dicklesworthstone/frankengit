# ADR-0009: Federation Is Admission-Controlled Import, Not Shared Authority

- **Status:** **accepted 2026-08-21 by GoldLotus ruling (fg061 comment 1103)**
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit architecture (federation)
- **Scope:** plan decision D13 — identity and key history, event classes, coordination rules, spam and moderation, equivocation, local admission
- **Binds:** `frankengit-fg063-federation-t6yd`
- **Spec sections:** plan §D13, `AGENTS.md` §5.1 (authority), §8 (statistical rules), §9 (untrusted text), `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` §5

## Context

Federation invites a second writer into a system whose entire correctness argument rests on one authority head per repository. Most federated designs answer this with eventual convergence and conflict resolution. FrankenGit cannot: a CRDT merge that silently reconciles two ref states is precisely the ambiguous-commit outcome the canonical model exists to make impossible.

## Settled

- **Protected refs remain locally coordinated.** A remote instance never moves a local ref (`AGENTS.md` §5.1).
- Remote content is untrusted text (`AGENTS.md` §9). It cannot widen capabilities, approve itself, suppress a gate, or alter retention.
- A moderation or reputation score may prioritise or recommend; it may never authorise, delete, or sanction (`AGENTS.md` §8).
- One sealed transaction has at most one terminal decision. Federation must not create a second path to a terminal outcome.

## Remaining choice

Which event classes federate, the identity and key-history model, and the moderation mechanism.

## Decision (proposed)

1. **Federation is import under local admission, never shared authority.** A remote event is a *proposal*; it becomes local state only by passing local admission and publishing through the ordinary local authority path. There is no remote write.
2. **Federate only self-certifying, append-only event classes** in the first slice: signed issue and discussion events, and signed release and evidence announcements. Each is content-addressed and independently verifiable, so import is validation rather than trust.
3. **Refs, merges, and protection changes do not federate.** They are the classes where two writers would create an ambiguous outcome.
4. **Identity is key history, not instance reputation.** A remote author is a key with a recorded history; rotation and revocation follow `docs/ADR-0003-CRYPTOGRAPHY-AND-KEY-POLICY.md`. An instance's hostname grants nothing.
5. **Equivocation is detected and retained, not resolved.** Two contradictory signed events from one key are both kept, the contradiction is recorded as evidence, and the key is flagged. The system does not silently pick a winner, because picking is exactly the ambiguity it must not manufacture.
6. **Moderation is local admission policy.** Each instance decides what it imports. There is no global moderation authority and no federated ban list with force; a shared list may inform local policy and may not execute it.

## Alternatives and why they are rejected

**A. CRDT-converged shared state including refs.** Rejected: it produces exactly the silent reconciliation of two ref states the canonical model forbids. Convergence is the wrong goal when one of the two states must be refused.

**B. Trust the remote instance and import its decisions.** Rejected: it makes a remote operator an authority over local state, which no §5.1 reading permits.

**C. Federate everything but require manual approval per event.** Rejected as unworkable and as security theatre: approval fatigue converts a human gate into a rubber stamp within a day.

**D. Global federated moderation with enforcement.** Rejected: it is a cross-instance authority over local data, and it makes a reputation score authorising, which §8 forbids.

**E. Defer federation entirely.** Not rejected as a *schedule* option — this ADR does not claim federation must ship in v1. It rejects only the idea that the trust model can be decided later, because the event classes chosen now determine whether a safe model is reachable at all.

## Evidence required before acceptance

- an admission corpus: forged signatures, replayed events, equivocating keys, revoked-key events, and events attempting capability widening — each must be refused with a typed reason;
- proof that no federated path can move a ref, alter protection, or produce a second terminal decision;
- equivocation drills showing both events retained and the contradiction recorded;
- spam and flooding drills showing bounded resource consumption under hostile import volume;
- a key-history campaign covering rotation, revocation, and post-revocation event handling.

## Migration and rollback

Federation is additive and per-instance. Disabling it stops import; imported events already admitted are ordinary local state and are unaffected, because they were published through the local authority path like anything else. There is no federated state to unwind, which is the main practical benefit of import-under-admission.

## Dependency, target, and unsafe consequences

Transport reuses the existing pure-Rust stack; signatures reuse the ADR-0003 registry. No new dependency is implied. Federation adds a hostile input surface and must be listed as one in `SECURITY_THREAT_MODEL.md` before implementation.

## Non-claims

- No claim that this model achieves convergence between instances. It deliberately does not: instances may hold different sets, and that is the correct outcome when admission policies differ.
- No claim of spam resistance beyond the measured bounded-consumption drills.
- No claim that the first event classes are sufficient for useful collaboration; they are the classes that are safe to import first.

## Supersession rule

A future ADR may widen the federated event classes. It may not make a remote instance an authority over local refs, and it may not resolve equivocation by selection.
