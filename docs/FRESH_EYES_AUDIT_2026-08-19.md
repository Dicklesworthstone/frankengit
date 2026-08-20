# Fresh-Eyes Architecture and Publication Audit

**Date:** 2026-08-19  
**Scope:** Initial public FrankenGit architecture repository  
**Disposition:** Corrected in the audited publication revision

## Executive verdict

The initial design had a strong central thesis—Git compatibility at the edge, immutable canonical truth, disposable materializations, repairable storage, and an agent-native forge—but several descriptions were ambiguous exactly where ambiguity would become a distributed-systems bug. The initial GitHub upload also corrupted the intended directory layout.

This audit treats documentation as executable architecture. A design claim is accepted only when its identity domain, owner, linearization point, failure semantics, recovery path, and evidence class are explicit.

## Critical findings corrected

### A-001: Publication flattened the intended tree

The first upload moved files intended for `docs/` into the root, omitted constitutional/support files, added `.DS_Store`, and published bootstrap/checksum artifacts that belonged to the transfer bundle rather than the product repository. Relative links no longer described the actual tree.

**Correction:** Restore `docs/`, `.github/ISSUE_TEMPLATE/`, workflow, scripts, `.gitignore`, `LICENSE`, and `ARCHITECTURE.md`; delete platform and transfer artifacts; add a CI tree-integrity check.

### A-002: Push was incorrectly grouped under Git protocol v2

Git protocol v2 defines command-based negotiation used by upload-pack/fetch flows; push remains the receive-pack service and must be described independently. Treating “protocol v2 push” as an existing compatibility target would create a false test matrix and probably a broken implementation boundary.

**Correction:** `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` separates service, transport, protocol version, and capability. The compatibility matrix has independent upload-pack and receive-pack rows.

### A-003: Transaction identity had multiple incompatible definitions

One formulation implied stable idempotency from caller request identity; another introduced server-generated entropy. The latter makes a retry a new mutation and defeats permanent outcome lookup.

**Correction:** One domain-separated `TxId` formula binds tenant, repository, authenticated principal, idempotency key, and canonical request digest. Request IDs and server attempts are tracing identities only.

### A-004: No linearizable terminal outcome object

The plan promised permanent idempotent results but did not define the record that wins races among commit, refusal, disconnect, cancellation, and retry.

**Correction:** Add immutable `TxnOutcomeRecord`, keyed by `TxId`, with exactly two post-seal terminal variants: `Committed` and `Refused`. Infrastructure interruption leaves no terminal record; cancellation cannot assert non-commit.

### A-005: Reference algorithm used state before reading it

The reference flow evaluated policy and referenced snapshot-derived variables before pinning a complete repository snapshot. This makes authorization vulnerable to mixed-version reads and TOCTOU errors.

**Correction:** Pin one `RepositorySnapshot` before expected-old validation, object-closure validation, candidate construction, and policy evaluation. The serializable commit compares that snapshot is still current.

### A-006: Undefined variables and underspecified retry points

The earlier pseudocode referred to candidate roots, policy state, and object closure without defining their construction or ownership. It was unclear which failures retry and which become canonical refusals.

**Correction:** Replace the flow with a numbered algorithm that introduces every value, distinguishes request rejection from transaction refusal, and identifies the exact metadata compare-and-commit boundary.

### A-007: Capsule semantics could silently stale forge state

A carried-forward recovery capsule was sometimes described as if it authenticated current forge-stream positions. Capsules are periodic checkpoints and may lag intervening RCRs.

**Correction:** Every RCR carries `resulting_forge_position_root`. A capsule binds one exact RCR and is optional per commit. Old capsules remain recovery checkpoints, never current-state substitutes.

### A-008: Potential circular capsule identity

Signatures and placement acknowledgements were described near the capsule identity without an explicit exclusion rule. Including attestations that themselves sign or refer to the capsule creates circular or unstable identity.

**Correction:** Hash the unsigned canonical `RepositoryCapsuleBody`; signatures, replica acknowledgements, repair placement, and storage locations attest to that ID but do not define it.

### A-009: Object durability and transaction durability were conflated

The plan sometimes read as though successful upload or object-store placement made data canonical. That risks leaked retention roots, orphaned state, or accepting bytes before ref/forge atomicity.

**Correction:** Incoming bytes live in a transaction quarantine. Immutable bodies may be staged before the metadata commit, but only an admitted RCR creates canonical reachability. Promotion is identity-based and idempotent.

### A-010: RaptorQ scope was too easy to overread

The design correctly wanted fountain-coded repair, but “RaptorQ everywhere” can be misread as applying to mutable metadata or as providing integrity/consensus.

**Correction:** Restrict RaptorQ to registered immutable byte objects and require cryptographic plus structural verification after decode. Mutable canonical metadata uses replicated transactional storage and fencing.

### A-011: Agent cancellation and authority needed a harder boundary

An agent operation could be cancelled at the harness level while a sealed push continued, creating ambiguity about whether effects happened. Agent tokens also needed explicit attenuation rather than inherited sponsor power.

**Correction:** Intent Runs bind scoped capabilities and budgets. Cancellation before/after transaction seal follows the same canonical outcome rules as human clients. Credentials are revoked/drained with the structured-concurrency region.

### A-012: “Open source” conflicted with the inherited custom rider

The current license with an OpenAI/Anthropic exclusion is source-available but not an OSI-approved open-source license. Marketing the repository unqualifiedly as open source would be factually and strategically inconsistent.

**Correction:** Add `docs/LICENSING_DECISION.md`; make licensing an explicit launch gate; avoid unqualified OSI claims until the owner chooses AGPL, Apache/MIT, or another genuine open-source strategy.

## Major omissions added to the architecture surface

- Git LFS batch API and lock semantics;
- SHA-256 repository format and hash-agile typed IDs;
- push quarantine limits for delta/decompression bombs;
- signed push certificates and signature-policy evidence;
- partial-clone/promisor correctness;
- transactional outbox and webhook idempotency;
- CI runner trust, cache poisoning, artifact provenance, and secret isolation;
- package/release registry integrity and tenant quotas;
- GC root catalog, legal holds, grace horizons, and deletion claims;
- import/export, disaster recovery, and mixed-version migration evidence;
- fork visibility and confidential-source leakage boundaries;
- branch-protection/merge-queue TOCTOU handling;
- current forge-position roots independent of checkpoint cadence;
- reversible limits on statistical automation;
- verifier-independence classes for agent-authored changes;
- source-tree and link integrity CI.

## Claims deliberately narrowed

- RaptorQ improves recoverability only within registered coding and placement assumptions.
- e-processes provide anytime-valid evidence only under their stated null/model conditions; they do not decide truth or guilt.
- deterministic replay covers recorded inputs and modeled effects, not unknowable external behavior.
- object-store durability is not end-to-end recovery evidence.
- content addressing proves byte identity, not authorship or safety.
- source availability is not equivalent to OSI open source.
- a complete plan is not an implemented forge.

## Mechanical gates introduced

`scripts/verify_docs.py` checks:

- required constitutional files and intended directories;
- absence of `.DS_Store` and transfer artifacts;
- relative Markdown link targets;
- balanced fenced code blocks;
- no flattened copies of `docs/` contracts;
- presence of the normative transaction/capsule/push language;
- immutable SHA pinning for third-party GitHub Actions;
- explicit pre-implementation and licensing status.

The workflow runs this gate on pushes and pull requests.

## Remaining decisions that cannot be honestly “fixed” in prose

1. Final open-source/commercial license model.
2. Initial metadata substrate and its measured availability envelope.
3. Whether V1 supports both SHA-1 and SHA-256 repository creation or only imports SHA-256 repositories behind an experimental gate.
4. Exact GitHub API compatibility subset for the first hosted release.
5. CI execution substrate and sandbox boundary.
6. Data-residency and deletion guarantees offered by FrankenGit.com.
7. Which Franken-family dependencies are reused as crates versus reimplemented behind local traits.
8. Whether federation is a V1 goal or a later protocol after single-site semantics are proven.

Those are now explicit decision gates rather than hidden assumptions.