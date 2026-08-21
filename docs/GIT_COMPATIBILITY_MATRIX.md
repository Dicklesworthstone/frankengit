# Git and Forge Compatibility Matrix

**Status:** target registry, not an implementation claim.  
**Production boundary:** every supported Git behavior is implemented in clean-room, memory-safe Rust. Upstream Git executables are pinned, sandboxed conformance oracles only; production never links or invokes them.

Base status values used below are `required-v1`, `planned`, `experimental-v1`, `experimental-later`, `explicitly-out-of-scope`, and `explicitly-out-of-scope-v1`; a row may append a narrowing qualifier after the base status (for example `required-v1 subset` or `explicitly-out-of-scope server truth`). A row becomes implemented or verified only through the evidence registry and release gates in [`VERIFY_SPEC.md`](../VERIFY_SPEC.md).

## Git transport, object, and repository semantics

| Surface | V1 target | Required semantics / oracle |
|---|---:|---|
| Smart HTTP `git-upload-pack` | required-v1 | Pure-Rust server; clone/fetch negotiation, pkt-line, sideband, capability, cancellation, and error parity against pinned clients |
| SSH `git-upload-pack` | required-v1 | Pure-Rust service behind typed SSH command dispatch; same upload-pack state machine |
| Smart HTTP `git-receive-pack` | required-v1 | Pure-Rust server; create/update/delete/force, atomic, push-options, report-status, quarantine, and sideband errors |
| SSH `git-receive-pack` | required-v1 | Same receive-pack semantics over SSH command dispatch |
| Git protocol v0/v1 fetch | required-v1 | Legacy capability and negotiation compatibility |
| Git protocol v2 `ls-refs`/`fetch` | required-v1 | Capability-scoped command tests and byte transcripts |
| “Protocol v2 push” | explicitly-out-of-scope | No standardized Git v2 push command; push compatibility is `git-receive-pack` |
| SHA-1 repositories | required-v1 | Exact native OIDs, framing, pack behavior, and stronger internal envelope commitments |
| SHA-256 repositories | planned, constitutionally typed | Native SHA-256 object format and transition fixtures; never digest-byte aliasing with SHA-1 |
| Blob/tree/commit/annotated-tag parsing | required-v1 | Exact framing, header semantics, ordering, encoding, and resource bounds |
| Pack v2 parsing/writing | required-v1 | Header/trailer/checksum, OFS/REF delta, thin packs, bounded reconstruction, deterministic writer profiles |
| Atomic push | required-v1 | All ref commands publish in one decision batch/RCR or none when negotiated |
| Non-atomic push | required-v1 | Exact per-command success/failure mapping with stable sealed transaction identities |
| Push options | required-v1 | Preserved in sealed request and policy evidence |
| Signed push certificates | planned | Certificate parsing, nonce policy, signature verification, and replay protection |
| Shallow clone/fetch | required-v1 | Depth, deepen, deepen-since/not, unshallow, and reachability edge cases |
| Partial clone / filters | required-v1 | `blob:none`, tree-depth filters, promisor correctness, authenticated omissions, lazy fetch |
| Pack delta chains | required-v1 | Compatible bounded validation; depth/fan-out/expanded-byte limits; thin-pack completion |
| Hidden refs | required-v1 | Authorization and advertisement separation; no side-channel disclosure |
| Namespaces | planned | Tenant/repository isolation; no accidental cross-namespace advertisement |
| Annotated and lightweight tags | required-v1 | Peeling, protection, deletion, signature evidence, deterministic ordering |
| Git notes | required-v1 | Ordinary refs with explicit policy controls |
| Submodules | required-v1 | Gitlink preservation; no implicit trust, credential delegation, or recursive authorization |
| Replace refs / graft-like local behavior | explicitly-out-of-scope server truth | Client-local views cannot alter canonical server state |
| Reflogs | planned compatibility view | Derived/materialized audit view; canonical decision history remains the authority |
| Alternates | explicitly-out-of-scope production authority | May appear in conformance fixtures; cannot create hidden canonical dependencies |
| Git bundles / bundle URI | planned | Authenticated import/export manifests and accelerated clone |
| Server-side hooks | planned typed subset | Sandboxed/capability-scoped deterministic policy interfaces; no ambient host execution |
| Arbitrary user wire hooks | explicitly-out-of-scope | Replaced with typed events, policies, obligations, and effect broker |
| Archive generation | required-v1 subset | Pure-Rust tar/zip generation, path safety, deterministic ordering, resource bounds |
| Diff/merge | required-v1 core | Pure-Rust Myers/patience/histogram-style diff profiles and deterministic merge; oracle corpus for observable behavior |

## Native ATP-Git transport

| Surface | Status | Boundary |
|---|---:|---|
| ATP-Git capability negotiation | experimental-v1 | Separate FrankenGit-native protocol; never falsely advertised as ordinary Git |
| Have-summary delta planning | experimental-v1 | Authenticated object/segment inventory; false positives may cost transfer but never correctness |
| Unique-piece swarm transfer | experimental-v1 | Verified piece identity, rarity/endgame policy, bounded peers and memory |
| Path graph and racing | experimental-v1 | Typed paths, privacy/security policy, deterministic tie-break receipt, loser drain |
| RaptorQ transfer blocks | experimental-v1 | Adaptive within hard bounds; exact object/manifest verification after decode |
| Ordinary Git fallback | required-v1 | Unsupported or under-evidenced ATP uses the native pure-Rust Git pack path, not C Git |

## Forge and ecosystem surfaces

| Surface | V1 target | Required semantics / oracle |
|---|---:|---|
| Git LFS batch API | required-v1 | Upload/download/verify, resumability, quota, SHA-256 identity, retention |
| Git LFS locks | planned | Ownership, force unlock, ref/policy integration, audit |
| GitHub REST compatibility | planned subset | Versioned endpoint registry; pagination, errors, timestamps, races, idempotency |
| GitHub GraphQL compatibility | planned subset | Versioned schema/cost/authorization semantics |
| GitHub Actions workflow syntax | planned local-execution subset | Translation/execution compatibility is explicit; GitHub-hosted Actions are not a correctness or release dependency |
| GitHub webhooks | required-v1 subset | Stable delivery ID, signature, retry, ordering, SSRF and redirect controls |
| Issues and pull requests | required-v1 | Event-sourced canonical entities and deterministic projections |
| Review comments / suggestions | required-v1 | Source-spanned stable anchors plus explicit outdated/remap behavior |
| Branch protection | required-v1 | Pinned policy input, bypass evidence, target-movement and merge-race handling |
| Merge queue | required-v1 | Synthetic refs, batch identity, stale-result invalidation, one publication decision |
| Releases and assets | required-v1 | Immutable assets, mutable metadata events, local signed root-last release manifest |
| Package registry | planned | OCI first; provenance, quotas, retention, malware-review hooks |
| Pages / arbitrary site hosting | explicitly-out-of-scope-v1 | Separate product and security boundary |
| Codespaces-like hosted IDE | explicitly-out-of-scope-v1 | TreeFS workspaces are narrower and capability-scoped |
| Federation | experimental-later | No V1 canonical multi-master claim |

## Observable-behavior doctrine

Compatibility includes more than successful output bytes. Each supported row records:

- return/status/error class and message fields where clients observe them;
- packet ordering and capability advertisement;
- ref ordering and tie-break behavior;
- cancellation, disconnect, retry, and partial-read semantics;
- resource-limit refusals under adversarial input;
- SHA/object-format applicability;
- versioned accepted divergences;
- exact client/server/oracle versions;
- fixtures, generated cases, fuzz corpora, and packet transcripts;
- replay command and evidence identity.

Unsupported behavior returns a typed refusal. It never shells out to another Git implementation and presents that result as native FrankenGit behavior.

Planning ownership is explicit without changing target status: FG-097 owns required-v1 tags; FG-084 notes; FG-085 submodules; FG-095 the declared local workflow subset; FG-098 the planned reflog/LFS-lock/push-certificate/namespace/typed-hook/broader-workflow cohort; FG-099 GraphQL; and FG-100 package-format phases. FG-090 generates row status from their executable evidence. An open or closed bead is not itself compatibility evidence.
