# Git and Forge Compatibility Matrix

**Status values:** `required-v1`, `planned`, `experimental`, `explicitly-out-of-scope`, `oracle-only`.

This is a target matrix, not an implementation claim. A row becomes “implemented” only through the evidence registry defined by `VERIFY_SPEC.md`.

| Surface | V1 target | Required semantics / oracle |
|---|---:|---|
| Smart HTTP `git-upload-pack` | required-v1 | Git client differential corpus; clone/fetch negotiation and sideband behavior |
| SSH `git-upload-pack` | required-v1 | OpenSSH transport harness plus Git client differential corpus |
| Smart HTTP `git-receive-pack` | required-v1 | Push, delete, force, atomic, push-options, report-status, sideband errors |
| SSH `git-receive-pack` | required-v1 | Same receive-pack semantics over SSH command dispatch |
| Git protocol v0/v1 fetch | required-v1 | Legacy client compatibility |
| Git protocol v2 `ls-refs`/`fetch` | required-v1 | Capability-scoped v2 command tests |
| “Protocol v2 push” | explicitly-out-of-scope | Not a standardized Git v2 command; push is tested as receive-pack |
| SHA-1 repositories | required-v1 | Exact native object IDs and pack behavior |
| SHA-256 repositories | planned | Typed hash format; Git's SHA-256 transition fixtures |
| Atomic push | required-v1 | All commands commit or none when capability is negotiated |
| Push options | required-v1 | Preserved in sealed request and policy evidence |
| Signed push certificates | planned | Certificate parsing, nonce policy, signature verification |
| Shallow clone/fetch | required-v1 | Depth, deepen, unshallow, and reachability edge cases |
| Partial clone / filters | required-v1 | `blob:none`, tree-depth filters, promisor correctness, lazy fetch |
| Pack delta chains | required-v1 | Bounded but compatible validation; thin-pack completion |
| Replace refs / graft-like local behavior | explicitly-out-of-scope | Client-local behavior must not alter canonical server truth |
| Hidden refs | required-v1 | Authorization and advertisement separation |
| Namespaces | planned | Tenant/repository isolation; no accidental cross-namespace advertisement |
| Annotated and lightweight tags | required-v1 | Tag peeling, protection, deletion, signature evidence |
| Git notes | required-v1 | Ordinary refs with policy controls |
| Submodules | required-v1 | Gitlink preservation; no implicit trust or recursive authorization |
| Git LFS batch API | required-v1 | Upload/download/verify, resumability, quota, object identity |
| Git LFS locks API | planned | Lock ownership, force unlock, branch/ref policy integration |
| Bundles / bundle URI | planned | Import/export and accelerated clone; authenticated manifests |
| Server-side hooks | planned | Sandboxed deterministic policy hooks; no ambient host execution |
| User-supplied wire hooks | explicitly-out-of-scope | Replace with typed event/policy interfaces |
| GitHub REST compatibility | planned subset | Versioned endpoint registry; pagination, errors, behavior fixtures |
| GitHub GraphQL compatibility | planned subset | Schema/version registry; cost and authorization semantics |
| GitHub Actions YAML | planned subset | Translator/executor compatibility explicitly versioned |
| GitHub webhooks | required-v1 subset | Stable delivery ID, signatures, retries, ordering contract |
| Issues and pull requests | required-v1 | Event-sourced canonical entities and deterministic projections |
| Review comments / suggestions | required-v1 | Stable anchors plus explicit outdated-position behavior |
| Branch protection | required-v1 | Pinned policy snapshot, bypass evidence, merge-race handling |
| Merge queue | required-v1 | Synthetic refs, batch identity, stale-result invalidation |
| Releases and assets | required-v1 | Immutable asset identities, mutable release metadata events |
| Package registry | planned | OCI first; provenance, quotas, retention, malware-review hooks |
| Pages / arbitrary site hosting | explicitly-out-of-scope-v1 | Separate product/security boundary |
| Codespaces-like hosted IDE | explicitly-out-of-scope-v1 | Agent workspaces are narrower and capability-scoped |
| Federation | experimental-later | No V1 canonical multi-master claim |

## Conformance doctrine

For each supported row, the registry must identify:

- exact client/server versions in the oracle matrix;
- fixtures and generated cases;
- byte-level versus behavioral equivalence expectations;
- accepted divergences with stable error codes;
- resource-limit behavior under adversarial inputs;
- SHA/object-format applicability;
- evidence artifact schema and replay command.