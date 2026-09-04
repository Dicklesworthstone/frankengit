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
| Commit-graph V1 materialization | planned compatibility surface | Source-receipted deterministic graph materializer and exact graph-walk comparison exist internally; no pinned-Git reader-parse evidence is declared yet |
| Reachability bitmap materialization | planned compatibility surface | Source-receipted bitmap materializer and exact reachability comparison exist internally; no pinned-Git bitmap-reader evidence is declared yet |
| Multi-pack index (MIDX) materialization | planned compatibility surface | Source-receipted deterministic MIDX writer and bounded internal lookup exist; no pinned-Git MIDX-reader evidence is declared yet |
| Atomic push | required-v1 | All ref commands publish in one decision batch/RCR or none when negotiated |
| Non-atomic push | required-v1 | Exact per-command success/failure mapping with stable sealed transaction identities |
| Push options | required-v1 | Preserved in sealed request and policy evidence |
| Signed push certificates | planned | Certificate parsing, nonce policy, signature verification, and replay protection |
| Shallow clone/fetch | required-v1 | Depth, deepen, deepen-since/not, unshallow, and reachability edge cases |
| Partial clone / filters | required-v1 | `blob:none`, tree-depth filters, promisor correctness, authenticated omissions, lazy fetch |
| Pack delta chains | required-v1 | Compatible bounded validation; depth/fan-out/expanded-byte limits; thin-pack completion |
| Receive session envelope | required-v1 profile | Deliberate, operator-selected size/time bounds for one pushed pack; typed refusals, never a silent hangup after the pack trailer — see the envelope section below |
| Hidden refs | required-v1 | Authorization and advertisement separation; no side-channel disclosure |
| Selected-pack write envelope | required-v1 profile | Deliberate, operator-selected bound on one emitted pack's expanded bytes; Fatal-sideband/typed refusal when exceeded — see the envelope section below |
| Namespaces | planned | Tenant/repository isolation; no accidental cross-namespace advertisement |
| Annotated and lightweight tags | required-v1 | Peeling, protection, deletion, signature evidence, deterministic ordering |
| Git notes | required-v1 | Ordinary refs with explicit policy controls |
| Submodules | required-v1 | Gitlink preservation; no implicit trust, credential delegation, or recursive authorization |
| Replace refs / graft-like local behavior | explicitly-out-of-scope server truth | Client-local views cannot alter canonical server state |
| Reflogs | planned compatibility view | Derived/materialized audit view; canonical decision history remains the authority |
| Alternates | explicitly-out-of-scope production authority | May appear in conformance fixtures; cannot create hidden canonical dependencies |
| Git bundles / bundle URI | planned | Restricted source-receipted Full Bundle V2 and `mode=any` mirror-list profiles exist internally; no pinned-Git bundle/URI consumer evidence is declared yet |
| Server-side hooks | planned typed subset | Sandboxed/capability-scoped deterministic policy interfaces; no ambient host execution |
| Arbitrary user wire hooks | explicitly-out-of-scope | Replaced with typed events, policies, obligations, and effect broker |
| Archive generation | required-v1 subset | Pure-Rust tar/zip generation, path safety, deterministic ordering, resource bounds |
| Diff/merge | required-v1 core | Pure-Rust Myers/patience/histogram-style diff profiles and deterministic merge; oracle corpus for observable behavior |

## Hidden-ref disclosure: implementation status (2026-09-04)

**Source revision:** `0f26c6856896021fd4008e40b917465ee713bd33`. The owning
implementation is [`fgit-wire::visibility`](../crates/fgit-wire/src/visibility.rs).
This subsection records landed source, not a promotion of the target row above
or a claim that current node transports are verified.

`RefVisibility` evaluates a peeled `<ref>^{}` record under its base ref's
ordered hide/unhide rules. Its insertion bound rejects counts at or above the
limit supplied for that call, including policies built under a larger earlier
limit; refusal never partially installs an exception.

`VisibleUploadPackRepository` derives its ordered advertisement, disclosable
tips, and symbolic metadata together. It reads each advertised alias edge once,
propagates hiding backwards through that advertised graph with a deduplicated
nonrecursive worklist, and retains only permitted symbolic metadata. A hidden
branch cannot become visible merely because `HEAD` or another advertised alias
points to it. Shared object identity still remains disclosable through an
independent public ref. Canonical unborn `HEAD` metadata is forwarded only when
both `HEAD` and its target are visible; an empty filtered advertisement is not
evidence that the canonical repository is unborn.

The source regression targets are:

| Test target | Authored coverage |
|---|---|
| [`visibility_peeled_records`](../crates/fgit-wire/tests/visibility_peeled_records.rs) | Exact tag/peeled pairing, ordered exceptions, shared identities, hidden-only wants/haves, SHA-1/SHA-256, encoded v1 output |
| [`visibility_symbolic_refs`](../crates/fgit-wire/tests/visibility_symbolic_refs.rs) | Hidden/absent v2 output equality, permitted symrefs, alias chains/cycles, shared tips, one metadata lookup per advertised ref, visible/refused unborn metadata |
| [`visibility_rule_limits`](../crates/fgit-wire/tests/visibility_rule_limits.rs) | Reduced, zero, equal, and increased rule limits; unchanged policy on refusal |

**Remaining boundary.** The standalone `filter_advertised_refs` helper has
names but no symbolic metadata; it is not a substitute for the wrapper or an
equivalent authority-bound projection. The inner repository still owns the
canonical permitted object closure, including non-tip wants and commonality;
this wrapper does not derive reachability authorization from object existence.
Adapters with separate view implementations, including node transport views,
require their own integration evidence. This change set does not establish
end-to-end pack disclosure safety, timing-side-channel resistance, or complete
Git compatibility. It does not change the node receive/report deadlines.

The sixteen tests above are authored, not executed in the implementation
environment. Formatting, compilation, the sanctioned whole `fgit-wire` target
set, node integration, pinned-client differential checks, and the independent
batch gate remain to be run at an exact revision under `AGENTS.md` §16.2.
Historical passing revisions and the presence of these tests are not current
verification evidence.

## Receive and selected-pack session envelopes (git-daemon slice)

Resource limits are compatibility semantics (constitution section 6), so the
receive envelope is a deliberate, documented policy rather than an accidental
function of a fixed connection timeout and the host's seal throughput
(frankengit-asb8). For one raw git-daemon `git-receive-pack` session, two
limit families govern:

- **Size.** `ReceiveLimits`/`PackLimits`: pushed-pack input bytes (default
  64 MiB; quarantine retention tracks it), unique expanded content bytes
  (default 128 MiB; the delta-resolver cache tracks it), per-object bytes
  (default 32 MiB), entry/delta depth/fan-out/work bounds. A violation is a
  typed `PackError` surfaced through report-status as `unpack`/`ng` with
  `ResourceBudgetExceeded` wording (frankengit-xefn).
- **Time.** The session budget is `base + min(admitted_bytes * per_byte,
  max_extension)`, charged against every byte received from the client.
  Defaults: base 300 s, per-byte ≈ 1 s per admitted MiB, extension ceiling
  3600 s. A peer that stops delivering bytes earns no extension, so the
  anti-trickle property of the original absolute deadline is preserved as a
  sustained-minimum-rate policy. A zero per-byte rate with a zero ceiling
  selects the legacy flat envelope.

The admission layer's database budget derives from the same policy rather
than from the generic 15 s database class default: the seal's deadline is
the session's own envelope value, and its poll and cost quotas scale with
admitted bytes above the class floors (one poll per 64 bytes, one cost unit
per 8 bytes). One work-proportional doctrine bounds both the socket session
and the seal, so a large-but-legitimate first push is never capped by the
host's incidental throughput rank.

The sibling **write-side envelope** (frankengit-e6jj) bounds one emitted
pack: `PackLimits.max_total_expanded_bytes` (default 128 MiB; the writer's
delta-base cache tracks it) gates the selected-pack plan because the current
writer buffers the finished pack in memory before streaming. `fg serve` and
`fg export` widen it explicitly with `--pack-max-expanded-mib`. An
over-envelope selected pack is refused before any pack byte is emitted: a
client that negotiated sideband-64k receives one Fatal sideband message
naming the limit (diagnosable, not an unexplained early EOF); without
sideband the connection ends as in upstream mid-service failure. `fg export`
prints the typed refusal directly.

`fg serve` selects the receive envelope explicitly: `--session-timeout-secs`,
`--session-secs-per-mib`, `--session-max-extension-secs`,
`--receive-max-input-mib`, `--receive-max-expanded-mib`; `fg serve` and
`fg export` select the write-side envelope with `--pack-max-expanded-mib`.

Refusal behavior by phase: a deadline that fires while the client is still
sending (greeting, command section, pack stream) is a typed serve error and
the connection ends, matching upstream mid-transfer failure behavior; a
deadline that fires during admission — after the client has finished sending —
is delivered through report-status with the notice "push outcome unknown:
retry the identical push to resolve it idempotently" (cancellation never
proves non-commit, normative contract section 5.2), written inside one bounded
30 s terminal report grace. The committed report is likewise always
deliverable when the envelope fires after the verdict exists.

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
