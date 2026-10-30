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

## Executed stock-client rows: partial clone, notes, gitlinks, atomic push, push options

These rows come from one discovered suite, `suites-transport-stock_transport_capabilities`
(`scripts/e2e/suites/transport/stock_transport_capabilities.sh`, helper
`scripts/e2e/helpers/stock_transport_capabilities.py`; frankengit-root-doctrine-x2mv.4.33).
It passed **375/375** at **05e29b11** with a release `fg` built there
(sha256 `e7e4daa3bd424ca9…`), run twice: host git 2.55.0 and the pinned oracle
git 2.54.0. Each run covers SHA-1 and SHA-256 repositories over
`fg serve-http`, `fg serve` (git://) and `fg serve-ssh` (OpenSSH 10.2p1), with
one fresh node per transport. Assertion ids are
`TCAP-{host,pinned}-{sha1,sha256}-{http,git,ssh}-<check>`.

The push-option rows were added at **9db4d8bd** (frankengit-321s), and the
typed push-option refusal at **5a3a4d81** (frankengit-yrff). With a release
`fg` of that code (sha256 `b0d3e0fb33d89acb…`), the suite's helper recorded
684 checks, 342 for each git (host 2.56.0 and pinned 2.54.0), and all passed.
That run was the helper invoked directly, not the suite runner.

| Capability | Check ids (`<check>`) | Result at 05e29b11 |
|---|---|---|
| Partial clone, `blob:none` and `blob:limit=1k` (v2; `blob:none` also v0) | `filter-blob-none-*`, `filter-blob-limit-*`, `filter-blob-none-v0` | pass; the clone's missing set equals the source's own `rev-list --filter-print-omitted` |
| Partial clone, `tree:0`, `tree:1`, `combine:blob:none+tree:2` | `filter-tree-0-*`, `filter-tree-1-*`, `filter-combine-*` | pass; omission observed, promisor recorded |
| Lazy fetch from the promisor remote | `lazy-object`, `filter-*-lazy-checkout` | pass; one object byte-equal, and a checkout restores the source tree exactly |
| Sparse filters (`sparse:oid=<rev>:<path>`, `sparse:oid=<oid>`, v0 and v2) | `sparse-{expression,object-id}-v{0,2}-refused` | refused, deliberately: the client's first fatal line is upstream's `fatal: remote error: filter 'sparse:oid' not supported`, beside the served `blob:none` twin. Before 05e29b11 it was a hang-up, an HTTP 400/503 or sideband noise (24 failing checks at ebd8e04b). Over HTTP v0 the client adds "remote end hung up" after the error, exactly as it does against upstream `git-http-backend` |
| Git notes (`refs/notes/commits`) | `notes-fetch`, `notes-push`, `notes-roundtrip` | pass |
| Submodule gitlinks, submodule objects absent by design | `gitlink-clone`, `gitlink-push` | pass; a push moving the gitlink publishes, and a fetch reads it back |
| Atomic push | `atomic-success`, `atomic-all-or-nothing` | pass; a refname-conflict refusal of one update rejects both and leaves every ref unchanged |
| Non-atomic push | `non-atomic-per-ref` | pass; the valid ref publishes, the conflicting one gets per-ref `[remote rejected]` |
| Push options (`git push -o ci.skip -o key=value`) | `push-options` | pass at 9db4d8bd. Before it, every transport failed on the client ("the receiving end does not support push options"), because nothing advertised the capability. The options are sealed in client order into the request's canonical digest (node test `guarded_git_daemon` `push_options::advertised_push_options_are_sealed_exactly_and_in_client_order`) |
| Push option past the sealable bound (1,025 bytes) | `push-option-bound` | refused with nothing published, beside a 1,024-byte twin that publishes. Since 5a3a4d81 the client's first fatal line names the cause on every transport: `fatal: remote error: a push option is empty, longer than this server accepts, or contains NUL, CR or LF; no ref decision was attempted` (frankengit-yrff) |

Divergence: fg serves filters without an `uploadpack.allowFilter` switch
(DIV-TA-002). Non-claims: loopback only, one node per transport, filter
correctness judged by omission and lazy-fetch content rather than by pack
bytes, and no claim about `object:type` or other filters stock git does not
send by default.

## Conditional deletion of an absent ref

An all-zero old and new object ID is a delete command with an explicit
absent-ref precondition (frankengit-l6mb). When that ref is absent, it succeeds
as an identity no-op: it requires no pack, retains the original command in the
sealed request and terminal result, and leaves the ref root unchanged. In a
mixed push it does not prevent another valid command from publishing. Atomic
pushes still share one decision; non-atomic pushes retain independent command
outcomes and recovery identities.

The same command targeting an otherwise permitted present ref receives
`stale info` and cannot delete it. This preserves the old-ID assertion and is
the explicit DIV-TA-004 safety divergence below. Hidden-ref authorization runs before either the
no-op or expected-old comparison, so both hidden-present and hidden-absent
targets receive the existing generic hidden-ref refusal.

Default-branch protection still refuses deletion of an existing HEAD target,
including a zero-old request. An unborn HEAD target has no branch to delete,
so the conditional absent-ref no-op succeeds. No-op-only pushes use the
existing committed-noop decision path: they change no ref or object closure,
while retaining the sealed request and terminal outcome for retry and recovery.

Authored regression coverage includes both native object formats, packless
quarantine handoff, capability/name/count bounds, cancellation, mixed
atomic/non-atomic outcomes, exact sealed identity, and recovery after a node
restart, including an unborn HEAD no-op retried through another receive
adapter after reopening the node. The stock-client helper above includes
`absent-delete-{atomic,non-atomic}` and
`absent-delete-create-{atomic,non-atomic}` for each configured HTTP, git://,
and SSH transport and hash format. These additions are not included in the
historical executed counts above; their execution is reported separately at
the tested source revision.

## Many-reference admission and publication

Native imports and atomic pushes admit up to 4,096 commands. Non-atomic pushes
admit up to 16,384 independently sealed commands through a versioned session
carrier, subject to independent byte, object, storage and work budgets
(frankengit-p9b5). The parser retains a distinct atomic command bound, so a
larger non-atomic envelope does not widen a single transaction. HTTP/CLI indexed
recovery accepts indices through 16,383; whole-session response assembly allows
up to 64 MiB while respecting a tighter server ceiling. Non-atomic option
replication is bounded to 16 MiB before lowering or sealing, with retained
header work charged even for empty options.

Complete-input native and loopback adapters feed bounded fragments into the
wire parser, so the closing flush does not make an otherwise valid 4,096-command
request exceed the per-call packet budget. Tighter configured packet limits
remain effective, and cancellation is checked between fragments. Non-atomic
recovery descriptors must fit the unchanged 1 MiB v1 envelope through 4,096
commands or the 4 MiB v2 envelope above that count before any retry key is
reserved. A smaller backend body limit also applies. An oversized descriptor
leaves an otherwise unused key available for a corrected request. V2 binds
canonical chunk digests and the complete original wire permutation; it preserves
every child key and transaction identity. Authored tests cover 16,384 commands
through the real reference-authority planner/seal/CAS path and a 4,097-command
HTTP restart/recovery path. These are separate from the historical stock-Git
campaign results below; native execution must be reported at its tested revision.

The continuing durable receive path combines up to 64 independent command
decisions into one bounded publication (frankengit-x0v8). Individual seals,
transaction identities, commit/refusal records and wire-order status remain
independent. Each successful command advances the batch's scratch refs for
later commands; a refusal does not discard successful siblings. Atomic
requests retain one all-or-nothing decision. This is combining within one
session, not a cross-session scheduler or an end-to-end throughput claim.

The repository-owned stock-Git campaign is
`scripts/e2e/helpers/many_ref_admission.py`. It creates a mixed branch,
lightweight-tag and annotated-tag corpus in both hash formats, verifies the
complete ref map after imports and atomic/mirror pushes, and repeats each
operation. For example:

```sh
python3 scripts/e2e/helpers/many_ref_admission.py \
  --fg /absolute/path/to/fg --counts 64,256,1024,4096 \
  --summary /tmp/many-ref-admission.json
```

Its default is 1,000 refs over the existing git://, HTTP and SSH helpers.
Recorded elapsed times describe the supplied binary and host; they do not
establish a release performance envelope. This authored campaign and the new
native/model regressions are not included in historical executed totals.

## Tier A: the declared differential tier

### Rejected upload wants

Upload-pack applies the same visible-object reachability boundary to wants in
protocol v0, v1 and v2, including when no refs are visible. A stored object from
deleted or hidden history and a never-stored object receive the same
`ERR upload-pack: not our ref <oid>` packet, before any pack output. The
diagnostic echoes only the requested object ID. Smart HTTP carries this Git
protocol error in a `200` upload-pack RPC response; malformed framing retains
its separate transport refusal (frankengit-aitq).

The stock transport campaign includes deleted-commit, deleted-blob and
unknown-object refusal cases, each paired with a successful visible-commit
fetch. `--focus unreachable-wants` runs those cases across both native hash
formats and all three transports. These authored cases do not change the
historical executed counts below.

### Differential scope

Tier A is the narrow compatibility tier the plan's Phase 2 exit and 1.0
definition of done (item 2) require to pass differentially. Its rows are
declared in [`registries/compatibility_tiers.tsv`](../registries/compatibility_tiers.tsv).
Each row names the surfaces of the table above that it evidences, plus its
service, transport, protocol, object format, operation, oracle pin and owning
suite. The registry checker refuses a row that cites a surface not in that
table, names an undeclared pin, or is owned by a suite that is not a
pinned-oracle suite or never asserts the row.

`./scripts/verify.sh tier-a` builds `fg` once and runs every owning suite
against the pinned upstream Git oracle. It writes `tier_a_receipt.json` with one
status per row, bound to the source revision, the `fg` digest, the registry
digest and the oracle's install receipt.
- Exit 0 means every row passed.
- Exit 3 means the oracle was unavailable and no row ran.
- Any other exit is a failure.
- A row with no executed assertion is `not_run`, never passing.

For each row, [`tier_a_differential.py`](../scripts/e2e/helpers/tier_a_differential.py)
runs the same operation twice: against pinned Git, over file transport inside
the sandbox, and against `fg serve`, over loopback `git://` through the oracle's
fixed loopback modes. It runs each operation on SHA-1 and SHA-256 copies of seven
corpora:
- an empty repository;
- 1,200 linear commits;
- a 2,500-file tree with nested, spaced, UTF-8, executable, symlink and empty
  entries;
- 80 revisions of a 120 KB file packed at Git's default delta depth;
- branches, a merge, an octopus merge, an orphan root, an empty tree, and
  annotated, lightweight and nested tags;
- a repository whose default branch is `trunk`, initialized with
  `fg init --initial-branch trunk` to match;
- one commit of 20,000 files, about 20,100 objects. Before frankengit-eq4h
  every pack over about 16,400 objects was refused (NEG-037).

It compares:
- import of each corpus;
- v0 and v2 advertisements and capabilities, and `ls-refs` (with `unborn`);
- HEAD, refs, the object set, `fsck --strict` and the checked-out index after a
  clone;
- full and incremental fetch over protocol v0, v1 and v2;
- push report-status and the resulting refs for create, fast-forward, tag,
  rejected and forced non-fast-forward, atomic multi-ref, an ordinary
  delta-chained history, a push of over 20,000 new objects, delete,
  deletion of HEAD's branch, and a directory/file refname conflict.

Declared divergences are capabilities `fg` advertises that upstream advertises
only under non-default configuration. The first two are served inside `fg`'s
exact-head visible-graph proof:
- DIV-TA-001: `allow-reachable-sha1-in-want`;
- DIV-TA-002: `filter`;
- DIV-TA-006: `push-options` on `git-receive-pack`. Upstream advertises it only
  with `receive.advertisePushOptions`. `fg` advertises it on every transport
  since 9db4d8bd (frankengit-321s) and seals the options into the request's
  canonical digest.

Every other capability `fg` advertises must also be advertised by pinned Git,
and the Tier A capability subset must match exactly.

Upload-pack's visible-object boundary has an additional deliberate divergence:

- DIV-TA-005: `fg` refuses wants for objects outside the visible ref graph,
  including blobs and protocol v2 requests. The pinned upstream 2.54.0 probes
  recorded in frankengit-aitq serve an unreachable blob in v0 and both an
  unreachable commit and blob in v2; `fg` deliberately does not disclose them.
  Every such refusal carries `ERR upload-pack: not our ref <oid>`, matching
  upstream's v0 unreachable-commit diagnostic. Stored-but-unreachable and
  never-stored objects have identical diagnostics; reachable twins still
  succeed. This boundary does not change when the visible advertisement is empty.

Report-status must match byte for byte except for the following explicitly
scoped divergences. DIV-TA-003 changes reason wording only; its accept/refuse
decision and target ref must still match:
- DIV-TA-003: deleting HEAD's branch. Upstream says `deletion of the current
  branch prohibited`; `fg` refuses it through its ref-protection policy and says
  `protected ref denied`.
- DIV-TA-004: a raw all-zero old/new command targeting a present ref. Upstream
  permits a zero-old delete as an unconditional corruption-recovery operation.
  `fg` retains `ExpectedOld::Absent` and refuses with `stale info`, preserving
  the present ref; existing default-branch and hidden-ref protections retain
  their own refusals. An absent target succeeds in both implementations, and a
  delete carrying the correct nonzero old ID remains supported. This single
  precondition case deliberately differs in acceptance; it does not relax
  outcome parity for ordinary deletes, other commands, or hidden-ref policy.

The push node runs at `fg serve`'s default session and processing budgets, so
the many-objects push is checked against fg as shipped. Before batched receive
placement (frankengit-pc9g), those defaults refused any push of more than about
15,000 objects, and the lane had to raise both budgets.

Non-claims: Tier A covers the `git://` loopback carrier only. Smart HTTP and
SSH carry the same upload-pack and receive-pack state machines, but they are not
Tier A rows until the oracle has a constrained mode for them. Shallow and
partial clone, LFS, signed push, bundle URI and notes are outside Tier A. This
section states no result; the receipt does.

Last observed receipt (an observation, not a standing claim): 2026-10-21 at
`18f77336`, clean tree, receipt sha256 `b98bfaa2…`, `fg` sha256 `a298e9ce…`.
Verdict **pass**: 18 of 18 rows and 624 of 624 checks, over seven corpora,
with the push node at `fg serve`'s default budgets. The 20,100-object import
took about 15 s, the 20,000-object push about 17 s, and the 1,200-commit
import 4.0 s. Pinned git-2.54.0 clones that 1,200-commit corpus in 0.08 s on
the same host, so import is still about 50 times slower (frankengit-pc9g).
Earlier receipts at the same oracle record the defects this lane found and the
fixes that cleared them:
- `8a992b6e`: 18/18 rows; the push node needed both receive budgets raised to
  1800 s, and the 20,000-object push took about 391-396 s.
- `f5e1a106`: 16/18 rows; the many-objects push was refused at the 300 s
  session budget (`frankengit-3gdw`). Every import, clone and fetch row of the
  new corpus passed.
- `d376cb0d`: 18/18 rows, 544 checks, over six corpora. Packs over about 16,400
  objects were still refused at that revision, but no corpus that large existed
  yet (`frankengit-eq4h`, fixed in `71e1f6fa`).
- `e2ced51a`: 2/18 rows, every failure in the delta corpus
  (`frankengit-z6rb`, fixed in `d376cb0d`).
- `8248db67`: 2/18 rows, with
  - HEAD never published (iahh, fixed in `ee2db3fd`);
  - the refname-conflict acceptance (`frankengit-vbqe`, fixed in `e2ced51a`);
  - the delta budget.

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
pack: `PackLimits.max_total_expanded_bytes`, 4096 MiB by default on every
transport and for `fg export`. The writer streams (frankengit-8xyq): objects
are loaded, decided and written one at a time to unlinked scratch, so the
envelope bounds work and scratch disk, while memory is the delta candidates,
bounded by the profile and enforced as `max_cached_bytes` (128 MiB). Every
serving command and `fg export` set it with `--pack-max-expanded-mib`. An
over-envelope selected pack is refused before any pack byte is emitted: a
client that negotiated sideband-64k receives one Fatal sideband message
naming the limit (diagnosable, not an unexplained early EOF); without
sideband the connection ends as in upstream mid-service failure. `fg export`
prints the typed refusal directly.

For network upload-pack, the verified visible graph now supplies an exact
preflight after wants, haves, shallow boundaries, filters and tag inclusion.
The complete selected expanded size and each selected object's serving limit
are checked before body reads. That prepared selection also drives the writer,
which still verifies the selected bodies before exposing its completed pack.
Successful selection earns time using the existing rate and hard extension
cap, shared with client ingress; repeated selection does not accumulate credit.
The Transfer context preserves its remaining poll/cost quotas and priority,
and expired or cancelled contexts earn no extension. Flat scaling stays flat.
Git and SSH have a one-shot finite terminal-write phase for selected-pack
refusals, including work expiry, without reopening input or computation.

The same prepared keys now carry deterministic basename hints from verified
visible trees. A metadata-only source adapter makes buffered and streamed
objects agree with those keys, preserving IDs, kinds and reader ownership.
The [basename grouping contract](UPLOAD_PACK_VISIBILITY_AND_TAGS.md#verified-basename-grouping-for-served-packs)
changes served pack order and possibly bytes, not closure/filter/have decisions
or the frozen profile's comparator, encoding and resource rules. Local export
keeps its existing zero hints. Pack-component regressions cover both hash
formats and actual decoded content; they are not a stock-client or full node
integration result.

Smart HTTP selected-pack resource refusals use a bounded Git ERR packet inside
HTTP 200, before any negotiation or pack bytes, so v0/v2 and quiet clients can
read the cause. Only public size/output/window limits, named runtime exhaustion
and the selected-pack session timeout are reported this way. Other failures
retain their existing status mapping. The native TCP regressions in
`fgit-node/tests/smart_http_server/upload_limits.rs` cover an accepted push,
quiet refused clones, an unchanged authority head, and successful native pack
verification after raising only the upload envelope in both object formats.
These are authored integration regressions, not a new stock-client performance
or compatibility measurement.

The per-object body ceiling does not reject unselected blobs reached through
verified tree or tag edges during the pre-advertisement metadata walk. Their
bounded envelope reads still check identity, namespace, kind and exact file
length; bodies selected for a pack still pass the original size and native
identity checks before publication. Thus ref listing, up-to-date fetches and
filters omitting a large blob remain usable without widening body limits.
Untyped ref-root objects and commit/tree/tag parsing retain their limits.
The authored `upload_visibility::tests::partial_clone::blob_limits` regressions
exercise protocol v0/v1/v2 and both native hash formats using a 4,096-byte blob
against a 4,095-byte serving cap, with an exact-bound successful clone,
malformed-header refusal, deleted-ref isolation and unchanged canonical state.
These are native loopback packet tests, not a stock-client compatibility claim.

**Explicit large selected blobs.** `fg export`, `fg serve` (library and guarded
bindings), `fg serve-http` and `fg serve-ssh` accept the same checked
`--pack-max-blob-mib <non-zero>` option. Embedded consumers use
`NodeConfig::with_selected_pack_blob_limit(bytes)`. A limit above 32 MiB selects
`git-pack-compressed-v6`, `git-pack-compressed-v6-thin` or
`git-pack-compressed-no-delta-v2`; existing defaults and profile identities remain
unchanged. Larger blobs are whole base entries read from a retained file
descriptor and compressed in fixed 16 KiB chunks, never object-sized source
buffers, delta candidates or retained compressed cache entries. They clear the
candidate window and are skipped as optional client-held thin bases. Exact
length, EOF, native identity and the stronger fabric payload commitment are
verified before scratch promotion; cancellation, corruption, short/long reads,
encoder receipt mismatches and sink failures abort custody. The explicit fabric
stored-file allowance includes envelope/framing overhead while eager-import,
receive and buffered metadata limits remain unchanged. Independent selected
object, expanded-pack, output, compression-work and time limits still apply.

The authored pack component tests cover both hashes, short-read-independent
bytes, planned/streamed equivalence across delta-window barriers, malformed
sources, cancellation, sink failures, thin-base skipping and bounded cache
behavior. A generated 33 MiB source never allocates its full body. Native node
fixtures also cover a 33 MiB sparse stored blob through the actual selected-pack
consumer, exact-limit refusal and late-corruption cleanup, plus both-hash small
exports and v0/v1/v2 fetches under the explicit configuration. CLI regressions
cover shared 32/33-MiB boundaries, malformed/overflowing values, duplicate and
missing options, command scope and application to every serving configuration.
These fixtures are implementation coverage, not a claim that the stock-client or full native
batch gates have run at this revision.

The **upload read ceiling** (frankengit-root-doctrine-x2mv.4.53) bounds the
object-fabric reads behind one served pack under the Database class, anchored
at the session's greeting.
- A session that idles or stalls past the class deadline (default 15 s) is
  refused with the exact Database dimension (x7ja R5).
- Those reads follow the same work-proportional doctrine: each verified object
  byte read earns the session's per-byte allowance (about 1 s per MiB by
  default, up to the extension ceiling). The poll and cost quotas carry over
  unchanged.
- A read that delivers nothing earns nothing, and the session deadline still
  bounds everything.

A clone of a few hundred MB therefore reads under a ceiling proportional to its
size instead of failing at 15 s. The disclosure walk reads typed blob headers;
the selected-pack consumer reads and verifies the requested bodies. A streamed
blob earns its verified-byte credit only at exact EOF, so unverified partial
chunks cannot extend the Database ceiling.

**Thin fetch packs** (frankengit-pazc). Upload-pack advertises `thin-pack` on
every transport. A fetch that requested it, with `ofs-delta` and at least one
have, and that is full-history and unfiltered, is written with the
`git-pack-compressed-v5-thin` profile. V5 is V4 with delta candidates also
bounded by body bytes: a decision looks back over at most 128 MiB of
preceding bodies (frankengit-8xyq), which bounds a streamed pack's memory.
Where the nearest 32 bodies fit, V5 plans exactly as V4. V4 is V3's plan with the
`fixed-or-stored-v1` DEFLATE profile (frankengit-uf91): a member block whose
fixed-Huffman encoding would not beat a stored block is stored, so
incompressible objects are copied rather than bit-encoded and do not grow.
Every other block is byte-identical to V3.
- An entry may then delta against a client-held object that the pack does not
  carry, emitted as REF_DELTA.
- Candidates come from a bounded tree walk: every commit the pack sends is
  compared with the client's first four permitted have commits, at the same
  paths and of the same kind. That means every sent commit, not only the tips:
  a path's first version in pack order has no in-pack base, so it would
  otherwise ship whole (NEG-034). Only differing subtrees are walked, up to 4096
  commit and tree reads, and there are at most two bases per target.
- Every base lies in the permitted closure of the client's haves. A have outside
  that closure, such as a hidden ref's commit, supplies none.
- Bases are paid from the same per-target work budget as in-pack candidates.
  An in-pack base wins an equal-length tie.
- Clones (no haves), shallow and filtered fetches, and clients without
  `thin-pack` keep the self-contained `git-pack-compressed-v5` pack, byte for
  byte.

A client base must beat the best in-pack choice by more than its REF_DELTA
base ID. Each client base it names is one more object that stock git stores
whole (`index-pack --fix-thin`), so middle versions chain in-pack and only a
path's chain root goes thin (NEG-034).

Measured:
- suites/transport/thin_fetch.sh, a 60,000-line file shifted by three lines:
  the one-commit fetch drops from about 254 KB, the size of a clone, to about
  520 B, on protocols 0, 1 and 2 over `fg serve` and `fg serve-http`. Stock git
  completes the pack, and `fsck --strict` passes.
- The FG-028c matched harness, stale fetch 3 commits behind, received pack
  (`wire_pack_bytes`): 930,515 B before (99.7% of the clone) and 1,818 B after
  (0.19%), against upstream git daemon's 1,899 B. FG-028C-E2E-036 gates this at
  10% of the clone. Bytes written to the client (`egress_bytes`) fall only to
  654,591 B, because git stores the fetched pack's bases whole.

These are two corpora, not a general performance claim.

`fg serve` selects the receive envelope explicitly: `--session-timeout-secs`,
`--session-secs-per-mib`, `--session-max-extension-secs`, `--processing-timeout-secs`,
`--receive-max-input-mib`, `--receive-max-expanded-mib`; `fg serve` and
`fg export` select the write-side envelope with `--pack-max-expanded-mib`
(4096 MiB by default; `fg serve-http` accepts 1..65536).

Refusal behavior by phase: a deadline that fires while the client is still
sending (greeting, command section, pack stream) is a typed serve error and
the connection ends, matching upstream mid-transfer failure behavior; a
processing deadline starts after the complete trailer, independently of the
elapsed ingress clock. Writer admission and native database work share its
remaining time. Expiry during admission preserves outcome uncertainty
(cancellation never proves non-commit, normative contract section 5.2): the
guarded receiver emits an unknown-outcome `ERR`; the legacy receiver emits an
unknown-outcome report-status notice. A known terminal result is reported as
such even after a late cancellation. Each final response gets one fresh finite
session allowance, with no byte extension or unbounded delivery guarantee.
Tier A's push node uses the default finite ingress and processing flags; this
contract update is not a new execution of that differential lane.

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
