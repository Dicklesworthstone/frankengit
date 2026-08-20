# Git TreeFS: Sparse Copy-on-Write Workspaces for Humans, Agents, and CI

**Status:** architecture profile  
**Version:** 1.0  
**Last revised:** 2026-08-19

Git TreeFS is FrankenGit’s virtual workspace model. It presents a repository tree as a safe, lazy, versioned filesystem view without requiring a full clone or checkout. The core is a pure Rust library over immutable Git trees and a copy-on-write overlay. Host adapters may materialize ordinary directories or expose FUSE-backed mounts through FrankenFS; the canonical workspace model does not depend on a kernel filesystem or mutable bare repository.

## 1. Motivation

Agent and CI workloads often need a tiny fraction of a monorepo, yet conventional tools clone or materialize broad histories and working trees. This wastes network, storage, inode operations, cache capacity, and context budget. It also gives an agent ambient access to paths, secrets, and history it never needed.

TreeFS makes sparse authorization and sparse materialization the default.

## 2. Workspace identity

```rust
struct WorkspaceSnapshotBody {
    workspace_id: WorkspaceId,
    repository_id: RepositoryId,
    base_rcr_id: RepositoryCommitId,
    base_commit_oid: GitObjectId,
    base_tree_oid: GitObjectId,
    overlay_root: Digest,
    visible_epoch: WorkspaceEpoch,
    durable_epoch: WorkspaceEpoch,
    authorization_root: Digest,
    path_filter_root: Digest,
    toolchain_profile: ToolchainProfileId,
    intent_run_id: Option<IntentRunId>,
}
```

The workspace snapshot is immutable. A mutable session points to its latest snapshot through a local anti-rollback authority record. Tools receive explicit snapshot/epoch receipts rather than a path whose contents may have changed invisibly.

## 3. Tree model

### 3.1 Immutable base

The base is a Git commit/tree closure pinned to one canonical RCR. Tree nodes and blobs are fetched by typed OID and verified before use. Unchanged subtrees retain their original OIDs.

### 3.2 Copy-on-write overlay

The overlay records semantic entries:

- create/replace regular file;
- create/replace executable file;
- create symlink as link-text data;
- delete/whiteout;
- rename/move;
- directory creation/removal intent;
- mode-only change;
- submodule entry update;
- conflict marker object;
- generated-output class and provenance.

It does not copy unchanged file bytes. A commit rebuild touches only changed leaves and ancestor tree objects.

### 3.3 Path identities

Paths are canonical byte sequences subject to Git tree rules and host-adapter policy. The core never resolves through ambient process working directories. Every access is descriptor/capability-relative to a workspace root.

The core distinguishes:

- repository path bytes;
- display-normalized text;
- host filesystem path;
- case-fold/collision key;
- Unicode normalization warning key.

A repository may contain names that cannot be represented losslessly on a target host. TreeFS returns a typed refusal or uses an explicit escaped materialization profile; it never silently aliases two Git paths.

## 4. Access capabilities

A `TreeCapability` binds:

- workspace/base identity;
- read/write path prefixes;
- allowed object classes and history depth;
- symlink policy;
- maximum fetched bytes and file count;
- network/cache class;
- generated-output destination;
- secret class;
- expiration and revocation handle.

Search or graph discovery of a path does not grant access. Lazy fetch rechecks the capability before revealing bytes.

## 5. Read path

1. Canonicalize the requested relative path.
2. Reject absolute, parent-escaping, NUL-containing, reserved, or host-ambiguous forms under the active profile.
3. Consult overlay ancestors for whiteout/rename/conflict state.
4. Resolve unchanged remainder through immutable Git tree objects.
5. Fetch missing object bytes through ATP-Git under the workspace capability.
6. Verify OID, type, size, and parser limits.
7. Return a bounded owned byte view and source receipt.

The read API may stream large blobs and range-read immutable segments. It never exposes an unverified cache buffer as a Git object.

## 6. Write path and epochs

TreeFS adopts FrankenFS’s explicit epochs:

```text
staged_epoch >= visible_epoch >= durable_epoch
```

- `staged`: overlay intent/body exists in session memory or staging store;
- `visible`: subsequent workspace reads observe it;
- `durable`: session journal/snapshot survives declared crash model.

A write operation is reserve → stage → publish-visible → optionally sync-durable. `flush` and `fsync` semantics are explicit per host adapter. CI and agent effect receipts name the durability boundary they require.

## 7. Intent log and net-effect normal form

Every user/tool operation is recorded as a typed `TreeEditIntent` before final commit construction:

```rust
enum TreeEditIntent {
    Write { path, basis_digest, content_id, mode },
    Delete { path, basis_entry },
    Rename { from, to, basis_entry },
    Chmod { path, before, after },
    UpdateSubmodule { path, before_oid, after_oid },
    ApplyPatch { patch_id, expected_spans },
}
```

Evaluation occurs in source order with read-your-own-writes. Finalization folds basis and after-image into a target-disjoint `TreeNetEffect`:

- repeated writes collapse to the final content;
- create then delete becomes explicit inverse-cancellation no-op;
- rename chains become one source-to-destination move where safe;
- write then rename attaches content to the destination;
- delete absorbs earlier modifications;
- mode and content changes combine;
- every source intent maps to one surviving effect, no-op reason, statement error, or transaction abort.

This totality map is preserved in the Evidence-Carrying Change so reviewers can inspect what an agent attempted versus what actually survives.

## 8. Conflict witnesses

A workspace change carries hierarchical witnesses:

1. commit/ref basis;
2. subtree OIDs along changed paths;
3. exact entry before-images;
4. optional line/span anchors;
5. optional symbol/dependency graph witnesses;
6. policy/CODEOWNERS witnesses;
7. generated-file provenance.

The merge/rebase engine begins conservatively. If the branch moved, unchanged subtree OIDs prove many paths independent in O(changed-depth) time. When coarse path witnesses collide, value-of-information refinement may compare spans, syntax nodes, or symbols. Finer witnesses can avoid false conflicts but can never turn a proven semantic conflict into silent last-writer-wins.

## 9. Semantic merge ladder

The merge ladder is ordered from strongest proof to fallback:

1. **Identity/no-op:** proposed after-image already exists.
2. **Disjoint subtree:** changed ancestor paths share no affected leaf.
3. **Disjoint structured patch:** syntax/source-map keys are non-overlapping and before-images match.
4. **Append-only proof:** additions target a format-defined append region with stable identity.
5. **Commutative set/map operation:** schema declares algebra and canonical tie-break.
6. **Intent replay:** re-execute the original edit intent against the new basis and verify claimed postcondition.
7. **Three-way textual merge:** deterministic algorithm and tie-break, result marked for review when conflicts remain.
8. **Typed conflict:** no safe proof; refuse autonomous publication.

Raw byte-range overlay, XOR, or “both patches applied cleanly” is not a semantic proof for source text.

## 10. Lazy process materialization

Many compilers and tools require ordinary filesystem paths. TreeFS supports two adapters.

### 10.1 FUSE/FrankenFS adapter

On supported systems, a safe Rust adapter exposes the virtual tree. Reads trigger authorized object fetch. Writes land in the overlay. Mount lifecycle is owned by an Asupersync region and must reach quiescence before credentials or workspace leases close.

### 10.2 Sparse directory adapter

Where FUSE is unavailable, a deterministic materializer creates only declared inputs plus generated-parent directories. It tracks inode/path aliases, refuses symlink traversal, and reconciles outputs back into the overlay through a manifest rather than scanning arbitrary untrusted directories.

Neither adapter changes canonical workspace semantics.

## 11. Build and test inputs

A CI job receives a `BuildInputCapsule`:

- exact workspace snapshot;
- declared input paths/globs expanded at one source generation;
- toolchain/container/runner identity;
- dependency/package lock roots;
- environment and secret capability classes;
- expected generated-output paths;
- network policy;
- resource budget.

The runner may request additional files only through an audited capability escalation or declared lazy-input policy. This turns hidden undeclared dependencies into evidence rather than cache accidents.

## 12. Agent context and workspaces

Context Packets and TreeFS share source identities. A text span shown to an agent carries:

- repository/RCR/commit/tree/blob IDs;
- path and source span;
- parser/transform profile;
- graph/search generation;
- authorization receipt.

When the agent edits that span, the patch references the same lineage. This prevents review comments, search results, and workspace files from drifting into unrelated revisions without detection.

## 13. Cache and storage tiers

TreeFS uses temperature-aware tiers:

- tiny inline metadata and microtrees;
- hot immutable tree/blob chunks;
- sealed object-aware segments;
- cached Git packs for compatibility clients;
- cold archive/repair placements;
- local verified overlay blocks;
- generated-output cache keyed by complete input capsule.

Promotion/demotion decisions are answer-preserving physical policy. They bind decision cards and cannot alter Git logical identity.

## 14. Crash and cancellation matrix

Tests cover interruption:

- before content reservation;
- mid-stream write;
- after body, before visible overlay pointer;
- after visible, before durable journal;
- during rename chain;
- while lazy fetch is in flight;
- during FUSE read/writeback;
- during process cancellation;
- after output creation, before manifest import;
- during commit-tree construction;
- after new objects, before repository transaction publication.

After restart, each intent is either absent, visible in the recovered overlay, or explicitly refused as incomplete. No orphan mount, process, object-fetch credential, or temporary output survives run closure.

## 15. Security boundaries

- Repository symlinks are data, not host traversal authority.
- Device files, sockets, FIFOs, and special host objects are not synthesized from Git entries.
- Case and Unicode aliases are detected before materialization.
- Generated archives are extracted through a separate bounded safe parser.
- Watchers cannot escape the workspace root.
- Workspace secrets are delivered through brokered handles, never checked into the overlay by default.
- Prompt text in repository files cannot widen a TreeCapability.
- A tool’s access attempts are evidence and may trigger bounded review; they do not automatically prove malice.

## 16. Performance targets and proofs

Target metrics include:

- time to first authorized file;
- bytes fetched before first test/build action;
- overlay write amplification;
- changed-tree construction work versus changed paths;
- process startup latency;
- peak RSS per open file/large blob;
- cache hit/miss and false-prefetch cost;
- cancellation drain time;
- full materialization equivalence.

Every optimization compares the same workspace/input capsule and verifies byte-identical generated Git trees or records an explicit accepted divergence.
