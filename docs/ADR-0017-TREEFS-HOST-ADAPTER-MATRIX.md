# ADR-0017: D7 TreeFS Host Adapters Are an Explicit Support Matrix

- **Status:** proposed
- **Date:** 2026-08-23
- **Decision owners:** TreeFS and Git-materialization architecture
- **Scope:** plan decision D7 — direct API, sparse-directory, and FrankenFS/FUSE
  host-adapter profiles
- **Binds:** `frankengit-fg026-treefs-y3p`,
  `frankengit-fg052-materializers-gy4`, and `frankengit-fg076-treefs-crash-matrix-mnmu`
- **Spec sections:** plan §§17.1–17.3 and D7; `docs/GIT_TREE_FS.md`
  §§10 and 14; `AGENTS.md` §§3.1–3.3, 4, 5.4, 6, and 9

## Context

TreeFS is a direct, pure-Rust workspace model over an immutable Git tree and a
copy-on-write overlay.  Its direct API is the reference semantics.  The plan
also names two optional host-adapter families: a deterministic sparse
directory for tools which need pathnames, and a FrankenFS/FUSE mount on
supported systems.

The repository already has two adjacent, deliberately narrower capabilities:
`SparseManifest` computes the immutable, capability-checked manifest that a
future sparse-directory writer must consume, while `UstarArchive` and
`ZipArchive` return deterministic bytes.  Neither writes a host directory,
mounts a filesystem, imports host outputs, or gains authority.  Treating
either as a FUSE or sparse-directory implementation would make fixtures and
preparation formats look like live host proof.

`fgit-treefs` therefore deliberately exposes no FUSE host adapter today.  Its
crash matrix records the FUSE read/writeback and host-output/import points as
structurally absent rather than manufacturing a mock mount.  This ADR makes
that absence, its consumer-facing support matrix, and the conditions for
changing it explicit.

## Decision (proposed)

1. **Direct TreeFS API is the normative and supported host-independent
   profile.** It is the only profile allowed to define workspace semantics,
   path-capability checks, overlay state, or publication proposals.
2. **Archive bytes and sparse manifests are supported derived products, not
   host adapters.** They are safe to rebuild from their source coordinate and
   must retain their receipts.  A caller may inspect or persist their bytes,
   but neither result authorizes a ref move, a host write, or a filesystem
   scan.
3. **Sparse-directory support requires independent host-profile acceptance.**
   The candidate below consumes the manifest, which is not a substitute for
   the writer. A supported writer owns
   descriptor-relative creation, generated-parent handling, alias tracking,
   symlink refusal, bounds-before-I/O, output reconciliation through the
   manifest, cancellation, and cleanup. A profile without that acceptance
   remains unavailable for a release claim.
4. **No FrankenFS/FUSE mount is currently advertised on any target.** There is
   no first-party unsafe exception, FFI shim, native-library dependency, or
   hidden mount helper.  A missing adapter is not a successful no-op and must
   not be represented as one; consumers use the direct profile or do not offer
   a mount operation.
5. **Future profiles are additive and target-scoped.** A proposed FUSE or
   directory-writer profile must name its target triples, toolchain, exact
   dependency/unsafe/FFI audit, authority boundary, Asupersync region-owned
   lifecycle, cancellation/reap behavior, resource limits before host I/O,
   and a compatibility matrix.  It may not alter direct API semantics.

## Alternatives and why they are rejected

**A. Call `SparseManifest` a sparse-directory adapter.** Rejected: it does not
perform host I/O or output reconciliation.  That label would present a
preparation artifact as live filesystem evidence.

**B. Use a system FUSE helper or native library behind a Rust wrapper.**
Rejected: it contradicts the pure-Rust, no-FFI construction boundary and
creates an unreviewed second lifecycle owner.

**C. Add a mock mount solely to make the FUSE crash matrix execute.** Rejected:
the resulting test would establish mock behavior, not kernel-visible path
security or teardown.  The current structural-absence cells are falsifiable
and name exactly what must change.

**D. Let a host adapter publish workspace output directly.** Rejected: an
adapter is derived and cannot bypass the normal sealed transaction and
authority-head transition.

## Admission evidence for a future host adapter

- A real, safe-only adapter over a declared target matrix, with no alternate
  async runtime or foreign Git/FS helper.
- The `fg026b` path-security corpus exercised through the real mount or real
  directory writer, including traversal, symlink, case/Unicode, and
  capability-denial cases.
- A crash/cancellation matrix covering the newly reachable §14 points, with
  region-owned child/credential/lease cleanup and typed containment failure.
- Receipt linkage to the source authority coordinate and a proof that
  delete-and-rebuild does not change the derived bytes for a fixed profile.
- A dependency-policy row and target/unsafe/FFI audit for every newly admitted
  crate, plus a pinned compatibility evidence row if any external host
  interface is claimed.

## Migration and rollback

The direct API remains stable.  A new adapter is opt-in by explicit profile
and target selection; its cache or host outputs are derived and may be
discarded and rebuilt.  Disabling a profile stops new host work, drains its
region, reaps its resources, and leaves canonical repository state untouched.

## Non-claims

- This ADR does **not** claim that a FUSE mount exists or that the candidate
  sparse-directory implementation has independent batch acceptance.
- It does not claim that archive bytes constitute a working tree or prove
  host-path behavior.
- It does not establish compatibility with a particular kernel, FUSE ABI, or
  upstream Git client.
- `SparseManifest`, USTAR, and ZIP tests establish their declared bounded
  in-repository properties only; they are not live adapter conformance tests.

## Supersession rule

Only an ADR accepted by the TreeFS/materialization owners may add a host
profile.  It must retain direct API normativity, pass the admission evidence
above, and identify the preceding structural-absence test cells that become
real drills.  A convenience wrapper, feature flag, or undocumented helper
cannot supersede this matrix.

## Linux sparse-directory implementation candidate (2026-09-08)

The owner-requested bridge work in `frankengit-audit-treefs-host-zb0q` adds
[`fgit-runner::sparse_workspace`](../crates/fgit-runner/src/sparse_workspace.rs).
It is a concrete directory writer and importer, pending independent batch
verification of the full bead. It does not reopen the FUSE decision or grant
release credit to library tests.

`OneNode::sparse_workspace_manifest_in` supplies the production source
connection: it selects a currently visible ref from authenticated authority,
derives its commit/tree/RCR coordinates, restricts reads to the admitted
closure, and uses the node's existing verified fabric reader and request
checkpoints. Its private ObjectSource cannot be constructed by callers to
pair an unrelated OID with a path grant. The host adapter receives the same
SparseManifest that this method returns. Output remains an ordinary intent
log for admission, with no local-directory authority shortcut.

| Profile | Candidate behavior | Applicability / acceptance |
| --- | --- | --- |
| Direct TreeFS | Existing reference semantics | Host independent |
| Linux sparse directory v1 | Verified manifest to actual files; declared outputs to ordinary TreeFS intents | Linux openat2 and /proc; byte-preserving local filesystem; tests authored for x86_64-unknown-linux-gnu and nightly-2026-08-31; independent batch acceptance pending |
| FrankenFS/FUSE | No adapter | No supported target |

The broker supplies a private 0700 parent directory descriptor and a
`ReservedObligation<SparseDirectoryLease>` from its region. The plan commits
to repository/RCR/commit/tree coordinates, workspace ID, exact input and
output paths, native object identities, modes, and limits. The caller must
reconstruct this plan from authenticated source coordinates when reopening;
the local marker is only a consistency check. It never grants authority.

Creation uses `openat2(BENEATH | NO_SYMLINKS | NO_XDEV)`, exclusive creates,
0600 regular files and 0700 executable files, and distinct inode checks.
Directory creation and cleanup stay relative to owned descriptors. Existing
final/staging names are never overwritten. Files and descendant directories
are synced before a no-replace root rename; parent sync then establishes the
declared durable boundary. A marker-bound interrupted stage can be explicitly
discarded. A crash before its marker exists is an explicit incomplete root
requiring the broker's creation receipt, never a successful no-op.

The completed directory has an exclusive advisory lease. Tools are bounded
trusted processes whose execution/reaping belongs to the runner. Before
import or close, the broker must quiesce them and prevent other principals
from renaming the private parent. This is not a hostile execution boundary.
Import reauthorizes the plan, opens only declared files without following
symlinks, bounds reads before allocation, checks inode/mode/link counts and
mutation metadata, and returns the complete edit log only after all reads
succeed. Read-only input changes refuse. Undeclared outputs never become
edits; cleanup removes them under the declared entry/depth ceiling or reports
containment. A failed cleanup leaves the region obligation unsettled.

Tool output modes map the owner's executable bit to Git's regular/executable
mode. Ordinary umask-dependent group/other permissions are not Git metadata;
the private broker parent still prevents disclosure. Setuid, setgid, sticky
and owner-unreadable modes remain refused.

The profile preserves case and Unicode byte distinctions when the host does;
exclusive creation/alias checks refuse collisions. Symlink materialization,
gitlinks, special files, cross-mount traversal, and shared host hardlinks are
unsupported. The immutable `Arc<SparseManifest>` is shared between runs;
each host workspace copies its input payloads and has private changes. The
receipt reports copied bytes and **zero shared host bytes**. This is no claim
of reflink/FUSE performance or million-workspace scale.

### DEP-118 direct-use admission

The required capability is race-resistant descriptor-relative filesystem
access, unavailable in safe std path APIs. The inspected FrankenFS checkout
uses Asupersync 0.3.9 and a local patched fuser edge, and supplies image/VFS
operations rather than this host-directory contract. Importing that closure
would conflict with the selected Asupersync 0.4.9 constellation.

The adapter directly uses the already locked rustix 1.1.4 with default
features disabled, std and fs. DEP-118 is reclassified in place under
ADR-0003 Amendment 2's single-winning-row rule; no duplicate row can shadow
it. No package version or checksum is added. The existing runtime closure
already enables these APIs. Its transitive unsafe OS-ABI implementation and
compile-probing build script remain ledgered; no proc macro, native engine,
alternate runtime, network-fetching build script, or first-party unsafe is
introduced. Licensing is Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT.

The oracle is direct TreeFS export identity plus real host operations and
fresh-process interruption tests in
[`sparse_workspace.rs`](../crates/fgit-runner/tests/sparse_workspace.rs).
Replacing rustix with an admitted FrankenFS descriptor API changes only the
physical adapter; it does not change canonical repository bytes. Independent
constitution, target, unsafe/linkage and host tests remain required for
admission evidence. This paragraph does not assert a new vulnerability audit.
