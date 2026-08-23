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
3. **No sparse-directory writer is currently advertised.** The manifest is its
   required input, not a substitute for it.  Until a real writer owns
   descriptor-relative creation, generated-parent handling, alias tracking,
   symlink refusal, bounds-before-I/O, output reconciliation through the
   manifest, cancellation, and cleanup, the host-directory profile remains
   unavailable.
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

- This ADR does **not** claim that a FUSE mount or sparse-directory writer
  exists.
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
