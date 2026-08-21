# ADR-0003: Own the Hashes That Compute Git Object Identity, Reuse Every Other Primitive

- **Status:** proposed; resolves open decision D8 (cryptography and key policy) from `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md` section 47
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit cryptography registry and key management
- **Scope:** which cryptographic primitives FrankenGit implements versus admits as dependencies, the key-purpose and rotation model, encryption-domain separation, and cryptographic erasure
- **Implements:** `crates/fgit-crypto`
- **Does not cover:** the canonical body encoding, which is `docs/ADR-0002-CANONICAL-CODEC.md`; the deletion states erasure integrates with, which are FG-033; and TLS or transport authentication, which arrive with the runtime's transport profile

## Context

Three documents say the same thing about primitives, in almost the same words.
`SECURITY_THREAT_MODEL.md` section 8: *"Fundamental pure-Rust crypto
dependencies are preferred over bespoke unreviewed primitive
implementation."* Plan section 35.6: *"Fundamental pure-Rust cryptographic
dependencies require explicit review rather than bespoke unreviewed
primitives."* Decision D8 itself: *"Avoid bespoke primitive design."*

Against that, `docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md` section 8
assigns FrankenGit ownership of *"object header and object-ID calculation"*,
*"SHA-1 and SHA-256 repository formats"*, and *"collision defense"*.

These do not conflict, but the boundary between them has to be drawn
deliberately rather than case by case, because case-by-case is how a project
ends up with five hand-written primitives each individually justified.

A fact discovered while drawing it changes the arithmetic. Admitting
`asupersync` 0.4.9 brought its entire cryptographic closure into `Cargo.lock`
with active registry rows: `ed25519-dalek` (DEP-051), `ed25519` (DEP-050),
`signature` (DEP-127), `curve25519-dalek` (DEP-044), `aes-gcm` (DEP-016),
`chacha20poly1305` (DEP-031), `aead` (DEP-014), `poly1305` (DEP-102),
`universal-hash` (DEP-143), `hmac` (DEP-069), `zeroize` (DEP-172), `subtle`
(DEP-132), `getrandom` (DEP-064), `rand_core` (DEP-112), plus `sha1`
(DEP-122) and `sha2` (DEP-123). Reuse therefore costs **zero new crates**.

## Options considered

### A. Own everything

Implement every primitive in-tree. Maximal control, no admission review, and
one dependency story.

### B. Reuse everything

Take all primitives from the admitted closure, including the Git object
identity hashes.

### C. Own the Git identity hashes, reuse everything else

Draw the line at the constitution's own boundary: the hashes that compute a
Git object identity are ours because Git identity is ours; every other
primitive comes from the admitted closure.

### D. Case-by-case

Decide per primitive on its merits at the time.

## Evaluation

**A is refused by the specification.** Three separate documents forbid bespoke
primitive design, and signature schemes and AEAD are exactly what they mean.
The correctness risk is also not comparable to a hash: a signature scheme has
key handling, point validation, malleability and canonicalisation concerns
that known-answer vectors do not close.

**B is refused by the constitution and by a concrete engineering fact.**
Section 8 assigns object-ID calculation to FrankenGit, and the plan section
11.6 collision-defense hook needs the chaining value and the expanded 80-word
message schedule of every SHA-1 compression block. No general-purpose digest
crate exposes that. Building the hook over `sha1` would mean writing the
compression function anyway and then maintaining two SHA-1 implementations
that must agree byte for byte — strictly more code and more risk than owning
one.

**D is refused because it is not a decision.** It re-opens the argument at
every primitive and produces a boundary nobody can state.

**C is what the two constraints actually leave**, and it has the property that
matters for review: the line is stateable in one sentence, so a reviewer can
tell at a glance whether a given piece of code is on the right side of it.

## Decision

**FrankenGit owns the hashes that compute Git object identity. Every other
primitive is reused from the admitted dependency closure.**

### Owned, in `fgit-crypto`

| Primitive | Why owned | Evidence |
|---|---|---|
| SHA-1 (FIPS 180-4) | Constitution section 8; the collision hook needs per-block internals | FIPS 180-4 vectors, block-boundary vectors, Git's published empty-blob and empty-tree identities |
| SHA-256 (FIPS 180-4) | Same; also the internal-identity construction | FIPS 180-4 vectors, block-boundary vectors |
| HMAC-SHA-256 (RFC 2104) | A *construction* over an owned hash, not a primitive: no key schedule, no nonce, no secret-dependent control flow | RFC 4231 vectors |
| HKDF-SHA-256 (RFC 5869) | A construction over HMAC; it is the domain-separation mechanism for encryption domains | RFC 5869 Appendix A vectors |

The construction/primitive distinction is the load-bearing one. A construction
is fully specified in terms of something already owned, and implementing it
adds no new cryptanalytic surface. A primitive is not.

### Reused, from the admitted closure

| Need | Crate | Row |
|---|---|---|
| Signatures | `ed25519-dalek`, `ed25519`, `signature`, `curve25519-dalek` | DEP-051, 050, 127, 044 |
| AEAD | `aes-gcm`, `chacha20poly1305`, `aead`, `poly1305`, `universal-hash` | DEP-016, 031, 014, 102, 143 |
| Secret hygiene | `zeroize`, `subtle` | DEP-172, 132 |
| Randomness | `getrandom`, `rand_core` | DEP-064, 112 |

### The registry consequence, which is not a formality

Every row above reads `allow_transitive_admitted_runtime` with the rationale
*"asupersync 0.4.9 transitive"*. They are admitted **because the runtime needs
them**, not because the key layer does. Treating an existing transitive row as
authorisation for direct first-party use is dependency smuggling.

Each reused crate therefore needs a **direct-admission row alongside** the
transitive one, recording the key-layer rationale, feature policy, unsafe
policy, FFI policy and removal path. Adding rather than reclassifying keeps
"the runtime pulled this in" and "the identity layer depends on this
deliberately" separately auditable: if the runtime's feature closure later
drops one, the row justifying our use survives and the failure is loud.

`DEP-004` (`pure-rust-crypto`) currently matches no real crate. It should
either become a real pattern under this decision or be retired, rather than
remaining a row that looks like policy and enforces nothing.

## Key model

### Purposes

The eight purposes are the threat model's, not this ADR's: identity,
authority/admin, capsule, evidence, package/release, webhook, tenant
encryption, recovery. The set is closed and consumers cannot extend it.

Separation is enforced at three layers, because any one alone is insufficient:

1. **Type** — a key carries its purpose as a type parameter, so two purposes
   are different Rust types and substitution does not compile.
2. **Operation** — capability traits gate operations, so a key of the wrong
   purpose has no such method. Nothing is refused at runtime because nothing
   can be written.
3. **Cryptographic** — each purpose derives through HKDF with the purpose tag,
   code point, epoch and scope in a length-prefixed `info`. Types stop a
   programmer; only this stops the material.

Serialized material is the one place a purpose arrives as data, and that is
where a runtime check belongs.

### Rotation, revocation, erasure

Rotation and revocation are the same question asked of different epochs — may
this epoch *issue*, versus may it *verify* — and collapsing them into one
boolean is how a revoked key keeps signing. They are answered separately.
Rotation retires the previous epoch, which still verifies. Revocation stops
both and leaves nothing issuing, so a caller must rotate deliberately rather
than have a retired key silently chosen.

Cryptographic erasure is a **state, not an absence**. An erased epoch reports
that its material was destroyed and dependent data is permanently
unrecoverable; it never reports "unknown key", because unknown invites a
retry, a resynchronisation, or a corruption diagnosis, and each of those is a
route by which deleted data is resurrected or a deletion obligation is
dropped. Every transition emits a receipt with canonical bytes and a
domain-separated identity so the evidence is a body, not a log line.

### Encryption domains

A key's derivation commits to tenant and repository, so *"a ciphertext copied
across incompatible key domains is not a valid placement"* is true of the
bytes and not only of the annotations.

## Consequences

### Positive

- The boundary is one sentence, so review is cheap and drift is visible.
- Reuse costs zero new crates and does not move `Cargo.lock`.
- The collision-defense hook stays implementable, because we own the SHA-1
  compression function it needs.
- Purpose confusion is a compile error rather than a runtime check that a
  caller can forget.

### Negative

- `fgit-crypto` stops being a zero-dependency crate. That property was
  advertised in its frozen-surface announcement and is given up deliberately.
- Direct admission adds registry rows and audit obligations that transitive
  admission did not carry. That is the cost of doing it honestly.
- Owning four hash-side implementations means owning their correctness
  permanently, including under future toolchain changes.

## Non-claims

This ADR does not claim that reuse makes the reused crates correct, that
FIPS vectors make the owned implementations constant-time, or that the
construction/primitive distinction is a bright line in general — it is a
defensible line *here*, given what the constitution already assigns us.

It does not select a specific signature scheme or AEAD. It says where they
come from; which ones, and with what feature closure, is the admission review
that follows this decision.

The owned implementations carry claim class E1 (local exact): published
known-answer vectors, reproduced by this code, derived from an implementation
outside this crate. That is not a differential-conformance claim against
upstream Git, and it is not a side-channel claim.

Cryptographic erasure evidence is a claim about the key registry, not about
every byte that ever held the key. Erasure cannot reach copies a caller made,
backups, or allocator pages not yet reused.
