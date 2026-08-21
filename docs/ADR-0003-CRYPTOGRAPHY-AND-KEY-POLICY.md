# ADR-0003: Own the Hashes That Compute Git Object Identity, Reuse Every Other Primitive

- **Status:** **accepted** 2026-08-21; resolves open decision D8 (cryptography and key policy) from `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md` section 47
- **Acceptance record:** accepted by GoldLotus as the wave-1 orchestrator ruling for D8 (Agent Mail 7476, 2026-08-21), selecting option C. The evidence cited in the ruling was `fgit-crypto` at `bd92f01` — 96 tests passing, 0 failing, across 7 targets — together with the independent code audit's re-verification of all 38 FIPS known-answer vectors, which returned zero findings. Amended the same day during implementation: see *Amendment 1*. The amendment corrects a mechanism this ADR prescribed that does not enforce what it claims, and selects the concrete signature scheme and AEAD that the original text deferred.
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

> **Superseded in part by Amendment 1 (2026-08-21).** The two paragraphs above
> prescribe a *second* row alongside the transitive one. Implementation showed
> that a second row is silently inert, so the mechanism changed. The
> requirement did not: "the runtime pulled this in" and "the identity layer
> depends on this deliberately" must stay separately auditable, and Amendment 1
> meets that requirement a different way. The original text is kept rather than
> rewritten, because the reason a reader should distrust a duplicate row is the
> same reason this paragraph already gives for distrusting `DEP-004`.

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

## Amendment 1 (2026-08-21): concrete selection, and a correction to the registry mechanism

Accepting this ADR authorised two things it had deferred: the direct-admission
registry rows, and the choice of a signature scheme and an AEAD. Carrying them
out surfaced a defect in the mechanism the ADR itself prescribed, which is
recorded first because it changes how the rest of this amendment is written.

### The correction: one reclassified row, not two rows

The superseded text asked for a direct-admission row to be **added alongside**
the existing transitive row. Against the checker as built, that does nothing.

`tools/registry-check/src/main.rs::active_policy_for_package` resolves a
package to exactly one policy row, preferring an exact `crate_pattern` match,
then the longest pattern, then the **lowest `id`**. Two active rows with
`crate_pattern = ed25519-dalek` therefore resolve to `DEP-051` permanently: any
row added later carries a higher `DEP-NNN` and is never selected. The
unsafe-ledger comparison in `report_unsafe_ledger_policy_mismatches` reads only
the winning row. A second row would be a row that looks like policy and
enforces nothing — the exact failure this ADR already names in `DEP-004`, which
is why the paragraph diagnosing `DEP-004` is kept above rather than deleted.

The corrected mechanism is **one authoritative row per directly used crate,
reclassified rather than duplicated**: `decision` becomes
`allow_direct_first_party`, and `rationale` records the direct first-party
justification *and* the transitive origin. This preserves what the original
mechanism was for. If the runtime's feature closure later drops one of these
crates, the row justifying our own use is the row that is actually consulted,
so the justification survives and the failure is loud.

### The residual gap, recorded rather than papered over

Reclassification makes the row honest. It does not make it a gate, and this
amendment does not claim that it does.

`check_manifests` requires only that every dependency named in a manifest match
*some* active row whose `decision` begins with `allow`. Nothing requires a
crate named directly in a first-party manifest to hold a row whose decision
authorises *direct* use. Under the current checker, `ed25519-dalek` in
`fgit-crypto`'s manifest would pass on the strength of the transitive row alone.
`allow_direct_first_party` is therefore an auditable statement of intent, not an
enforced boundary, and dependency smuggling stays possible.

Closing it is a small check — for each first-party manifest dependency, require
the resolved row's decision to authorise direct use — but it lives in
`tools/registry-check/**`, which this ADR does not own. Recorded as a follow-up
for the registry-checker owner rather than implemented here, and recorded as a
known gap rather than left for a reader to discover.

### Signatures: Ed25519, via `ed25519-dalek` 2.2.0 (DEP-051)

**Rejected alternative: ECDSA over P-256** (`p256`). It is the more widely
interoperable choice and the one a compliance regime is likelier to name. It
was rejected because its dominant real-world failure mode is nonce handling: a
repeated or biased per-signature nonce discloses the private key, and that
failure is silent, produces valid signatures, and is invisible to
known-answer vectors. Ed25519 derives its nonce deterministically from the key
and message (RFC 8032 section 5.1.6), so the failure mode is absent by
construction rather than avoided by care. It also admits no new crate, where
`p256` would.

Ed25519's own known sharp edge is signature malleability and the
divergence between verification definitions across implementations. It is
recorded here rather than left implicit: `ed25519-dalek` 2.x verifies with the
stricter `verify_strict`-style checks available, and FrankenGit treats a
signature as evidence of authorship only, never as evidence of trustworthiness
— the separation plan section 35.6 requires.

**Feature closure: `default-features = false`, no additional features.** This is
load-bearing, not tidiness. `default` enables `zeroize`, and `rand_core` enables
in-crate key generation; either adds a dependency edge to `ed25519-dalek` and
moves `Cargo.lock` for all sixteen agents sharing this checkout. Neither is
needed.

**Key material is derived, not generated.** An Ed25519 signing key comes from
`derive_key` (HKDF-SHA-256) with purpose, epoch and scope in the length-prefixed
`info`, and is then handed to `SigningKey::from_bytes`. Key generation stays
inside FrankenGit's own domain separation and the crate is used only as the
primitive. This is why the `rand_core` feature is unnecessary rather than merely
declined.

**Audit surface, stated as measured and not as assurance.** `ed25519-dalek`
resolves `curve25519-dalek` 4.1.3, which contains `unsafe` in its SIMD backends,
runs a build script through `rustc_version`, and pulls the
`curve25519-dalek-derive` proc macro. None of it has been audited by this
project. The unsafe ledger classifies it `ledgered_transitive`, and this
amendment claims exactly that and nothing stronger. Selecting a reused primitive
is a decision about *where correctness risk is concentrated*, not a claim that
the risk is gone.

**Removal path.** The scheme is reached only through the code point registered
in `fgit_crypto::schemes`, and signature bytes are carried in a
domain-separated envelope that names the scheme. Replacing Ed25519 means
allocating a second code point and retiring the first; existing signatures stay
verifiable under the retired row for as long as its status says so. No caller
names `ed25519_dalek` types.

### AEAD: XChaCha20-Poly1305, via `chacha20poly1305` 0.11.0 (DEP-031)

**Rejected alternative: AES-256-GCM** (`aes-gcm`, DEP-016). It is the
standardised choice (NIST SP 800-38D) where XChaCha20-Poly1305 has only a
CFRG draft, and that is a real cost, recorded plainly. It was rejected on nonce
economics. AES-GCM's 96-bit nonce forces one of two options at tenant scale:
maintain a durable per-key counter, which is persistent state that must survive
restore, replication and rollback and is therefore exactly the kind of state
this project treats as authority; or use random nonces and accept a birthday
bound around 2^32 messages under one key. Nonce reuse in GCM is
catastrophic rather than degrading — it discloses the authentication subkey and
forfeits integrity for every message under that key, not just the colliding
pair.

XChaCha20-Poly1305's 192-bit nonce makes a random nonce safe with no counter
and no stored state, which is why it is chosen: it removes a durable-state
obligation from the encryption path rather than adding one. It is also
constant-time on every target without depending on hardware AES.

The draft-status cost is accepted for a specific reason: this is
encryption at rest between FrankenGit and itself. There is no third party to
interoperate with, the algorithm is reached through a versioned registry code
point, and the construction is HChaCha20 key derivation followed by
RFC 8439 ChaCha20-Poly1305 — the underlying primitive is standardised even
though the extended-nonce composition is not. Were an interoperability or
compliance requirement to appear, that is a new code point, not a rewrite.

**Feature closure: `default-features = false`.** Same reasoning as above; the
in-place `AeadInOut` interface needs no `alloc` and no `getrandom`, so the
resolution does not move.

**Domain binding is cryptographic, not annotational.** The key-domain framing
— tenant, repository, purpose, epoch — is supplied as the AEAD's associated
data, so a ciphertext moved across key domains fails authentication rather than
decrypting into something a caller might use. This is what makes plan sections
12.5 and 13.7 — *"a ciphertext copied across incompatible key domains is not a
valid placement"* — true of the bytes.

### Non-claims specific to this amendment

- Selecting these primitives is not a claim that they are correct, and not a
  claim that this project has reviewed them. It is a claim about where the
  risk sits and who carries it.
- `default-features = false` is chosen to avoid moving `Cargo.lock`, but Cargo
  unifies features across the graph: another crate in this workspace may enable
  features on these crates, and the build will then have them. First-party code
  here therefore uses only the featureless API, and no claim is made that the
  compiled feature set equals the requested one.
- No side-channel claim is made about either selection.
- No claim is made that `allow_direct_first_party` is enforced. See the
  residual gap above.

## Non-claims

This ADR does not claim that reuse makes the reused crates correct, that
FIPS vectors make the owned implementations constant-time, or that the
construction/primitive distinction is a bright line in general — it is a
defensible line *here*, given what the constitution already assigns us.

The body of this ADR does not select a specific signature scheme or AEAD; it
says only where they come from. Amendment 1 makes that selection, and the
non-claims attached to it are stated there rather than here.

The owned implementations carry claim class E1 (local exact): published
known-answer vectors, reproduced by this code, derived from an implementation
outside this crate. That is not a differential-conformance claim against
upstream Git, and it is not a side-channel claim.

Cryptographic erasure evidence is a claim about the key registry, not about
every byte that ever held the key. Erasure cannot reach copies a caller made,
backups, or allocator pages not yet reused.
