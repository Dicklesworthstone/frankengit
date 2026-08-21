# ADR-0002: The Canonical Encoding Is a Hand-Owned Versioned Binary Framing, Not a General Serialization Format

- **Status:** proposed; resolves open decision D1 (canonical codec) from `COMPREHENSIVE_PLAN_FOR_THE_DESIGN_OF_FRANKENGIT.md` section 47
- **Date:** 2026-08-21
- **Decision owners:** FrankenGit canonical state and codec
- **Scope:** the byte encoding of every immutable FrankenGit body whose digest is an identity, the framing that separates schemas, decode bounds, forward compatibility, and the signed-envelope convention
- **Implements:** `crates/fgit-codec`, on the typed vocabulary in `crates/fgit-types`
- **Does not cover:** digest algorithms, the algorithm registry, signature schemes, and verification, which belong to `fgit-crypto`; and native Git object encoding, which is Git's own format and is owned by `fgit-git-object`

## Context

`docs/ADR-0001-CANONICAL-STATE.md` makes repository truth an immutable decision stream selected by one conditional replacement of an authenticated head. That decision has a consequence it does not itself discharge: every canonical body's identity is the digest of its bytes, so the encoding is not an implementation detail underneath the protocol. It **is** part of the protocol.

Two properties follow, and neither is negotiable.

1. **One value has exactly one byte string.** If a value can be written two ways, it has two identities. A compare-and-exchange that should have lost would win, a duplicate suppression that should have fired would not, and a replay check keyed on identity would let the same logical mutation through twice.
2. **Decoding hostile bytes is bounded before it allocates.** Canonical bodies arrive from peers, from storage, and from repair. A length prefix is an assertion by a stranger, not a fact.

Beyond those, the decision has to serve a system that spans an embedded single node and a hosted multi-region service, runs the same verifier logic in a browser through `WebAssembly`, and must be auditable years later by someone reading a hexdump next to a specification.

`docs/NORMATIVE_PROTOCOL_CONTRACTS.md` section 3.2 fixes the identity rule: an internal identity is a domain-separated digest over the schema's domain tag, its schema identifier, and the canonical body bytes. Section 3.3 fixes the single normative derivation of the logical mutation identity. This ADR chooses the encoding those rules are computed over; it does not restate or amend either rule.

The constitution constrains the answer further. `docs/DEPENDENCY_AND_MEMORY_SAFETY_CONSTITUTION.md` and `AGENTS.md` section 3.3 require a closed dependency universe, forbid build scripts and procedural macros, and require that an external crate earn its place by marginal capability rather than by shortening a prototype.

## Options considered

### A. Hand-owned versioned binary framing

Fixed-width big-endian integers, explicit length prefixes, sorted collections, an explicit frame carrying magic, codec version, domain tag, schema identifier, and payload length. No dependency; the format specification and the implementation are both first-party.

### B. A `postcard`-like compact binary format

Varint-encoded integers, sequence length prefixes, a derive-based schema mapping.

### C. A `CBOR` subset with canonicalization rules

A standard format with an existing specification, restricted to a deterministic profile: definite lengths only, shortest-form integers, sorted map keys, no floats, no indefinite-length items, no tags.

### D. A purpose-built canonical text format

Something in the spirit of canonical `JSON`: sorted keys, no insignificant whitespace, one number form.

## Evaluation

| Criterion | A hand-owned | B postcard-like | C CBOR subset | D canonical text |
|---|---|---|---|---|
| One byte string per value | Structural: fixed widths admit no alternative spelling | Requires a shortest-form varint rule, enforced on decode | Achievable, but the canonicalization profile is the hard part and non-conforming encoders are common | Number and string escaping are a recurring source of second spellings |
| Bounded decoding | Every bound is ours to place and to name in a refusal | Possible, but bounds live in someone else's decoder | Possible with a strict profile; the parser surface is much larger | Text scanning is the least bounded of the four |
| `WebAssembly` portability | No dependency, no platform integers, no allocation surprises | Depends on the crate's own portability | Depends on the crate | Fine, but the largest code size |
| Forward compatibility | Explicit codec and schema major/minor, with a stated rule for unknown fields | Field addition is by convention | Map keys allow additive fields naturally | Additive fields natural |
| Auditability | A hexdump is readable against a one-page layout | Varints are awkward to read by eye | Requires knowing `CBOR` | Best to read, worst to make canonical |
| Dependency cost | None | One crate, and a derive crate is a procedural macro the constitution refuses | One crate plus its canonicalization discipline | None |
| Size on the wire | Largest | Smallest | Middle | Largest |
| Blast radius of a bug | Ours, and fixable in one crate | Shared with every other user of the crate | Shared | Ours |

Two criteria decided it.

**The dependency rule is close to dispositive.** Option B's ergonomics come from a derive macro, and procedural macros are refused. Without the derive, B's remaining advantage over A is varints, which is a size argument. Option C's crates likewise carry more surface than the profile we would actually use.

**Size is the wrong thing to optimize here.** Canonical bodies are small and few: a seal, a commit record, a decision batch, a head. The bytes that dominate a forge are Git objects and packs, which this codec does not touch. Trading a few bytes per body for a format whose canonicality is structural rather than rule-enforced is the right trade at this position. A varint encoding is only canonical if every encoder obeys a shortest-form rule and every decoder checks it; a fixed-width encoding is canonical because there is nothing else to write.

## Decision

**Adopt option A.** The canonical encoding is a first-party, versioned, length-prefixed binary framing, implemented in `crates/fgit-codec` with no external dependency.

### Frame layout

```text
magic          4 bytes, "FGC1"
codec_major    u16 big-endian
codec_minor    u16 big-endian
domain         u32 length + label bytes
schema_family  u32 length + label bytes
schema_major   u16 big-endian
schema_minor   u16 big-endian
payload        u32 length + payload bytes
```

**The frame is transport framing, and is therefore excluded from identity.** `docs/NORMATIVE_PROTOCOL_CONTRACTS.md` section 3.2 says canonical body bytes exclude transport framing, and the frame is exactly that: it makes bytes on a wire or in a store self-describing. A body's **canonical body bytes are its payload alone**, and its identity is computed from that payload together with the domain separation tag and the schema identifier.

An earlier draft of this ADR digested the whole frame, on the reasoning that binding more can only be safer. That was wrong against section 3.2, and it had a concrete cost: re-framing a body under a later codec minor would have changed its identity. `crates/fgit-codec` exposes `canonical_body_bytes` (payload) separately from `encode_body` (frame) so the distinction is in the API rather than in a comment.

### Value rules

- **Integers are fixed-width big-endian.** There is no variable-length form and therefore no shortest-form rule to get wrong.
- **Signed integers are zigzag-mapped** onto unsigned before being written at their declared width.
- **There are no floating-point values.** Nothing canonical may depend on rounding mode, a not-a-number payload, or signed zero.
- **There are no platform-width integers.** This is enforced by the compiler: the encoder is generic over a sealed trait in `fgit-types` implemented for exactly the eight fixed-width integer types, so `usize`, `isize`, `f32`, and `f64` cannot reach the wire.
- **Byte strings, text, and labels carry an explicit `u32` length.** Nothing is terminator-delimited. Text must be valid `UTF-8`, verified on decode.
- **Booleans and optional tags are one byte with two legal values.** Any other byte is refused rather than treated as truthy.
- **Ordered sequences keep their order** and are used only where order is semantic, such as the decisions inside one batch, each of which is evaluated against the prior decisions in the same batch.
- **Unordered collections are sorted by their own encoded bytes** and a repeat is refused. Shuffled logical input therefore produces identical bytes.
- **Maps are sorted-key collections with strictly increasing keys.** There is no map whose meaning depends on iteration order and no map carrying two values for one key. Contradictory duplicates are refused rather than normalized into an invented policy.
- **Labels are bounded lowercase ASCII** over `a`..`z`, `0`..`9`, and `-`, `_`, `.`, `/`. Case folding and Unicode normalization can therefore never move an identity.

The decoder re-verifies ordering and uniqueness on the way in. Without that second check the one-byte-string-per-value rule would hold only for bodies this process wrote itself, and a peer could offer two encodings of one value.

### Bounds

Every length and count is checked against an explicit limit **and** against the bytes actually remaining, before anything is allocated. Nesting depth is bounded. Each bound has its own refusal naming the field, the observed magnitude, and the limit.

### Version rules

- An unknown **codec major** is refused. A future major may reorder or reinterpret fields.
- An unknown **schema major** is refused, for the same reason at body level.
- A **higher minor** is additive, and the two decode entry points treat it differently on purpose. The **preserving** decoder reads the fields its own minor declares and retains the unparsed suffix verbatim, so re-encoding reproduces the original bytes exactly and a process that does not understand a newer body can still relay it without changing its identity. The **strict** decoder refuses a higher minor outright, codec or schema, *even when it carries no new fields*.
- That last clause was not in the first draft, and the mutation campaign is what found it. Bumping a frame's codec minor leaves the payload untouched, so the mutant decoded to the canonical **value** while carrying different bytes: `encode(decode(b)) == b` failed, which is invariant 1. The identity still differed, because the codec version travels in it, so it was not an identity collision — it was a second encoding of one value, the defect one step upstream of one. Strict decoding now accepts only what it can reproduce.
- At a minor the decoder implements, there is no suffix, and trailing bytes there are refused.

The strict entry point refuses a body carrying unknown fields outright, because it cannot hand back a value that would re-encode to different bytes. The preserving entry point returns the value together with the suffix.

### Signed-envelope convention

A signature never changes what it signs. An envelope carries the unsigned body's canonical frame bytes **verbatim** and attaches detached signatures that commit over the body's identity. Adding, removing, or replacing a signature changes the envelope's bytes and leaves the body's bytes and identity untouched. Signatures are encoded as a sorted collection, so their order in memory never affects the envelope's bytes.

A signature whose committed identity is not in the carried body's domain cannot be attached, which is a structural check that needs no key material.

### Boundary with `fgit-crypto`

`fgit-codec` performs no cryptography **and does not define the digest preimage either**. The seam is:

```rust
trait BodyIdentity {
    fn identify(&self, domain: DomainTag, schema: SchemaId, codec_version: CodecVersion,
                canonical_body: &[u8]) -> Result<InternalObjectId, CodecRefusal>;
}
```

Its shape is deliberate. Handing `fgit-crypto` the components rather than a pre-assembled buffer is what stops a second, silently divergent preimage framing from growing inside this crate — which is precisely the failure that a "canonical" codec cannot afford, because two preimages mean two identities for one body.

Two details of that signature were wrong in the first draft. Both were real defects rather than taste, so they are recorded rather than quietly corrected:

- **It must be fallible.** One call site takes its domain from a *decoded frame*, which is untrusted input. An infallible signature leaves an implementor two options for a tag the registry never allocated — panic, or mint an identity nothing can verify — and makes neither visible to the caller. An unregistered domain is now a typed refusal.
- **It must carry the codec version.** The preimage has three fields but the *identity* has four, and an implementor not given the fourth has to invent it, silently mislabelling any body encoded under a different minor. `body_id_of_frame` passes the frame's own codec version, so relaying a body written by a newer minor does not restamp it.

A typed variant, `body_id_of_frame_as::<B>`, additionally pins a frame's domain and schema to an expected body type before identifying it. The registry's refusals catch an unregistered tag and a wrong digest; neither can catch a *registered* tag on the wrong body type, because neither ever sees `B`. The untyped form remains for relay, indexing, and repair, where the caller genuinely does not know what it holds.

`fgit-crypto` owns the preimage framing, the digest algorithms, the code-point-to-construction registry, output lengths, migration, signature schemes, and verification. `fgit-types` owns the *shape* of a digest — an opaque registry code point plus bounded bytes — so every protocol body is expressible before any algorithm is chosen, and choosing one later cannot change a body's shape.

## Consequences

### Positive

- Canonicality is structural rather than rule-enforced, so the most dangerous class of bug in a canonical codec is largely designed out rather than tested for.
- Identity is independent of framing, so a transport or storage change cannot move a body's identity.
- No dependency, no build script, no procedural macro, no platform assumptions; the same bytes on a server and in a browser build.
- Every refusal names the field, the observed value, the bound, and the offset, so a rejected body is diagnosable from one log line.
- A hexdump is readable against a one-page layout, which matters for an audit years after the code was written.
- The whole format is one crate, so a defect has a bounded blast radius and one owner.

### Negative

- Bodies are larger than a varint encoding would produce. This is accepted because canonical bodies are small and few, and the bytes that dominate a forge are Git objects, which this codec does not touch. It is a real cost and would need revisiting if a high-cardinality body class ever became canonical.
- Every schema's encoder and decoder is written by hand, which is more code and more opportunity for a field-order mistake than a derive would be. The golden corpus exists precisely because that risk is real.
- The project owns compatibility forever: no upstream will fix a format bug, and no upstream test suite covers us.
- A third-party consumer must implement the format from the specification rather than reach for an existing library. The specification is short and the corpus is executable, but this is a genuine adoption cost.

## Invariants

1. One logical value has exactly one canonical byte string, in both directions: decoding a body and re-encoding it reproduces the original bytes, and encoding a value and decoding it reproduces the value.
2. Bodies in different domains never share an identity, whatever their payloads.
3. A body's identity depends on its payload, its domain, and its schema, and on nothing else — not on its frame, not on how many signatures are attached to it.
4. No canonical byte string contains a floating-point value, a platform-width integer, an ambiguous map, or a collection whose order is unspecified.
5. Every length, count, and nesting depth is bounded before allocation, and exceeding a bound is a typed refusal naming the bound.
6. An unknown codec major or schema major is refused, never guessed.
7. A body carrying fields from a higher minor can be relayed without changing its identity, and a strict decode accepts only bytes it can reproduce exactly.
8. Attaching, removing, or replacing a signature never changes the identity of the body it signs.
9. Every codec refusal maps to exactly one member of the closed protocol refusal vocabulary, deterministically, so a decode failure and the refusal recorded in the decision stream cannot disagree.
10. A domain no identity registry knows yields a refusal, never a computed identity.
11. Pinning a frame to an expected body type changes whether an identity is produced, never which identity is produced.

## Rejected alternatives

### A `postcard`-like compact binary format

Rejected primarily because its ergonomic advantage comes from a derive crate, and procedural macros are refused by the dependency constitution. Without the derive it is a varint encoding whose canonicality depends on a shortest-form rule being enforced everywhere, in exchange for bytes that do not matter at this position.

### A `CBOR` subset with canonicalization rules

Rejected because the standard is the easy part and the canonical profile is the hard part. Deterministic `CBOR` requires definite lengths, shortest-form integers, sorted keys, no floats, no indefinite-length items, and no tags — at which point the remaining benefit is a parser we would have to constrain anyway, plus a dependency, plus a much larger surface for an attacker than the format we actually use. Interoperability with generic `CBOR` tooling is a real loss and is accepted.

### A canonical text format

Rejected because text encodings are where second spellings live: number formatting, string escaping, and Unicode normalization each admit more than one representation of one value. Human readability is better served by a documented layout plus tooling than by making the identity-bearing bytes themselves textual.

### Reusing Git's own object encoding for internal bodies

Rejected because Git's object format is a compatibility obligation with fixed semantics, not a general body encoding. Overloading it would couple internal schema evolution to Git compatibility and risk internal digests being mistaken for native object identities, which the normative contract forbids.

### Making signatures a field inside the signed body

Rejected because it makes identity depend on who has signed so far. The same logical body would have a different identity before and after countersigning, and a body could not be re-signed without being re-identified.

## Verification

The corpus lives under `crates/fgit-codec/tests/goldens/` as one file per case in a line-oriented text format: the schema, whether the case is valid or a planted defect, the frame length, the canonical body length, the expected identity, and the bytes as lowercase hexadecimal.

The suite only ever **reads** the corpus. Regenerating it is a deliberate act, never something a failing test does for itself.

Coverage as committed:

- one or more canonical goldens for each identity-bearing schema — transaction seal, Repository Commit Record, decision batch, authority head (both at genesis with every optional position absent and advanced with every optional position present), refusal record, and signed envelope with zero, one, and two signatures;
- six planted defects per canonical golden — corrupted magic, bumped codec major, bumped schema major, swapped domain tag, truncated payload, appended trailing byte — each recording the exact refusal it must produce;
- round-trip assertions in both directions for every valid golden;
- a seeded deterministic sweep over generated bodies, with the seed and an input fingerprint in every failure message;
- shuffle-invariance sweeps for sorted collections and sorted-key maps;
- forward-compatibility assertions in both directions: a higher-minor body decodes, preserves its unknown suffix, and re-encodes byte-identically, while an unexplained suffix at a known minor is refused;
- bound assertions that accept a value exactly at each bound and refuse the value one past it;
- the signed-envelope property: three envelopes carrying one body with zero, one, and two signatures agree on the carried body's bytes and identity while differing as envelopes;
- a framing-independence assertion: the identity computed from a body equals the identity computed from its frame, and the frame is strictly larger than the bytes that were identified;
- a domain-separation assertion: the same canonical bytes under two domains produce two identities;
- cross-crate bridge assertions: an identity this crate produces is one `fgit-crypto` verifies and rejects against a different body; the corpus framing equals the production framing; every body domain has a registry row; the corpus algorithm slot lies inside the range `fgit-crypto` reserves for harnesses; and a registered domain on the wrong body type is refused when the caller states what it expects.

On top of that, FG-002c adds the adversarial half:

- **a mutation campaign** over every canonical vector, asserting that each mutant either refuses or decodes to something whose identity differs from the canonical form's. Mutants are exhaustive where that is cheap — every bit of every byte — plus truncation at every length, trailing bytes, payload-length-prefix tampering, and version bumps; a descending collection and a repeated element are constructed directly, because byte mutation cannot reach them. Nothing is random, so a failure names an exact byte and bit. Each campaign asserts it was substantive rather than vacuous: a minimum mutant count and a minimum number of distinct refusal kinds, so a decoder failing for one blunt reason cannot pass as one that diagnoses;
- **an independent verifier**, `fgit-codec-verify`, depending on `std` alone and re-implementing the frame format, the identity preimage and the corpus digest from this document. It shares no code with the crate it checks, because a bug present in both an encoder and its checker is invisible. It re-derives 100% of the canonical vectors, counted rather than assumed;
- **an e2e suite**, `scripts/e2e/suites/codec/codec_adversarial.sh`, running all of the above at one revision with a per-vector NDJSON digest record, and asserting against the manifest that the verifier has not acquired a dependency on what it verifies.

**The committed golden bytes were derived from this specification by a second implementation, written separately from the encoder and discarded afterwards.** The suite therefore compares two independent readings of the format rather than the encoder confirming itself. That is a weaker guarantee than an independently maintained verifier and is the reason FG-002c exists.

## Non-claims

- **No cryptographic claim is made anywhere in this crate.** It computes no digest and verifies no signature.
- **The corpus digest is not a cryptographic digest.** The committed identities were computed with a fully specified non-cryptographic function reserved to the corpus, so the identity path could be exercised before `fgit-crypto` published its registry. It has no collision-resistance property. What the corpus proves is that a body's identity depends on exactly its domain, schema, and canonical bytes and on nothing else; it proves nothing about digest strength. Production identities are computed by `fgit-crypto` through the `BodyIdentity` seam, and binding the corpus to real algorithm slots is FG-002b work.
- **The corpus re-implements the `fgit-crypto` preimage framing rather than importing it**, which is what makes the committed identities a cross-check of that framing instead of a copy of it. An earlier revision of this ADR recorded the resulting drift risk as an open non-claim; **that gap is now closed** by `the_corpus_preimage_framing_matches_the_production_framing`, which compares the two implementations directly across several domains and bodies. Note what the neighbouring test does *not* do: an identity round-tripped through construction and verification cannot detect framing drift, because both routes use the same framing. Only a direct comparison of the two implementations can.
- **The one-byte-string-per-value property is a design property supported by tests, not a proof.** No exhaustive search or mechanized argument has been performed. It is not claimed for any body type not represented in the corpus.
- **Forward compatibility is claimed only for additive minor versions.** A higher major is refused, by design, and no claim of any kind is made about decoding one.
- **Bound values are engineering defaults, not measured limits.** They were chosen for canonical protocol bodies and have not been derived from a workload.
- **This ADR deliberately refines the written head schema in one place.** The normative contract types the head's latest decision and repository sequences as plain sequences, but a repository at genesis has neither. Both are optional here, with an explicit presence tag, rather than reserving a zero sentinel that would travel disguised as a real sequence. This is a narrowing of representable states, not a change to any protocol rule; if the contract owners prefer the sentinel, this ADR yields.
- **No performance claim is made.** No benchmark has been run, and the size cost relative to a varint encoding has been reasoned about rather than measured.

## Supersession rule

A future ADR may replace this encoding only if it preserves exact identity for every body already published, or specifies a migration in which old identities remain computable and are never silently recomputed under the new rules. A codec change that would alter an existing body's identity is a break in canonical history, not an optimization, and the codec major version exists to make such a change loud. An implementation shortcut cannot silently supersede this decision.
