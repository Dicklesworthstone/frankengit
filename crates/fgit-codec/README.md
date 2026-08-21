The canonical encoding: one byte string per value, domain-separated framing,
bounded decoding, and the signed-envelope convention.

Every value this crate writes has exactly one legal byte string, and every
decoder re-verifies that property on the way in. That is the whole point: a
body's identity is derived from its canonical bytes, so two encodings of one
value would be two identities for one fact.

Canonical body bytes are the **payload**. The frame is transport framing and is
excluded from identity, so re-framing a body cannot change what it is.

How the rule is kept:

- **Fixed-width big-endian integers.** No variable-length form, so no
  shortest-form rule to get wrong. `usize`, `isize`, `f32`, and `f64` cannot
  reach the wire at all — the encoder is generic over a sealed trait in
  `fgit-types` that they do not implement.
- **Explicit lengths.** Byte strings, text, labels, and collections all carry a
  `u32` count. Nothing is delimited by a terminator that could be smuggled in.
- **Canonical collections.** A logically unordered collection is sorted by its
  own encoded bytes and a repeat is refused, so shuffling the input cannot
  change the output. There is no map whose meaning depends on iteration order
  and no map with two values for one key.
- **Bounded decoding.** Every length and count is checked against explicit
  limits, and against the bytes actually remaining, before anything is
  allocated.
- **Versioned framing.** An unknown codec major or schema major is refused
  rather than guessed. A higher minor is additive: unparsed trailing fields are
  preserved verbatim, so a process that does not understand a newer body can
  still relay it without changing its identity.

The crate performs no cryptography and does not assemble a digest preimage.
`BodyIdentity` is the seam, shaped as *(domain, schema, canonical body)* rather
than *(bytes)* on purpose: `fgit-crypto` owns the preimage framing as well as
the construction, so a second, silently divergent preimage cannot grow here.

The reasoning behind the format, the alternatives that were weighed, and the
explicit non-claims are in `docs/ADR-0002-CANONICAL-CODEC.md`.
