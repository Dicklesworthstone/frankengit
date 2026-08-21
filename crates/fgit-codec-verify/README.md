An independent re-derivation of the `fgit-codec` golden corpus.

This crate exists to disagree. It depends on nothing but `std` — **not on
`fgit-codec`, not on `fgit-types`, not on `fgit-crypto`** — and re-implements
the frame format, the identity preimage, and the corpus digest straight from
the written specification in `docs/ADR-0002-CANONICAL-CODEC.md`.

A bug shared between an encoder and its checker is invisible. The corpus is
worth something only if two implementations that share no code agree on it, so
nothing here is factored for reuse and nothing is imported from the crate under
test. Where the two disagree, one of them is wrong and the corpus says so.

What it deliberately does **not** do:

- mirror `fgit-codec`'s refusal taxonomy — matching taxonomies would be a way
  of sharing a bug. It rejects malformed frames coarsely and says why in prose;
- implement any cryptography. The corpus digest is a fully specified
  non-cryptographic function at a reserved algorithm slot, and re-deriving it
  proves the corpus is self-consistent, not that anything is collision
  resistant;
- decode payload interiors. It reads the frame and treats the payload as
  opaque bytes, which is exactly what identity covers. A defect planted inside
  a payload is invisible to it, and the report says so rather than counting it
  as a rejection.
