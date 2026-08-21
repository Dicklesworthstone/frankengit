Foundation vocabulary for `FrankenGit`: typed identities, bounded scalars, and
the closed rejection, refusal, and decision vocabularies every other crate
builds on.

This crate holds no algorithm, no runtime, no storage, and no encoding. It
holds the shapes that the rest of the system is forbidden from redefining:

- **Typed identities.** Assigned opaque identities, digest-derived identities
  pinned to one domain separation tag, and native Git object identities in two
  separate hash domains that cannot be compared or converted across.
- **Bounded scalars.** Gap-free monotone counters, codec versions, and byte
  counts. The `CanonicalScalar` trait is sealed over the eight fixed-width
  integer types, which is how "no platform integers and no floating point in
  canonical bytes" becomes a compile-time property rather than a review note.
- **Closed vocabularies.** Pre-seal request rejections and post-seal
  transaction refusals are separate types with separate code-point spaces,
  because one is not repository history and the other is. Decoding an
  unrecognized code point is a typed refusal, never a fallback to a default
  member.

Nothing in this crate panics on caller-supplied runtime data; every
constructor that can reject returns `TypeRefusal`. The `from_static`
constructors are the single exception and exist for `const` items, where a
violation is a compile-time error.
