#![forbid(unsafe_code)]
//! Domain-separated digest registry and typed object identities for
//! `FrankenGit`.
//!
//! `fgit-types` owns the identity *shells*: bounded scalars and the erased
//! `GitObjectId` / `InternalObjectId` records. This crate owns everything that
//! turns bytes into one of those records — the digest algorithms themselves,
//! the versioned algorithm and identity-domain registries, the
//! domain-separated internal-identity construction, native Git object identity
//! for both repository formats, and the SHA-1 collision-defense hook point.
//!
//! # Two separations, both enforced by the type system
//!
//! **Algorithm separation.** A SHA-1 Git identity and a SHA-256 Git identity
//! are different Rust types ([`GitOid<Sha1>`] and [`GitOid<Sha256>`]), so the
//! byte-aliasing the compatibility matrix bans is a compile error rather than
//! a comparison that answers `false`. Hex parsing never guesses an algorithm
//! from the input width: on the typed layer the algorithm is the type
//! parameter, and on the erased layer it is a required argument.
//!
//! **Domain separation.** An internal identity is
//! `H(domain_tag || schema_id || canonical_body_bytes)` with explicit
//! length-prefixed framing, and the domain comes from a closed enumeration, so
//! a digest computed for one body class cannot be replayed as another. Replay
//! produces a typed [`InternalIdentityError`], and SHA-1 has no route into an
//! internal identity at all.
//!
//! # Dependency decision (DEP-004, recorded here as the bead requires)
//!
//! **Chosen: in-house pure-Rust SHA-1 and SHA-256, zero external crates.**
//!
//! 1. The dependency constitution section 8 already assigns "object header and
//!    object-ID calculation", "SHA-1 and SHA-256 repository formats", and
//!    collision defense to `FrankenGit`'s owned surface. Obtaining the identity
//!    digest from outside the project would put the one thing the engine must
//!    own behind someone else's release cadence.
//! 2. **The collision-defense hook decides it.** Plan section 11.6 requires the
//!    SHA-1 identity path to run through a collision-detecting profile, and a
//!    `sha1dc`-class detector needs the chaining value and the expanded 80-word
//!    message schedule of every compression block. No general-purpose digest
//!    crate exposes that; implementing the hook on top of one would mean
//!    writing the compression function anyway, and then maintaining two SHA-1
//!    implementations that must agree byte for byte. Owning one core is
//!    strictly less code and strictly less risk than owning a shadow of one.
//! 3. Depending on another crate's transitive closure for a core identity
//!    primitive is fragile. The `sha1` and `sha2` rows in
//!    `registries/dependency_policy.tsv` are `allow_transitive_admitted_runtime`
//!    with the rationale "transitive, direct parent asupersync" — they are
//!    admitted because the runtime needs them, not because the identity layer
//!    does, and they are marked `ledgered_transitive_unaudited`. A direct
//!    dependency would be a separate admission with its own audit obligation,
//!    and a change to the runtime's feature closure would silently turn it into
//!    an unadmitted one.
//! 4. The usual "do not reimplement standards cryptography" hazard is about key
//!    handling, nonces, padding oracles, and secret-dependent timing. SHA-1 and
//!    SHA-256 as used here are unkeyed digests over public bytes with
//!    data-independent control flow, so the residual risk is plain correctness
//!    — which known-answer vectors close completely.
//!
//! **Rejected: `RustCrypto` `sha1` / `sha2`.**
//!
//! **Correction, recorded rather than quietly dropped.** This decision was
//! first justified partly on the cost of admitting the `RustCrypto` closure:
//! new registry rows for `digest`, `crypto-common`, `typenum` (which ships a
//! build script) and `cpufeatures` (which carries internal `unsafe`). That
//! argument is now **void**. Admitting `asupersync` 0.4.9 brought that entire
//! closure into `Cargo.lock` with active allow rows (DEP-025, DEP-037, DEP-041,
//! DEP-048, DEP-063, DEP-070, DEP-122, DEP-123, DEP-140), so using `sha2` would
//! add zero crates and zero rows. The decision stands on reasons 1 to 4 above,
//! which are unaffected; the marginal-dependency-cost reason is withdrawn.
//!
//! Revisit condition: if a digest crate exposes a per-block compression hook
//! sufficient for a UBC check, reason 2 dissolves and this should be
//! re-examined.
//!
//! **Non-claim.** This decision covers unkeyed content-addressing hashes only.
//! Signature verification, authenticated encryption, key derivation, and every
//! other keyed or secret-bearing primitive are out of scope here and remain a
//! real DEP-004 admission decision. Nothing in this crate should be read as
//! precedent for implementing those in-tree.
//!
//! # Evidence and non-claims for the digests themselves
//!
//! Correctness evidence is claim class E1 (local exact): the FIPS 180-4
//! known-answer vectors, block-boundary vectors around the 55/56/63/64/65-byte
//! padding transitions, multi-block and one-million-byte vectors, and the
//! well-known native Git identities of the empty blob and empty tree. Every
//! expected value in `goldens/` was derived from an implementation outside
//! this crate and is checked in as data; the tests assert that this
//! implementation reproduces it. No golden is regenerated from this crate's
//! own output.
//!
//! That is not a differential-conformance claim (E3). Agreement with a pinned
//! upstream Git across a real corpus belongs to the conformance lane and is
//! not claimed here. Nor is any performance claim made: these cores are the
//! scalar portable oracle, and any future optimised variant must reproduce
//! them byte for byte.

mod body_identity;
mod corpus;
mod defense;
mod hashing;
mod native;
mod registry;
mod screened;

#[cfg(any(test, feature = "test-double"))]
pub mod testing;

pub use body_identity::{
    GIT_PAYLOAD_SCHEMA, GIT_PAYLOAD_SCHEMA_FAMILY, InternalIdentityError, git_payload_body,
    git_payload_commitment, internal_algorithm_id, internal_digest, internal_digest_in_domain,
    internal_digest_over_parts, internal_digest_value, internal_domain_tag, internal_id_preimage,
    internal_id_preimage_header, internal_object_id, lowercase_hex, verify_internal_object_id,
};
pub use corpus::{
    ALGORITHM_HEADER, DOMAIN_HEADER, REGISTRY_MARKER, export_algorithm_registry,
    export_domain_registry,
};
pub use defense::{
    BlockVerdict, CollisionDefenseError, CollisionEvidence, CollisionVerdict, Sha1BlockContext,
    Sha1CollisionDetector,
};
pub use hashing::{DigestHasher, Sha1Hasher, Sha256Hasher, sha1_digest, sha256_digest};
pub use native::{
    GitHashAlgorithm, GitHashError, GitObjectHasher, GitObjectKind, GitOid, NativeObjectIdentity,
    Sha1, Sha256, git_object_id, parse_git_oid,
};
pub use registry::{
    ALGORITHM_REGISTRY, AlgorithmRow, AlgorithmUsage, DOMAIN_REGISTRY, DigestAlgorithm, DomainRow,
    IdentityDomain, InternalDigestAlgorithm, RowStatus,
};
pub use screened::{
    Sha1IdentityProfile, screened_sha1_digest, screened_sha1_git_oid, sha1_git_oid_with_profile,
};

// Identity *values* belong to `fgit-types`; they are re-exported here so a
// consumer that already depends on this crate for hashing does not need a
// second direct dependency to name the results. These are the same types, not
// copies: `GitOid<Sha1>` is an alias for `GitOidSha1`.
//
// `fgit_types::GitHashAlgorithm` is the declared repository object format. It
// is re-exported as `GitObjectFormat` because this crate's own
// `GitHashAlgorithm` is the type-level algorithm marker trait that consumers
// write as a bound; importing both under one name would be ambiguous.
pub use fgit_types::hash::{Digest, DigestAlgorithmId, DigestBytes};
pub use fgit_types::identity::{DERIVED_ID_DOMAINS, InternalObjectId};
pub use fgit_types::label::{DomainTag, SchemaFamily, SchemaId};
pub use fgit_types::native::{
    GitHashAlgorithm as GitObjectFormat, GitOid as AnyGitOid, GitOidSha1, GitOidSha256,
};
pub use fgit_types::numeric::CodecVersion;
