//! Typed key identities, purposes, and derivation.
//!
//! `SECURITY_THREAT_MODEL.md` section 8 enumerates the separation this module
//! enforces: *"Keys are separated for identity, authority/admin, capsule,
//! evidence, package/release, webhook, tenant encryption, and recovery."*
//! Those eight are the closed [`KeyPurpose`] set. They are not invented here
//! and they are not extensible by a consumer.
//!
//! # Purpose confusion is unrepresentable, not merely refused
//!
//! A key carries its purpose in its *type*: [`SecretKey<P>`] is parameterised
//! by a marker, so a capsule key and a webhook key are different Rust types.
//! Operations are then gated on the purpose rather than on the key: only a
//! purpose that may compute a tag implements [`MacCapable`], so a capsule key
//! has no `tag` method to call. There is nothing to refuse at runtime because
//! there is nothing to write.
//!
//! Serialized material is the one place a purpose arrives as data rather than
//! as a type, and that is exactly where [`StoredKey::into_typed`] performs the
//! runtime check the type system cannot: a stored capsule key refuses to
//! become a `SecretKey<Webhook>`.
//!
//! # Separation is cryptographic as well as type-level
//!
//! Types stop a programmer; they do not stop two purposes sharing bytes. Each
//! purpose therefore derives its material through HKDF with the purpose tag
//! and scope committed into the `info` argument, using the same
//! length-prefixed framing as the internal-identity preimage. Two purposes
//! under one root secret produce unrelated keys, and a tenant's key in one
//! encryption domain is not the key in another — which is what makes "a
//! ciphertext copied across incompatible key domains is not a valid
//! placement" true of the bytes and not only of the annotations.
//!
//! # Non-claims
//!
//! Key material is not zeroized on drop; see [`crate::HmacSha256`] for why
//! that is a dependency decision rather than something to fake here. Nothing
//! in this module generates randomness: a root secret is supplied by the
//! caller, because entropy is a capability the runtime owns and not something
//! a leaf crate should reach for on its own.

use core::fmt;
use core::marker::PhantomData;

use crate::derive::derive_key;
use crate::mac::{TAG_BYTES, hmac_sha256, verify_mac};

/// Width of a derived key, in bytes.
pub const KEY_BYTES: usize = TAG_BYTES;

/// Sealing module for the closed purpose set.
#[doc(hidden)]
pub mod closed_purpose {
    /// Implemented only by the purpose markers this crate defines.
    pub trait PurposeMarker {}
}

/// The eight key purposes the threat model separates.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum KeyPurpose {
    /// Principal and actor identity.
    Identity,
    /// Authority and administrative action.
    AuthorityAdmin,
    /// Repository and checkpoint capsules.
    Capsule,
    /// Immutable evidence records.
    Evidence,
    /// Package and release artifacts.
    PackageRelease,
    /// Outbound webhook authentication.
    Webhook,
    /// Tenant envelope encryption.
    TenantEncryption,
    /// Threshold and archive recovery.
    Recovery,
}

impl KeyPurpose {
    /// Every purpose, in code-point order.
    pub const ALL: &'static [Self] = &[
        Self::Identity,
        Self::AuthorityAdmin,
        Self::Capsule,
        Self::Evidence,
        Self::PackageRelease,
        Self::Webhook,
        Self::TenantEncryption,
        Self::Recovery,
    ];

    /// Stable registry code point.
    #[must_use]
    pub const fn code_point(self) -> u16 {
        match self {
            Self::Identity => 1,
            Self::AuthorityAdmin => 2,
            Self::Capsule => 3,
            Self::Evidence => 4,
            Self::PackageRelease => 5,
            Self::Webhook => 6,
            Self::TenantEncryption => 7,
            Self::Recovery => 8,
        }
    }

    /// Canonical domain tag committed into every derivation for this purpose.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Identity => "frankengit/key/identity/v1",
            Self::AuthorityAdmin => "frankengit/key/authority-admin/v1",
            Self::Capsule => "frankengit/key/capsule/v1",
            Self::Evidence => "frankengit/key/evidence/v1",
            Self::PackageRelease => "frankengit/key/package-release/v1",
            Self::Webhook => "frankengit/key/webhook/v1",
            Self::TenantEncryption => "frankengit/key/tenant-encryption/v1",
            Self::Recovery => "frankengit/key/recovery/v1",
        }
    }

    /// Recover a purpose from its code point, refusing an unknown one.
    #[must_use]
    pub fn from_code_point(code_point: u16) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|purpose| purpose.code_point() == code_point)
    }
}

impl fmt::Display for KeyPurpose {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.tag())
    }
}

/// A key purpose, as a type.
///
/// Sealed: the set is closed and a downstream crate cannot add a ninth.
///
/// The eight markers this crate defines satisfy it:
///
/// ```
/// use fgit_crypto::{Capsule, KeyPurpose, KeyPurposeMarker, Webhook};
///
/// fn purpose_of<P: KeyPurposeMarker>() -> KeyPurpose {
///     P::PURPOSE
/// }
/// assert_eq!(purpose_of::<Capsule>(), KeyPurpose::Capsule);
/// assert_eq!(purpose_of::<Webhook>(), KeyPurpose::Webhook);
/// ```
///
/// A ninth cannot be added downstream, because the sealing supertrait is
/// unnameable outside this crate:
///
/// ```compile_fail
/// use fgit_crypto::{KeyPurpose, KeyPurposeMarker};
///
/// #[derive(Clone, Copy, Debug)]
/// struct Backdoor;
///
/// impl KeyPurposeMarker for Backdoor {
///     const PURPOSE: KeyPurpose = KeyPurpose::Capsule;
/// }
/// ```
pub trait KeyPurposeMarker: closed_purpose::PurposeMarker + Copy + fmt::Debug {
    /// The runtime purpose this marker names.
    const PURPOSE: KeyPurpose;
}

/// Purposes permitted to compute a message authentication tag.
///
/// Deliberately narrow: a key exists to do one thing, and a capsule signing
/// key that can also MAC is a key with two jobs.
///
/// A webhook key tags, because webhook authentication is the token-MAC
/// purpose:
///
/// ```
/// use fgit_crypto::{KeyEpoch, KeyScope, RootSecret, SecretKey, Webhook};
///
/// let root = RootSecret::from_bytes([0x5a; 32]);
/// let key = SecretKey::<Webhook>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
/// let tag = key.tag(b"delivery body");
/// assert!(key.verify(b"delivery body", &tag));
/// ```
///
/// A capsule key has no `tag` method at all, so purpose confusion is not
/// something to refuse at runtime — there is nothing to write:
///
/// ```compile_fail
/// use fgit_crypto::{Capsule, KeyEpoch, KeyScope, RootSecret, SecretKey};
///
/// let root = RootSecret::from_bytes([0x5a; 32]);
/// let key = SecretKey::<Capsule>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR);
/// let _ = key.tag(b"delivery body");
/// ```
pub trait MacCapable: KeyPurposeMarker {}

/// Declares a purpose marker type.
macro_rules! purpose_marker {
    ($name:ident, $purpose:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name;

        impl closed_purpose::PurposeMarker for $name {}

        impl KeyPurposeMarker for $name {
            const PURPOSE: KeyPurpose = $purpose;
        }
    };
}

purpose_marker!(
    Identity,
    KeyPurpose::Identity,
    "Type-level marker for principal and actor identity keys."
);
purpose_marker!(
    AuthorityAdmin,
    KeyPurpose::AuthorityAdmin,
    "Type-level marker for authority and administrative keys."
);
purpose_marker!(
    Capsule,
    KeyPurpose::Capsule,
    "Type-level marker for capsule keys."
);
purpose_marker!(
    Evidence,
    KeyPurpose::Evidence,
    "Type-level marker for evidence keys."
);
purpose_marker!(
    PackageRelease,
    KeyPurpose::PackageRelease,
    "Type-level marker for package and release keys."
);
purpose_marker!(
    Webhook,
    KeyPurpose::Webhook,
    "Type-level marker for webhook authentication keys."
);
purpose_marker!(
    TenantEncryption,
    KeyPurpose::TenantEncryption,
    "Type-level marker for tenant envelope-encryption keys."
);
purpose_marker!(
    Recovery,
    KeyPurpose::Recovery,
    "Type-level marker for threshold and archive recovery keys."
);

// Webhook authentication is the token-MAC purpose from the threat model, and
// the only one that computes tags today. Adding a purpose here is a security
// decision, not a convenience.
impl MacCapable for Webhook {}

/// A purpose whose keys may produce detached signatures.
///
/// The third capability trait, gating signing exactly as [`MacCapable`] gates
/// authentication tags. A key whose purpose is not signing has no `sign`
/// method at all, so producing one is not a refusal a caller can forget to
/// check — it is a program that does not exist.
///
/// The membership below is a reading of the threat model's purposes, not a
/// convenience list. Signing is granted to the four purposes whose whole
/// reason to exist is attesting authorship: principal identity, authority
/// administration, capsules, and package releases. It is withheld from
/// evidence, webhook, tenant-encryption and recovery keys. `Evidence` is the
/// interesting exclusion: evidence bodies are *identified* by a
/// domain-separated digest and countersigned by whichever authority vouches
/// for them, so an evidence key that could also sign would blur the line
/// between "this evidence exists" and "this authority asserts it".
pub trait SignatureCapable: KeyPurposeMarker {}

impl SignatureCapable for Identity {}
impl SignatureCapable for AuthorityAdmin {}
impl SignatureCapable for Capsule {}
impl SignatureCapable for PackageRelease {}

/// A purpose whose keys may seal and open authenticated ciphertext.
///
/// Only tenant envelope encryption. `Recovery` is deliberately excluded even
/// though archive recovery plausibly wants to decrypt: a recovery key that can
/// open tenant ciphertext would make cryptographic erasure of a tenant key
/// meaningless, because the data would still be reachable through a key the
/// erasure did not touch. Plan section 19.4 treats erasure as a deletion state
/// with evidence, and a second key that silently defeats it is the failure
/// that state is meant to exclude.
pub trait EncryptionCapable: KeyPurposeMarker {}

impl EncryptionCapable for TenantEncryption {}

/// A key rotation epoch.
///
/// Gap-free and monotone: zero is reserved so a zeroed buffer is never a valid
/// epoch, and `next` refuses exhaustion rather than wrapping into a
/// previously-used epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyEpoch(u32);

impl KeyEpoch {
    /// The first epoch of a key's history.
    pub const FIRST: Self = Self(1);

    /// Builds an epoch, refusing the reserved zero.
    #[must_use]
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// The epoch number.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The next epoch, refusing exhaustion.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "e{}", self.0)
    }
}

/// The scope a key is derived for.
///
/// Tenant and repository are opaque to this crate; it commits to their bytes
/// without interpreting them. An empty scope is the operator-wide key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyScope<'a> {
    /// Tenant this key belongs to, if it is tenant-scoped.
    pub tenant: &'a [u8],
    /// Repository this key belongs to, if it is repository-scoped.
    pub repository: &'a [u8],
}

impl<'a> KeyScope<'a> {
    /// The operator-wide scope: no tenant, no repository.
    pub const OPERATOR: Self = Self {
        tenant: &[],
        repository: &[],
    };

    /// A tenant-wide scope.
    #[must_use]
    pub const fn tenant(tenant: &'a [u8]) -> Self {
        Self {
            tenant,
            repository: &[],
        }
    }

    /// A repository scope within a tenant.
    #[must_use]
    pub const fn repository(tenant: &'a [u8], repository: &'a [u8]) -> Self {
        Self { tenant, repository }
    }
}

/// The `info` argument committed into a derivation.
///
/// Length-prefixed exactly like the internal-identity preimage, so no two
/// (purpose, epoch, scope) triples can frame to the same bytes.
#[must_use]
pub fn derivation_info(purpose: KeyPurpose, epoch: KeyEpoch, scope: KeyScope<'_>) -> Vec<u8> {
    let tag = purpose.tag().as_bytes();
    let mut info = Vec::with_capacity(tag.len() + scope.tenant.len() + scope.repository.len() + 16);
    info.push(u8::try_from(tag.len()).expect("a purpose tag is far shorter than 255 bytes"));
    info.extend_from_slice(tag);
    info.extend_from_slice(&purpose.code_point().to_be_bytes());
    info.extend_from_slice(&epoch.get().to_be_bytes());
    let tenant_len = u64::try_from(scope.tenant.len()).expect("a slice length always fits in u64");
    info.extend_from_slice(&tenant_len.to_be_bytes());
    info.extend_from_slice(scope.tenant);
    let repository_len =
        u64::try_from(scope.repository.len()).expect("a slice length always fits in u64");
    info.extend_from_slice(&repository_len.to_be_bytes());
    info.extend_from_slice(scope.repository);
    info
}

/// A root secret a caller supplies.
///
/// This crate never generates one: entropy is a capability the runtime owns.
#[derive(Clone, Copy)]
pub struct RootSecret([u8; KEY_BYTES]);

impl RootSecret {
    /// Adopt caller-supplied root material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for RootSecret {
    /// Never prints the material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootSecret(redacted)")
    }
}

/// A key identity: purpose, epoch, and a commitment to the material.
///
/// The commitment is a MAC of a fixed label under the key, so an identity can
/// be recorded, compared and looked up without the material being recoverable
/// from it.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyId {
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    commitment: [u8; TAG_BYTES],
}

/// Fixed label under which a key commits to its own identity.
const COMMITMENT_LABEL: &[u8] = b"frankengit/key-commitment/v1";

impl KeyId {
    /// The purpose this key serves.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The rotation epoch this key belongs to.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// The commitment bytes.
    #[must_use]
    pub const fn commitment(&self) -> &[u8; TAG_BYTES] {
        &self.commitment
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}/{}",
            self.purpose,
            self.epoch,
            crate::lowercase_hex(&self.commitment)
        )
    }
}

/// A derived secret key, typed by purpose.
///
/// A key may be passed where its own purpose is required:
///
/// ```
/// use fgit_crypto::{KeyEpoch, KeyScope, RootSecret, SecretKey, Webhook};
///
/// fn requires_webhook(_key: SecretKey<Webhook>) {}
/// let root = RootSecret::from_bytes([0x5a; 32]);
/// requires_webhook(SecretKey::<Webhook>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR));
/// ```
///
/// It may not be substituted for another purpose:
///
/// ```compile_fail
/// use fgit_crypto::{Capsule, KeyEpoch, KeyScope, RootSecret, SecretKey, Webhook};
///
/// fn requires_webhook(_key: SecretKey<Webhook>) {}
/// let root = RootSecret::from_bytes([0x5a; 32]);
/// requires_webhook(SecretKey::<Capsule>::derive(&root, KeyEpoch::FIRST, KeyScope::OPERATOR));
/// ```
#[derive(Clone, Copy)]
pub struct SecretKey<P: KeyPurposeMarker> {
    material: [u8; KEY_BYTES],
    id: KeyId,
    purpose: PhantomData<P>,
}

impl<P: KeyPurposeMarker> SecretKey<P> {
    /// Derive this purpose's key for an epoch and scope.
    #[must_use]
    pub fn derive(root: &RootSecret, epoch: KeyEpoch, scope: KeyScope<'_>) -> Self {
        let info = derivation_info(P::PURPOSE, epoch, scope);
        let material = derive_key(purpose_salt(P::PURPOSE), &root.0, &info);
        let commitment = hmac_sha256(&material, COMMITMENT_LABEL);
        Self {
            material,
            id: KeyId {
                purpose: P::PURPOSE,
                epoch,
                commitment,
            },
            purpose: PhantomData,
        }
    }

    /// This key's identity.
    #[must_use]
    pub const fn id(&self) -> &KeyId {
        &self.id
    }

    /// The purpose this key serves, as a runtime value.
    #[must_use]
    pub const fn purpose() -> KeyPurpose {
        P::PURPOSE
    }

    /// The raw key material, for sibling modules in this crate only.
    ///
    /// Deliberately `pub(crate)`: signing and sealing need the bytes, and no
    /// caller outside this crate ever does. Every in-crate use derives a
    /// further sub-key from it under its own label rather than using it
    /// directly as a primitive's key.
    pub(crate) const fn material(&self) -> &[u8; KEY_BYTES] {
        &self.material
    }

    /// Serialize for storage, discarding the type parameter.
    ///
    /// The purpose survives as data so [`StoredKey::into_typed`] can refuse a
    /// mismatched reconstruction.
    #[must_use]
    pub const fn store(&self) -> StoredKey {
        StoredKey {
            purpose: P::PURPOSE,
            epoch: self.id.epoch,
            material: self.material,
        }
    }
}

impl<P: KeyPurposeMarker> fmt::Debug for SecretKey<P> {
    /// Never prints the material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretKey({}, redacted)", self.id)
    }
}

impl<P: MacCapable> SecretKey<P> {
    /// Compute an authentication tag.
    ///
    /// Only defined for purposes that may MAC, so a key of any other purpose
    /// has no such method at all.
    #[must_use]
    pub fn tag(&self, message: &[u8]) -> [u8; TAG_BYTES] {
        hmac_sha256(&self.material, message)
    }

    /// Verify a tag without branching on where it first differs.
    #[must_use]
    pub fn verify(&self, message: &[u8], candidate: &[u8; TAG_BYTES]) -> bool {
        verify_mac(&self.tag(message), candidate)
    }
}

/// Per-purpose derivation salt, so two roots that happen to collide still
/// separate by purpose.
const fn purpose_salt(purpose: KeyPurpose) -> &'static [u8] {
    match purpose {
        KeyPurpose::Identity => b"frankengit/key-salt/identity/v1",
        KeyPurpose::AuthorityAdmin => b"frankengit/key-salt/authority-admin/v1",
        KeyPurpose::Capsule => b"frankengit/key-salt/capsule/v1",
        KeyPurpose::Evidence => b"frankengit/key-salt/evidence/v1",
        KeyPurpose::PackageRelease => b"frankengit/key-salt/package-release/v1",
        KeyPurpose::Webhook => b"frankengit/key-salt/webhook/v1",
        KeyPurpose::TenantEncryption => b"frankengit/key-salt/tenant-encryption/v1",
        KeyPurpose::Recovery => b"frankengit/key-salt/recovery/v1",
    }
}

/// A key whose purpose is data rather than a type.
///
/// This is the serialized form. Its only route back to a typed key is
/// [`StoredKey::into_typed`], which checks the purpose.
#[derive(Clone, Copy)]
pub struct StoredKey {
    purpose: KeyPurpose,
    epoch: KeyEpoch,
    material: [u8; KEY_BYTES],
}

/// Refusal from reconstructing a typed key out of stored material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PurposeMismatch {
    /// Purpose the caller asked for.
    pub expected: KeyPurpose,
    /// Purpose the stored key actually has.
    pub stored: KeyPurpose,
}

impl fmt::Display for PurposeMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "stored key is for `{}` and cannot be used as `{}`",
            self.stored, self.expected
        )
    }
}

impl std::error::Error for PurposeMismatch {}

impl StoredKey {
    /// The purpose recorded alongside the material.
    #[must_use]
    pub const fn purpose(&self) -> KeyPurpose {
        self.purpose
    }

    /// The epoch recorded alongside the material.
    #[must_use]
    pub const fn epoch(&self) -> KeyEpoch {
        self.epoch
    }

    /// Reconstruct a typed key, refusing a purpose the material is not for.
    ///
    /// This is the runtime half of the separation: the type system cannot see
    /// a purpose that arrived as bytes, so this checks it.
    pub fn into_typed<P: KeyPurposeMarker>(self) -> Result<SecretKey<P>, PurposeMismatch> {
        if self.purpose != P::PURPOSE {
            return Err(PurposeMismatch {
                expected: P::PURPOSE,
                stored: self.purpose,
            });
        }
        let commitment = hmac_sha256(&self.material, COMMITMENT_LABEL);
        Ok(SecretKey {
            material: self.material,
            id: KeyId {
                purpose: self.purpose,
                epoch: self.epoch,
                commitment,
            },
            purpose: PhantomData,
        })
    }
}

impl fmt::Debug for StoredKey {
    /// Never prints the material.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "StoredKey({}, {}, redacted)",
            self.purpose, self.epoch
        )
    }
}
