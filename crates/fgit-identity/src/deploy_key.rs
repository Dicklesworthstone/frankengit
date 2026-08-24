//! Deploy keys: one key identity bound to one repository, with explicit scopes.
//!
//! A deploy key is not a principal. It is a credential that names exactly one
//! repository and exactly what it may do there, so a key leaked from one
//! repository's CI cannot be replayed against another. That binding is the
//! whole point of the type: [`DeployKeyBinding::permits`] answers *this
//! repository, this operation*, and a matching scope on the wrong repository is
//! refused as firmly as a missing scope.
//!
//! This module holds the registration RECORD and the authorization PREDICATE.
//! It holds no key material and performs no cryptography: the key is named by
//! digest, and the purpose-marker keys in `fgit-crypto` remain the only key
//! authority (`KeyPurposeMarker`). That split is deliberate -- a record that
//! could also mint or verify key material would be a second key authority, and
//! this crate is L2: it computes and refuses, it does not admit.

use core::fmt::{self, Display, Formatter};

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{Digest, DomainTag, RepositoryId, SchemaFamily};

/// Wire tag for [`DeployKeyScope::Read`].
///
/// Zero is not used, matching the gap-free counter convention in
/// [`crate::aggregate`]: it stays reserved so a zeroed buffer can never decode
/// as a live scope.
const SCOPE_READ: u32 = 1;
/// Wire tag for [`DeployKeyScope::Write`].
const SCOPE_WRITE: u32 = 2;

/// What a deploy key may do on the repository it is bound to.
///
/// `Write` does NOT imply `Read`. Each capability is named explicitly, because
/// an implication is a capability grant that nobody wrote down, and a reviewer
/// auditing what a key can do should be able to read the answer rather than
/// derive it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum DeployKeyScope {
    /// May read repository contents: advertisement and fetch.
    Read,
    /// May advance refs: push.
    Write,
}

impl DeployKeyScope {
    /// The wire tag for this scope.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Read => SCOPE_READ,
            Self::Write => SCOPE_WRITE,
        }
    }

    /// Parses a wire tag, refusing one this build does not know.
    ///
    /// An unknown tag is a refusal rather than a skip. A reader that silently
    /// dropped scopes it did not understand would narrow a credential without
    /// saying so, and a reader that ignored the field entirely would widen one.
    /// Failing closed is the only option that cannot silently change what a key
    /// is allowed to do.
    ///
    /// # Errors
    ///
    /// [`DeployKeyRefusal::UnknownScope`] naming the tag observed.
    pub const fn from_tag(tag: u32) -> Result<Self, DeployKeyRefusal> {
        match tag {
            SCOPE_READ => Ok(Self::Read),
            SCOPE_WRITE => Ok(Self::Write),
            observed => Err(DeployKeyRefusal::UnknownScope { observed }),
        }
    }
}

impl Display for DeployKeyScope {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("read"),
            Self::Write => formatter.write_str("write"),
        }
    }
}

/// Every way a deploy-key registration is declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeployKeyRefusal {
    /// The registration named no scopes at all.
    ///
    /// A binding that grants nothing is not a narrow credential, it is a
    /// mistake or a revocation wearing a registration's clothes. Refusing it
    /// keeps "registered" and "permitted to do nothing" from being the same
    /// state, which a later revocation check would otherwise have to
    /// distinguish by guessing.
    NoScopes,
    /// The wire carried a scope tag this build does not know.
    UnknownScope {
        /// The tag observed.
        observed: u32,
    },
}

impl Display for DeployKeyRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoScopes => {
                formatter.write_str("a deploy-key registration granting no scopes is refused")
            }
            Self::UnknownScope { observed } => {
                write!(formatter, "unknown deploy-key scope tag {observed}")
            }
        }
    }
}

impl core::error::Error for DeployKeyRefusal {}

/// One deploy key, bound to one repository, with the scopes it may exercise.
///
/// The scope list is kept sorted and duplicate-free so two registrations that
/// grant the same thing have the same bytes and therefore the same identity.
/// Construction is the only way in, which is what makes that invariant hold for
/// every value of this type rather than only for the ones that took the tidy
/// path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployKeyBinding {
    repository_id: RepositoryId,
    key: Digest,
    scopes: Vec<DeployKeyScope>,
}

impl DeployKeyBinding {
    /// Registers `key` against `repository_id` with `scopes`.
    ///
    /// Duplicate scopes are collapsed rather than refused: naming `Read` twice
    /// is a caller building a list, not an ambiguous grant, and it has one
    /// unambiguous meaning. An empty grant has none, so it is refused.
    ///
    /// # Errors
    ///
    /// [`DeployKeyRefusal::NoScopes`] when `scopes` is empty, or becomes empty.
    pub fn register(
        repository_id: RepositoryId,
        key: Digest,
        scopes: &[DeployKeyScope],
    ) -> Result<Self, DeployKeyRefusal> {
        let mut scopes = scopes.to_vec();
        scopes.sort_unstable();
        scopes.dedup();
        if scopes.is_empty() {
            return Err(DeployKeyRefusal::NoScopes);
        }
        Ok(Self {
            repository_id,
            key,
            scopes,
        })
    }

    /// The repository this key is bound to.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The digest naming the key material. No key material is held here.
    #[must_use]
    pub const fn key(&self) -> &Digest {
        &self.key
    }

    /// The granted scopes, sorted and duplicate-free.
    #[must_use]
    pub fn scopes(&self) -> &[DeployKeyScope] {
        &self.scopes
    }

    /// Whether this key may perform `scope` **on `repository_id`**.
    ///
    /// Both halves are checked. A key holding `Write` for repository A does not
    /// hold `Write` for repository B, and answering otherwise would make the
    /// binding decorative. This is a pure predicate: it consults only what the
    /// registration recorded, never ambient state, so the same binding and the
    /// same question always give the same answer.
    #[must_use]
    pub fn permits(&self, repository_id: RepositoryId, scope: DeployKeyScope) -> bool {
        self.repository_id == repository_id && self.scopes.contains(&scope)
    }
}

impl CanonicalBody for DeployKeyBinding {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/deploy-key-binding/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("deploy-key-binding");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_digest(&self.key)?;
        out.write_canonical_set("deploy_key.scopes", &self.scopes, |encoder, scope| {
            encoder.write_scalar(scope.tag());
            Ok(())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id =
            RepositoryId::from_bytes(input.read_opaque_id("deploy_key.repository_id")?);
        let key = input.read_digest()?;
        let scopes = input.read_canonical_set("deploy_key.scopes", |decoder| {
            let offset = decoder.offset();
            let tag = decoder.read_scalar::<u32>("deploy_key.scope")?;
            DeployKeyScope::from_tag(tag).map_err(|_| CodecRefusal::VariantUnknown {
                field: "deploy_key.scope",
                observed: tag,
                offset,
            })
        })?;
        // Decode goes through the SAME checked constructor the API does, so the
        // no-empty-grant invariant holds for every value of this type rather
        // than only for the ones built in process. A hostile encoder can emit a
        // zero-element set; it cannot thereby mint a binding that permits
        // nothing while still typing as a registration.
        //
        // The refusal matches the vocabulary fgit-forge already uses for the
        // same shape. Its `counter` reports a zero where a gap-free counter was
        // required as `ValueUnrepresentable { observed: 0, limit: 1 }`, reading
        // `limit` as the minimum admissible value rather than a maximum. An
        // empty scope set is that same statement about a collection, so it is
        // reported the same way. An earlier version of this comment claimed
        // `CodecRefusal` had no variant for this and that
        // `ValueUnrepresentable` meant the opposite; both were wrong, and the
        // precedent was two files away.
        Self::register(repository_id, key, &scopes).map_err(|_| {
            CodecRefusal::ValueUnrepresentable {
                field: "deploy_key.scopes",
                observed: 0,
                limit: 1,
            }
        })
    }
}
