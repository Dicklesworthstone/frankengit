//! Deploy keys: one key, one repository, one principal, explicit scopes.
//!
//! A deploy key is a credential that names exactly one repository and exactly
//! what it may do there, so a key leaked from one repository's CI cannot be
//! replayed against another. That binding is the whole point of the type:
//! [`DeployKeyBinding::authorize`] answers *this key, this repository, this
//! operation*, and a matching scope on the wrong repository is refused as
//! firmly as a missing scope.
//!
//! # What a transport gets from this module
//!
//! An authenticated transport (SSH, `fg047`/`hh37`) holds an ed25519 public key
//! it has just proven the peer controls, and needs three things:
//!
//! 1. **who the peer is** — [`DeployKeyBinding::resolve`] selects the binding
//!    for a presented key on a repository, refusing ambiguity rather than
//!    picking one;
//! 2. **what it may do** — [`DeployKeyBinding::authorize`] returns the
//!    [`PrincipalId`] the key speaks as, or a typed refusal naming which half
//!    failed;
//! 3. **whether it is still valid** — authorization takes
//!    [`RevocationEvidence`] as an argument, and `Write` (receive-pack) cannot
//!    be authorised without it.
//!
//! The key is matched by its exact 32 public bytes, not by a fingerprint. A
//! fingerprint would need a domain-separated digest construction, and the only
//! domain available is this body's own identity domain — putting a key
//! fingerprint and a body identity under one domain tag is the key-reuse
//! collision that `NORMATIVE_PROTOCOL_CONTRACTS` §5.2 fails closed on. Exact
//! bytes need no construction to agree on.
//!
//! # What this module is not
//!
//! It holds the registration RECORD and the authorization PREDICATE. It holds
//! no *secret* key material and performs no cryptography: nothing here signs or
//! verifies, and the purpose-marker keys in `fgit-crypto` remain the only key
//! authority (`KeyPurposeMarker`). A public key is public by construction, so
//! recording the peer's half of the pair is not custody of anything. That split
//! is deliberate — a record that could also mint or verify key material would
//! be a second key authority.

use core::fmt::{self, Display, Formatter};

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_crypto::{
    ED25519_CODE_POINT, PUBLIC_KEY_BYTES, SignatureSchemeError, VerifyingKey,
    resolve_signature_scheme,
};
use fgit_types::{DomainTag, PrincipalId, RepositoryId, SchemaFamily};

use crate::revocation::RevocationEvidence;

/// Wire tag for [`DeployKeyScope::Read`].
///
/// Zero is not used, matching the gap-free counter convention in `fgit-forge`'s
/// `aggregate`: it stays reserved so a zeroed buffer can never decode as a live
/// scope.
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
    /// May read repository contents: advertisement and fetch (upload-pack).
    Read,
    /// May advance refs: push (receive-pack).
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

    /// Whether this scope is high-impact, and therefore may never be authorised
    /// without revocation evidence.
    ///
    /// `Write` advances refs: a stolen write key rewrites history another
    /// principal depends on. `Read` leaks, which is bad and is not the same
    /// thing. Drawing the line here rather than at "everything" keeps the
    /// obligation where it buys something, and matches
    /// [`crate::token::TokenOperation::is_high_impact`] so one credential is
    /// not stricter than the other by accident.
    #[must_use]
    pub const fn is_high_impact(self) -> bool {
        matches!(self, Self::Write)
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

/// Every way a deploy-key registration or authorization is declined.
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
    /// No signature scheme is registered under this code point, or the code
    /// point is permanently reserved for harness material.
    ///
    /// Distinct from [`Self::KeyWidthUnsupported`]: this says the number names
    /// nothing usable, that says it names something whose keys this record
    /// cannot hold.
    KeySchemeUnusable {
        /// The code point offered.
        code_point: u16,
    },
    /// The scheme is registered, but its public keys are not the fixed width
    /// this record stores.
    ///
    /// The record holds exactly [`PUBLIC_KEY_BYTES`] bytes because that is what
    /// ed25519 needs and ed25519 is the only registered scheme. A wider scheme
    /// is a real future, and a typed refusal is the honest way to hold that
    /// place open — silently truncating or padding a key would make two
    /// different keys resolve to one binding.
    KeyWidthUnsupported {
        /// The code point offered.
        code_point: u16,
        /// The public-key width that scheme declares.
        public_key_len: usize,
    },
    /// The presented key is not the key this binding registered.
    KeyMismatch,
    /// The binding is confined to a different repository.
    RepositoryMismatch,
    /// The binding does not carry the scope requested.
    ScopeNotGranted {
        /// The scope asked for.
        requested: DeployKeyScope,
    },
    /// The binding was revoked.
    Revoked,
    /// A high-impact scope was requested without revocation evidence.
    ///
    /// This is the structural form of "no TTL-only revocation for high-impact
    /// scopes": the answer is not "probably fine, nobody said otherwise", it is
    /// a refusal to answer without the record.
    RevocationEvidenceRequired {
        /// The scope that demanded evidence.
        requested: DeployKeyScope,
    },
    /// No registered binding matches the presented key on this repository.
    NoBindingForKey,
    /// More than one registered binding matches the presented key on this
    /// repository.
    ///
    /// Two bindings for one key on one repository disagree about what that key
    /// may do, and picking either one silently resolves the disagreement in a
    /// direction nobody chose. Whichever way it were resolved — first match,
    /// widest, narrowest — the answer would be an authorization decision made
    /// by an iteration order.
    AmbiguousBinding {
        /// How many bindings matched.
        matched: usize,
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
            Self::KeySchemeUnusable { code_point } => {
                write!(
                    formatter,
                    "signature scheme {code_point} is not usable here"
                )
            }
            Self::KeyWidthUnsupported {
                code_point,
                public_key_len,
            } => write!(
                formatter,
                "signature scheme {code_point} has {public_key_len}-byte public keys, and a \
                 deploy-key binding holds {PUBLIC_KEY_BYTES}"
            ),
            Self::KeyMismatch => {
                formatter.write_str("the presented key is not the key this binding registered")
            }
            Self::RepositoryMismatch => {
                formatter.write_str("the binding is confined to a different repository")
            }
            Self::ScopeNotGranted { requested } => {
                write!(formatter, "the binding does not grant {requested}")
            }
            Self::Revoked => formatter.write_str("the deploy-key binding was revoked"),
            Self::RevocationEvidenceRequired { requested } => write!(
                formatter,
                "{requested} is high-impact and cannot be authorised without revocation evidence"
            ),
            Self::NoBindingForKey => {
                formatter.write_str("no registered deploy key matches the presented key")
            }
            Self::AmbiguousBinding { matched } => write!(
                formatter,
                "{matched} deploy-key bindings match the presented key on this repository"
            ),
        }
    }
}

impl core::error::Error for DeployKeyRefusal {}

/// One deploy key, bound to one repository, speaking as one principal, with the
/// scopes it may exercise.
///
/// The scope list is kept sorted and duplicate-free so two registrations that
/// grant the same thing have the same bytes and therefore the same identity.
/// Construction is the only way in, which is what makes that invariant hold for
/// every value of this type rather than only for the ones that took the tidy
/// path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployKeyBinding {
    repository_id: RepositoryId,
    principal: PrincipalId,
    scheme: u16,
    key: VerifyingKey,
    scopes: Vec<DeployKeyScope>,
}

impl DeployKeyBinding {
    /// Registers an ed25519 `key` against `repository_id`, speaking as
    /// `principal`, with `scopes`.
    ///
    /// Duplicate scopes are collapsed rather than refused: naming `Read` twice
    /// is a caller building a list, not an ambiguous grant, and it has one
    /// unambiguous meaning. An empty grant has none, so it is refused.
    ///
    /// # Errors
    ///
    /// [`DeployKeyRefusal::NoScopes`] when `scopes` is empty or becomes empty.
    pub fn register(
        repository_id: RepositoryId,
        principal: PrincipalId,
        key: VerifyingKey,
        scopes: &[DeployKeyScope],
    ) -> Result<Self, DeployKeyRefusal> {
        Self::register_under_scheme(repository_id, principal, ED25519_CODE_POINT, key, scopes)
    }

    /// Registers a key under an explicitly named signature scheme.
    ///
    /// [`Self::register`] is the call a caller wants; this one exists because
    /// the decoder must reconstruct a binding from whatever scheme code point
    /// the wire carried, and it must go through the same checks the API does.
    ///
    /// # Errors
    ///
    /// [`DeployKeyRefusal::KeySchemeUnusable`] when no production scheme is
    /// registered under `scheme`, [`DeployKeyRefusal::KeyWidthUnsupported`]
    /// when it is registered but its keys are not [`PUBLIC_KEY_BYTES`] wide, or
    /// [`DeployKeyRefusal::NoScopes`] when the grant is empty.
    pub fn register_under_scheme(
        repository_id: RepositoryId,
        principal: PrincipalId,
        scheme: u16,
        key: VerifyingKey,
        scopes: &[DeployKeyScope],
    ) -> Result<Self, DeployKeyRefusal> {
        // The scheme registry is fgit-crypto's, and it is consulted rather than
        // assumed: this crate does not get to decide what a signature scheme
        // is. Both of its refusals collapse to one variant here because the
        // distinction between "reserved for the harness" and "not registered"
        // is a fact about the registry, and this record's answer to both is the
        // same — it cannot hold a key for that number.
        let row = resolve_signature_scheme(scheme).map_err(|error| match error {
            SignatureSchemeError::ReservedForHarness { code_point }
            | SignatureSchemeError::Unregistered { code_point } => {
                DeployKeyRefusal::KeySchemeUnusable { code_point }
            }
        })?;
        if row.public_key_len != PUBLIC_KEY_BYTES {
            return Err(DeployKeyRefusal::KeyWidthUnsupported {
                code_point: scheme,
                public_key_len: row.public_key_len,
            });
        }
        let mut scopes = scopes.to_vec();
        scopes.sort_unstable();
        scopes.dedup();
        if scopes.is_empty() {
            return Err(DeployKeyRefusal::NoScopes);
        }
        Ok(Self {
            repository_id,
            principal,
            scheme,
            key,
            scopes,
        })
    }

    /// The repository this key is bound to.
    #[must_use]
    pub const fn repository_id(&self) -> RepositoryId {
        self.repository_id
    }

    /// The principal this key speaks as.
    ///
    /// A deploy key is not itself a principal: it is a credential that
    /// authenticates one. Everything above this crate — admission, authority,
    /// reference state — reasons about [`PrincipalId`], so a credential that
    /// could not name one would authenticate a peer into a vocabulary nothing
    /// downstream speaks.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The signature scheme code point the key belongs to.
    #[must_use]
    pub const fn scheme(&self) -> u16 {
        self.scheme
    }

    /// The registered public key. No secret material is held here.
    #[must_use]
    pub const fn key(&self) -> &VerifyingKey {
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
    ///
    /// This is **not an authorization decision**. It knows nothing about which
    /// key was presented and nothing about revocation. A transport calls
    /// [`Self::authorize`], which checks those and returns the principal.
    #[must_use]
    pub fn permits(&self, repository_id: RepositoryId, scope: DeployKeyScope) -> bool {
        self.repository_id == repository_id && self.scopes.contains(&scope)
    }

    /// Selects the binding registered for `key` on `repository_id`.
    ///
    /// This is a pure selector over bindings the caller already holds, not
    /// storage: this crate keeps no registry and this function opens no
    /// database. It exists so the matching rule — exact key bytes AND the right
    /// repository — is written once instead of at every call site.
    ///
    /// # Errors
    ///
    /// [`DeployKeyRefusal::NoBindingForKey`] when nothing matches, or
    /// [`DeployKeyRefusal::AmbiguousBinding`] when more than one does. Two
    /// bindings for one key on one repository disagree about what it may do,
    /// and resolving that by iteration order would make a scan order into an
    /// authorization decision.
    pub fn resolve<'a>(
        bindings: &'a [Self],
        key: &VerifyingKey,
        repository_id: RepositoryId,
    ) -> Result<&'a Self, DeployKeyRefusal> {
        let mut matches = bindings
            .iter()
            .filter(|binding| binding.repository_id == repository_id && &binding.key == key);
        let Some(found) = matches.next() else {
            return Err(DeployKeyRefusal::NoBindingForKey);
        };
        let extra = matches.count();
        if extra > 0 {
            return Err(DeployKeyRefusal::AmbiguousBinding { matched: extra + 1 });
        }
        Ok(found)
    }

    /// Decides whether the peer holding `key` may perform `requested` on
    /// `repository_id`, and returns the principal it does so as.
    ///
    /// This is the transport entry point. `authorize this principal for
    /// receive-pack on repository R` is
    /// `binding.authorize(&presented_key, r, DeployKeyScope::Write,
    /// revocation)`, and the [`PrincipalId`] it returns is what the rest of the
    /// system authorises against.
    ///
    /// The presented key is re-checked here even though [`Self::resolve`]
    /// matched on it, because a caller that resolved one binding and authorised
    /// against another would otherwise get a confident wrong answer. The order
    /// is deliberate: identity-shaped mismatches (key, repository, scope) are
    /// reported before revocation, so a caller debugging a refusal learns the
    /// credential is the wrong credential before learning it is also withdrawn.
    ///
    /// # Errors
    ///
    /// [`DeployKeyRefusal::KeyMismatch`],
    /// [`DeployKeyRefusal::RepositoryMismatch`],
    /// [`DeployKeyRefusal::ScopeNotGranted`], [`DeployKeyRefusal::Revoked`] or
    /// [`DeployKeyRefusal::RevocationEvidenceRequired`].
    pub fn authorize(
        &self,
        key: &VerifyingKey,
        repository_id: RepositoryId,
        requested: DeployKeyScope,
        revocation: RevocationEvidence,
    ) -> Result<PrincipalId, DeployKeyRefusal> {
        if &self.key != key {
            return Err(DeployKeyRefusal::KeyMismatch);
        }
        if self.repository_id != repository_id {
            return Err(DeployKeyRefusal::RepositoryMismatch);
        }
        if !self.scopes.contains(&requested) {
            return Err(DeployKeyRefusal::ScopeNotGranted { requested });
        }
        match revocation {
            RevocationEvidence::Revoked => return Err(DeployKeyRefusal::Revoked),
            RevocationEvidence::NotChecked if requested.is_high_impact() => {
                return Err(DeployKeyRefusal::RevocationEvidenceRequired { requested });
            }
            RevocationEvidence::NotChecked | RevocationEvidence::Live => {}
        }
        Ok(self.principal)
    }
}

impl CanonicalBody for DeployKeyBinding {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/deploy-key-binding/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("deploy-key-binding");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.repository_id.as_bytes());
        out.write_opaque_id(self.principal.as_bytes());
        out.write_scalar(self.scheme);
        out.write_bytes("deploy_key.key", self.key.as_bytes())?;
        out.write_canonical_set("deploy_key.scopes", &self.scopes, |encoder, scope| {
            encoder.write_scalar(scope.tag());
            Ok(())
        })
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let repository_id =
            RepositoryId::from_bytes(input.read_opaque_id("deploy_key.repository_id")?);
        let principal = PrincipalId::from_bytes(input.read_opaque_id("deploy_key.principal")?);
        let scheme = input.read_scalar::<u16>("deploy_key.scheme")?;
        let key_offset = input.offset();
        let key_bytes = input.read_bytes("deploy_key.key")?;
        let observed_len = key_bytes.len();
        // A key that is not exactly `PUBLIC_KEY_BYTES` wide is refused rather
        // than truncated or padded: either repair would make two different keys
        // resolve to one binding, which is the one thing an exact-match
        // resolution rule may never do.
        let key_bytes: [u8; PUBLIC_KEY_BYTES] =
            key_bytes
                .try_into()
                .map_err(|_| CodecRefusal::ValueUnrepresentable {
                    field: "deploy_key.key",
                    observed: observed_len as u64,
                    limit: PUBLIC_KEY_BYTES as u64,
                })?;
        let scopes = input.read_canonical_set("deploy_key.scopes", |decoder| {
            let offset = decoder.offset();
            let tag = decoder.read_scalar::<u32>("deploy_key.scope")?;
            DeployKeyScope::from_tag(tag).map_err(|_| CodecRefusal::VariantUnknown {
                field: "deploy_key.scope",
                observed: tag,
                offset,
            })
        })?;
        // Decode goes through the SAME checked constructor the API does, so
        // every invariant holds for every value of this type rather than only
        // for the ones built in process. A hostile encoder can emit a
        // zero-element set or an unregistered scheme code point; it cannot
        // thereby mint a binding that permits nothing, or one whose key belongs
        // to a scheme nothing can verify, while still typing as a registration.
        //
        // The empty-set refusal matches the vocabulary fgit-forge already uses
        // for the same shape. Its `counter` reports a zero where a gap-free
        // counter was required as `ValueUnrepresentable { observed: 0, limit:
        // 1 }`, reading `limit` as the minimum admissible value rather than a
        // maximum. An empty scope set is that same statement about a
        // collection, so it is reported the same way.
        let key = VerifyingKey::from_bytes(key_bytes);
        Self::register_under_scheme(repository_id, principal, scheme, key, &scopes).map_err(
            |refusal| match refusal {
                DeployKeyRefusal::KeySchemeUnusable { code_point }
                | DeployKeyRefusal::KeyWidthUnsupported { code_point, .. } => {
                    CodecRefusal::VariantUnknown {
                        field: "deploy_key.scheme",
                        observed: u32::from(code_point),
                        offset: key_offset,
                    }
                }
                _ => CodecRefusal::ValueUnrepresentable {
                    field: "deploy_key.scopes",
                    observed: 0,
                    limit: 1,
                },
            },
        )
    }
}
