//! Sessions: an authenticated principal, the strength it authenticated with,
//! and rotation that cannot silently weaken it.
//!
//! A session is what a transport holds after authentication succeeds. It is not
//! a credential: it names the principal that was authenticated, the credential
//! class that did the authenticating, and the bound the session inherits from
//! that act. A credential can outlive a session and a session can be revoked
//! without touching the credential, which is why they are different types.
//!
//! # Strength is bound at establishment and can only be re-earned
//!
//! [`AuthenticationStrength`] records HOW the principal proved itself. The rule
//! this module exists to make structural is that **rotation may not raise it**.
//! A session established by a deploy key cannot become a
//! multi-factor-authenticated session by being refreshed: refreshing proves the
//! holder still holds what they already had, and that is not evidence of
//! anything stronger. Raising strength requires authenticating again, which
//! produces a new session rather than a rotated one.
//!
//! Lowering it on rotation IS permitted, and deliberately so — a caller that
//! wants a weaker session for a narrower job is attenuating, which is the same
//! direction [`crate::token::TokenGrant::attenuate`] allows. The asymmetry is
//! the point: privilege escalation is refused, voluntary de-escalation is not.
//!
//! # No clock
//!
//! As everywhere in this crate, `now` is a parameter. Nothing here reads a
//! clock, so a session decision replays against the inputs it was made with.
//! Rotation does not extend a session past the deadline it was established
//! with; a rotated session expires when the original would have. Otherwise
//! rotation would be an unbounded lifetime extension performed by the holder,
//! which is the whole reason sessions expire.

use core::fmt::{self, Display, Formatter};

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{DomainTag, PrincipalId, RepositoryId, SchemaFamily};

use crate::revocation::RevocationEvidence;

/// Wire tag for [`AuthenticationStrength::DeployKey`]. Zero stays reserved.
const STRENGTH_DEPLOY_KEY: u32 = 1;
/// Wire tag for [`AuthenticationStrength::Token`].
const STRENGTH_TOKEN: u32 = 2;
/// Wire tag for [`AuthenticationStrength::SingleFactor`].
const STRENGTH_SINGLE_FACTOR: u32 = 3;
/// Wire tag for [`AuthenticationStrength::MultiFactor`].
const STRENGTH_MULTI_FACTOR: u32 = 4;

/// How a principal proved itself when this session was established.
///
/// The ordering is load-bearing: `Ord` is what "may not be raised by rotation"
/// is checked against, so the declaration order IS the strength lattice and
/// reordering these variants changes what rotation permits. That is why the
/// wire tags are written explicitly rather than derived from the discriminant —
/// a future reordering must not silently renumber the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum AuthenticationStrength {
    /// A deploy key: one repository, no human, no second factor.
    DeployKey,
    /// A bearer token issued to a principal.
    Token,
    /// One interactive factor.
    SingleFactor,
    /// Two or more independent interactive factors.
    MultiFactor,
}

impl AuthenticationStrength {
    /// The wire tag for this strength.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::DeployKey => STRENGTH_DEPLOY_KEY,
            Self::Token => STRENGTH_TOKEN,
            Self::SingleFactor => STRENGTH_SINGLE_FACTOR,
            Self::MultiFactor => STRENGTH_MULTI_FACTOR,
        }
    }

    /// Parses a wire tag, refusing one this build does not know.
    ///
    /// A reader that mapped an unknown strength onto a known one would be
    /// guessing at an authorization input. Failing closed is the only option
    /// that cannot silently change what a session is trusted for.
    ///
    /// # Errors
    ///
    /// [`SessionRefusal::UnknownStrength`] naming the tag observed.
    pub const fn from_tag(tag: u32) -> Result<Self, SessionRefusal> {
        match tag {
            STRENGTH_DEPLOY_KEY => Ok(Self::DeployKey),
            STRENGTH_TOKEN => Ok(Self::Token),
            STRENGTH_SINGLE_FACTOR => Ok(Self::SingleFactor),
            STRENGTH_MULTI_FACTOR => Ok(Self::MultiFactor),
            observed => Err(SessionRefusal::UnknownStrength { observed }),
        }
    }
}

impl Display for AuthenticationStrength {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeployKey => formatter.write_str("deploy-key"),
            Self::Token => formatter.write_str("token"),
            Self::SingleFactor => formatter.write_str("single-factor"),
            Self::MultiFactor => formatter.write_str("multi-factor"),
        }
    }
}

/// The revocable handle naming one established session.
///
/// Separate from the credential's handle on purpose: revoking a session must
/// not require revoking the credential that established it, and revoking a
/// credential must be able to leave already-established sessions to be reaped
/// on their own terms rather than silently surviving.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Builds a session id, refusing zero.
    ///
    /// Zero is reserved as the not-a-value, matching every other counter in
    /// this workspace, so a zeroed buffer can never name a live session.
    #[must_use]
    pub const fn try_new(value: u64) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// The wire value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Display for SessionId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Every way a session is declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionRefusal {
    /// The wire carried a strength tag this build does not know.
    UnknownStrength {
        /// The tag observed.
        observed: u32,
    },
    /// The session is confined to a different repository.
    RepositoryMismatch,
    /// The session expired at or before the instant asked about.
    Expired {
        /// The deadline recorded at establishment.
        expires_at: u64,
        /// The instant the question was asked about.
        now: u64,
    },
    /// The session was revoked.
    Revoked,
    /// A session was used without revocation evidence where the operation
    /// demanded it.
    RevocationEvidenceRequired,
    /// The session does not carry the strength the operation requires.
    ///
    /// Names both sides, because "insufficient" without the two numbers sends
    /// the operator to read code to find out what would have been enough.
    StrengthInsufficient {
        /// What the session was established with.
        established: AuthenticationStrength,
        /// What the operation demanded.
        required: AuthenticationStrength,
    },
    /// Rotation would raise the authentication strength.
    ///
    /// Refreshing proves the holder still holds what they already had. It is
    /// not evidence of anything stronger, so it may not buy anything stronger.
    /// A stronger session requires authenticating again.
    RotationWouldStrengthen {
        /// What the session was established with.
        established: AuthenticationStrength,
        /// What the rotation asked for.
        requested: AuthenticationStrength,
    },
    /// Rotation would extend the session past the deadline it was established
    /// with.
    ///
    /// Otherwise rotation is an unbounded lifetime extension performed by the
    /// holder, which is the reason sessions expire in the first place.
    RotationWouldExtend {
        /// The deadline recorded at establishment.
        expires_at: u64,
        /// The deadline the rotation asked for.
        requested: u64,
    },
}

impl Display for SessionRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownStrength { observed } => {
                write!(formatter, "unknown authentication-strength tag {observed}")
            }
            Self::RepositoryMismatch => {
                formatter.write_str("the session is confined to a different repository")
            }
            Self::Expired { expires_at, now } => write!(
                formatter,
                "the session expired at {expires_at}, asked at {now}"
            ),
            Self::Revoked => formatter.write_str("the session was revoked"),
            Self::RevocationEvidenceRequired => formatter
                .write_str("this operation cannot be authorised without revocation evidence"),
            Self::StrengthInsufficient {
                established,
                required,
            } => write!(
                formatter,
                "the session authenticated as {established}, and this operation requires {required}"
            ),
            Self::RotationWouldStrengthen {
                established,
                requested,
            } => write!(
                formatter,
                "rotation cannot raise {established} to {requested}; authenticate again"
            ),
            Self::RotationWouldExtend {
                expires_at,
                requested,
            } => write!(
                formatter,
                "rotation cannot extend the deadline {expires_at} to {requested}"
            ),
        }
    }
}

impl core::error::Error for SessionRefusal {}

/// One established session: who authenticated, how, where, and until when.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    id: SessionId,
    principal: PrincipalId,
    repository: RepositoryId,
    strength: AuthenticationStrength,
    expires_at: u64,
}

impl Session {
    /// Establishes a session for a principal that has just authenticated.
    ///
    /// There is no fallible path here and that is deliberate: every bound is
    /// supplied by the caller who performed the authentication, and refusing at
    /// establishment would mean second-guessing an act this crate did not
    /// witness. The refusals live where the session is USED and ROTATED, which
    /// is where this crate has something to check.
    #[must_use]
    pub const fn establish(
        id: SessionId,
        principal: PrincipalId,
        repository: RepositoryId,
        strength: AuthenticationStrength,
        expires_at: u64,
    ) -> Self {
        Self {
            id,
            principal,
            repository,
            strength,
            expires_at,
        }
    }

    /// The revocable session handle.
    #[must_use]
    pub const fn id(&self) -> SessionId {
        self.id
    }

    /// The authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The repository this session is confined to.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// How the principal authenticated.
    #[must_use]
    pub const fn strength(&self) -> AuthenticationStrength {
        self.strength
    }

    /// The instant at which this session stops being usable.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Decides whether this session may be used on `repository` at `now` for an
    /// operation requiring `required` strength, and returns the principal.
    ///
    /// As with deploy keys, the permit HANDS BACK the principal, so a caller
    /// cannot end up authorising an identity it did not check. The order is the
    /// same discipline used elsewhere in this crate: identity-shaped mismatches
    /// first, then revocation, then time — a caller debugging a refusal learns
    /// the session is the wrong session before learning it is also old.
    ///
    /// # Errors
    ///
    /// [`SessionRefusal::RepositoryMismatch`],
    /// [`SessionRefusal::StrengthInsufficient`], [`SessionRefusal::Revoked`],
    /// [`SessionRefusal::RevocationEvidenceRequired`] or
    /// [`SessionRefusal::Expired`].
    pub fn authorize(
        &self,
        repository: RepositoryId,
        required: AuthenticationStrength,
        now: u64,
        revocation: RevocationEvidence,
    ) -> Result<PrincipalId, SessionRefusal> {
        if self.repository != repository {
            return Err(SessionRefusal::RepositoryMismatch);
        }
        if self.strength < required {
            return Err(SessionRefusal::StrengthInsufficient {
                established: self.strength,
                required,
            });
        }
        // Revocation before expiry, for the same reason it comes first for
        // tokens: "it expired anyway" is how a revocation that never propagated
        // escapes notice. A session is always authority-relevant — it is the
        // thing a request acts under — so NotChecked is refused outright rather
        // than only for a high-impact subset.
        match revocation {
            RevocationEvidence::Revoked => return Err(SessionRefusal::Revoked),
            RevocationEvidence::NotChecked => {
                return Err(SessionRefusal::RevocationEvidenceRequired);
            }
            RevocationEvidence::Live => {}
        }
        if now >= self.expires_at {
            return Err(SessionRefusal::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(self.principal)
    }

    /// Rotates this session onto a new handle.
    ///
    /// Rotation exists so a long-lived session can change its handle without
    /// re-authenticating — the handle is what leaks, so replacing it
    /// periodically is the point. What rotation may NOT do is buy anything the
    /// holder did not already have:
    ///
    /// * strength may fall or stay equal, never rise;
    /// * the deadline may move earlier or stay equal, never later.
    ///
    /// The principal and repository are carried over rather than accepted as
    /// arguments, so rotation cannot move a session to another principal or
    /// another repository — there is no parameter through which it could.
    ///
    /// A revoked session cannot be rotated. Rotation of a revoked session would
    /// be a revocation that mints its own successor, which is the one thing
    /// revocation must not permit.
    ///
    /// # Errors
    ///
    /// [`SessionRefusal::RotationWouldStrengthen`],
    /// [`SessionRefusal::RotationWouldExtend`], [`SessionRefusal::Revoked`],
    /// [`SessionRefusal::RevocationEvidenceRequired`] or
    /// [`SessionRefusal::Expired`].
    pub fn rotate(
        &self,
        id: SessionId,
        strength: AuthenticationStrength,
        expires_at: u64,
        now: u64,
        revocation: RevocationEvidence,
    ) -> Result<Self, SessionRefusal> {
        if strength > self.strength {
            return Err(SessionRefusal::RotationWouldStrengthen {
                established: self.strength,
                requested: strength,
            });
        }
        if expires_at > self.expires_at {
            return Err(SessionRefusal::RotationWouldExtend {
                expires_at: self.expires_at,
                requested: expires_at,
            });
        }
        match revocation {
            RevocationEvidence::Revoked => return Err(SessionRefusal::Revoked),
            RevocationEvidence::NotChecked => {
                return Err(SessionRefusal::RevocationEvidenceRequired);
            }
            RevocationEvidence::Live => {}
        }
        // An expired session cannot be rotated either: otherwise a holder who
        // let a session lapse could revive it indefinitely, and the deadline
        // would bound nothing.
        if now >= self.expires_at {
            return Err(SessionRefusal::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        Ok(Self {
            id,
            principal: self.principal,
            repository: self.repository,
            strength,
            expires_at,
        })
    }
}

impl CanonicalBody for Session {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/session/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("session");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.id.get());
        out.write_opaque_id(self.principal.as_bytes());
        out.write_opaque_id(self.repository.as_bytes());
        out.write_scalar(self.strength.tag());
        out.write_scalar(self.expires_at);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let id_value = input.read_scalar::<u64>("session.id")?;
        let id = SessionId::try_new(id_value).ok_or(CodecRefusal::ValueUnrepresentable {
            field: "session.id",
            observed: id_value,
            limit: 1,
        })?;
        let principal = PrincipalId::from_bytes(input.read_opaque_id("session.principal")?);
        let repository = RepositoryId::from_bytes(input.read_opaque_id("session.repository")?);
        let strength_offset = input.offset();
        let strength_tag = input.read_scalar::<u32>("session.strength")?;
        let strength = AuthenticationStrength::from_tag(strength_tag).map_err(|_| {
            CodecRefusal::VariantUnknown {
                field: "session.strength",
                observed: strength_tag,
                offset: strength_offset,
            }
        })?;
        let expires_at = input.read_scalar::<u64>("session.expires_at")?;
        Ok(Self::establish(
            id, principal, repository, strength, expires_at,
        ))
    }
}
