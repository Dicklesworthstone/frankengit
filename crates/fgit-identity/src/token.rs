//! Tokens: a bounded, revocable, audience-bound grant to act as a principal.
//!
//! A token is not a password with a timer. It names the principal it speaks
//! for, the audience it may be presented to, the operations it may perform, the
//! repository it is confined to, a budget, and an expiry — and it carries a
//! revocable handle so it can be withdrawn before any of those run out.
//!
//! # No clock, no ambient state
//!
//! Nothing here reads a clock. [`TokenGrant::authorize`] takes `now` as an
//! argument, so the same grant and the same question always produce the same
//! answer. That is what lets a decision be replayed later against the inputs it
//! was actually made with, rather than against whatever the clock says at
//! replay time.
//!
//! # Revocation is a parameter, not a convention
//!
//! The acceptance this module implements says revocation must propagate, with
//! no TTL-only revocation for high-impact scopes. A comment asking callers to
//! remember the revocation check is exactly the rule that rots. So
//! [`TokenGrant::authorize`] takes [`RevocationEvidence`] as a typed argument and
//! refuses a high-impact operation presented with
//! [`RevocationEvidence::NotChecked`]. Forgetting the check is a refusal at the
//! call site rather than a silent pass.

use core::fmt::{self, Display, Formatter};

use fgit_codec::wire::CanonicalBody;
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{DomainTag, PrincipalId, RepositoryId, SchemaFamily};

/// Wire tag for [`TokenOperation::Read`]. Zero stays reserved.
const OPERATION_READ: u32 = 1;
/// Wire tag for [`TokenOperation::Write`].
const OPERATION_WRITE: u32 = 2;
/// Wire tag for [`TokenOperation::Administer`].
const OPERATION_ADMINISTER: u32 = 3;

/// What a token may do.
///
/// As with deploy keys, nothing is implied: `Administer` does not confer
/// `Write`, and `Write` does not confer `Read`. A reviewer reading a grant
/// should see what it permits, not have to derive it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TokenOperation {
    /// Read repository contents.
    Read,
    /// Advance refs.
    Write,
    /// Change who may do what: membership, keys, other tokens.
    Administer,
}

impl TokenOperation {
    /// The wire tag for this operation.
    #[must_use]
    pub const fn tag(self) -> u32 {
        match self {
            Self::Read => OPERATION_READ,
            Self::Write => OPERATION_WRITE,
            Self::Administer => OPERATION_ADMINISTER,
        }
    }

    /// Parses a wire tag, refusing one this build does not know.
    ///
    /// # Errors
    ///
    /// [`TokenRefusal::UnknownOperation`] naming the tag observed.
    pub const fn from_tag(tag: u32) -> Result<Self, TokenRefusal> {
        match tag {
            OPERATION_READ => Ok(Self::Read),
            OPERATION_WRITE => Ok(Self::Write),
            OPERATION_ADMINISTER => Ok(Self::Administer),
            observed => Err(TokenRefusal::UnknownOperation { observed }),
        }
    }

    /// Whether this operation is high-impact, and therefore may never be
    /// authorised on expiry alone.
    ///
    /// `Write` and `Administer` both change state that another principal can
    /// observe or be harmed by. A stolen read token leaks; a stolen write or
    /// administer token rewrites. Only the second class justifies refusing to
    /// answer at all without revocation evidence, and drawing the line here
    /// rather than at "everything" keeps the obligation where it buys
    /// something.
    #[must_use]
    pub const fn is_high_impact(self) -> bool {
        matches!(self, Self::Write | Self::Administer)
    }
}

impl Display for TokenOperation {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => formatter.write_str("read"),
            Self::Write => formatter.write_str("write"),
            Self::Administer => formatter.write_str("administer"),
        }
    }
}

/// The revocable handle naming one issued token.
///
/// The handle is what revocation operates on, and it is deliberately separate
/// from any bytes a bearer presents: revoking must not require possessing the
/// credential, and a leaked credential must be revocable by an administrator
/// who never saw it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TokenHandle(u64);

impl TokenHandle {
    /// Builds a handle, refusing zero.
    ///
    /// Zero is reserved as the not-a-value, matching every other counter in
    /// this workspace, so a zeroed buffer can never name a live token.
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

impl Display for TokenHandle {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

pub use crate::revocation::RevocationEvidence;

/// Every way a token is declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenRefusal {
    /// The grant named no operations.
    NoOperations,
    /// The wire carried an operation tag this build does not know.
    UnknownOperation {
        /// The tag observed.
        observed: u32,
    },
    /// The token was presented to an audience it was not issued for.
    ///
    /// This is the audience-confusion refusal: a token minted for one service
    /// replayed against another.
    AudienceMismatch,
    /// The token is confined to a different repository.
    RepositoryMismatch,
    /// The token does not carry the operation requested.
    OperationNotGranted {
        /// The operation asked for.
        requested: TokenOperation,
    },
    /// The token expired at or before the instant asked about.
    Expired {
        /// The expiry recorded in the grant.
        expires_at: u64,
        /// The instant the question was asked about.
        now: u64,
    },
    /// The budget is exhausted.
    BudgetExhausted {
        /// Uses already spent.
        spent: u64,
        /// Uses granted.
        budget: u64,
    },
    /// The handle was revoked.
    Revoked,
    /// A high-impact operation was presented without revocation evidence.
    ///
    /// This is the structural form of "no TTL-only revocation for high-impact
    /// scopes": the answer is not "probably fine, it has not expired", it is a
    /// refusal to answer without the record.
    RevocationEvidenceRequired {
        /// The operation that demanded evidence.
        requested: TokenOperation,
    },
    /// Delegation would grant something the parent does not hold.
    AttenuationWouldWiden {
        /// Which axis widened.
        axis: &'static str,
    },
}

impl Display for TokenRefusal {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOperations => formatter.write_str("a token granting no operations is refused"),
            Self::UnknownOperation { observed } => {
                write!(formatter, "unknown token operation tag {observed}")
            }
            Self::AudienceMismatch => {
                formatter.write_str("the token was issued for a different audience")
            }
            Self::RepositoryMismatch => {
                formatter.write_str("the token is confined to a different repository")
            }
            Self::OperationNotGranted { requested } => {
                write!(formatter, "the token does not grant {requested}")
            }
            Self::Expired { expires_at, now } => {
                write!(
                    formatter,
                    "the token expired at {expires_at}, asked at {now}"
                )
            }
            Self::BudgetExhausted { spent, budget } => {
                write!(formatter, "budget exhausted: {spent} of {budget} spent")
            }
            Self::Revoked => formatter.write_str("the token handle was revoked"),
            Self::RevocationEvidenceRequired { requested } => write!(
                formatter,
                "{requested} is high-impact and cannot be authorised without revocation evidence"
            ),
            Self::AttenuationWouldWiden { axis } => {
                write!(formatter, "delegation would widen {axis}")
            }
        }
    }
}

impl core::error::Error for TokenRefusal {}

/// One issued token: who it speaks for, and every bound on its use.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenGrant {
    handle: TokenHandle,
    principal: PrincipalId,
    audience: Vec<u8>,
    repository: RepositoryId,
    operations: Vec<TokenOperation>,
    budget: u64,
    expires_at: u64,
}

impl TokenGrant {
    /// Issues a token.
    ///
    /// # Errors
    ///
    /// [`TokenRefusal::NoOperations`] when `operations` is empty. As with
    /// deploy keys, a grant that permits nothing is a mistake or a revocation
    /// wearing an issuance's clothes, and storing it would make "issued" and
    /// "may do nothing" the same state.
    pub fn issue(
        handle: TokenHandle,
        principal: PrincipalId,
        audience: impl Into<Vec<u8>>,
        repository: RepositoryId,
        operations: &[TokenOperation],
        budget: u64,
        expires_at: u64,
    ) -> Result<Self, TokenRefusal> {
        let mut operations = operations.to_vec();
        operations.sort_unstable();
        operations.dedup();
        if operations.is_empty() {
            return Err(TokenRefusal::NoOperations);
        }
        Ok(Self {
            handle,
            principal,
            audience: audience.into(),
            repository,
            operations,
            budget,
            expires_at,
        })
    }

    /// The revocable handle.
    #[must_use]
    pub const fn handle(&self) -> TokenHandle {
        self.handle
    }

    /// The principal this token speaks for.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The audience it may be presented to.
    #[must_use]
    pub fn audience(&self) -> &[u8] {
        &self.audience
    }

    /// The repository it is confined to.
    #[must_use]
    pub const fn repository(&self) -> RepositoryId {
        self.repository
    }

    /// The operations granted, sorted and duplicate-free.
    #[must_use]
    pub fn operations(&self) -> &[TokenOperation] {
        &self.operations
    }

    /// Uses granted.
    #[must_use]
    pub const fn budget(&self) -> u64 {
        self.budget
    }

    /// The instant at which this token stops being usable.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Decides whether this token authorises `requested` under the stated
    /// conditions.
    ///
    /// Every bound is checked, and the order is deliberate: identity-shaped
    /// mismatches (audience, repository, operation) are reported before
    /// time-and-budget ones, so a caller debugging a refusal learns that the
    /// token is the wrong token before learning that it is also old.
    ///
    /// # Errors
    ///
    /// [`TokenRefusal::AudienceMismatch`], [`TokenRefusal::RepositoryMismatch`],
    /// [`TokenRefusal::OperationNotGranted`],
    /// [`TokenRefusal::RevocationEvidenceRequired`], [`TokenRefusal::Revoked`],
    /// [`TokenRefusal::Expired`] or [`TokenRefusal::BudgetExhausted`].
    pub fn authorize(
        &self,
        audience: &[u8],
        repository: RepositoryId,
        requested: TokenOperation,
        now: u64,
        spent: u64,
        revocation: RevocationEvidence,
    ) -> Result<(), TokenRefusal> {
        if self.audience != audience {
            return Err(TokenRefusal::AudienceMismatch);
        }
        if self.repository != repository {
            return Err(TokenRefusal::RepositoryMismatch);
        }
        if !self.operations.contains(&requested) {
            return Err(TokenRefusal::OperationNotGranted { requested });
        }
        // Revocation is consulted BEFORE expiry and budget. A revoked token
        // that has also expired must report the revocation, because "it
        // expired anyway" is how a revocation that never propagated escapes
        // notice.
        match revocation {
            RevocationEvidence::Revoked => return Err(TokenRefusal::Revoked),
            RevocationEvidence::NotChecked if requested.is_high_impact() => {
                return Err(TokenRefusal::RevocationEvidenceRequired { requested });
            }
            RevocationEvidence::NotChecked | RevocationEvidence::Live => {}
        }
        if now >= self.expires_at {
            return Err(TokenRefusal::Expired {
                expires_at: self.expires_at,
                now,
            });
        }
        if spent >= self.budget {
            return Err(TokenRefusal::BudgetExhausted {
                spent,
                budget: self.budget,
            });
        }
        Ok(())
    }

    /// Delegates a narrower token from this one.
    ///
    /// Every axis may only narrow. The handle is new, because a delegate that
    /// shared its parent's handle could not be revoked independently — and a
    /// delegation you cannot revoke without revoking the parent is not a
    /// delegation, it is a copy.
    ///
    /// # Errors
    ///
    /// [`TokenRefusal::AttenuationWouldWiden`] naming the axis that widened,
    /// or [`TokenRefusal::NoOperations`] when the delegate would grant nothing.
    pub fn attenuate(
        &self,
        handle: TokenHandle,
        operations: &[TokenOperation],
        budget: u64,
        expires_at: u64,
    ) -> Result<Self, TokenRefusal> {
        if let Some(operation) = operations.iter().find(|o| !self.operations.contains(o)) {
            let _ = operation;
            return Err(TokenRefusal::AttenuationWouldWiden { axis: "operations" });
        }
        if budget > self.budget {
            return Err(TokenRefusal::AttenuationWouldWiden { axis: "budget" });
        }
        if expires_at > self.expires_at {
            return Err(TokenRefusal::AttenuationWouldWiden { axis: "expiry" });
        }
        Self::issue(
            handle,
            self.principal,
            self.audience.clone(),
            self.repository,
            operations,
            budget,
            expires_at,
        )
    }
}

impl CanonicalBody for TokenGrant {
    const DOMAIN: DomainTag = DomainTag::from_static("frankengit/token-grant/v1");
    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static("token-grant");
    const SCHEMA_MAJOR: u16 = 1;
    const SCHEMA_MINOR: u16 = 0;

    fn write_payload(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_scalar(self.handle.get());
        out.write_opaque_id(self.principal.as_bytes());
        out.write_bytes("token.audience", &self.audience)?;
        out.write_opaque_id(self.repository.as_bytes());
        out.write_canonical_set(
            "token.operations",
            &self.operations,
            |encoder, operation| {
                encoder.write_scalar(operation.tag());
                Ok(())
            },
        )?;
        out.write_scalar(self.budget);
        out.write_scalar(self.expires_at);
        Ok(())
    }

    fn read_payload(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let handle_value = input.read_scalar::<u64>("token.handle")?;
        let handle =
            TokenHandle::try_new(handle_value).ok_or(CodecRefusal::ValueUnrepresentable {
                field: "token.handle",
                observed: handle_value,
                limit: 1,
            })?;
        let principal = PrincipalId::from_bytes(input.read_opaque_id("token.principal")?);
        let audience = input.read_bytes("token.audience")?.to_vec();
        let repository = RepositoryId::from_bytes(input.read_opaque_id("token.repository")?);
        let operations = input.read_canonical_set("token.operations", |decoder| {
            let offset = decoder.offset();
            let tag = decoder.read_scalar::<u32>("token.operation")?;
            TokenOperation::from_tag(tag).map_err(|_| CodecRefusal::VariantUnknown {
                field: "token.operation",
                observed: tag,
                offset,
            })
        })?;
        let budget = input.read_scalar::<u64>("token.budget")?;
        let expires_at = input.read_scalar::<u64>("token.expires_at")?;
        // Decode goes through the same checked constructor the API does, so a
        // hostile encoder cannot mint a token that grants nothing.
        Self::issue(
            handle,
            principal,
            audience,
            repository,
            &operations,
            budget,
            expires_at,
        )
        .map_err(|_| CodecRefusal::ValueUnrepresentable {
            field: "token.operations",
            observed: 0,
            limit: 1,
        })
    }
}
