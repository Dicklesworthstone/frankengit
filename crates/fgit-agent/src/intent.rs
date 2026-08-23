//! The Intent Run: the authoritative agent control object
//! (`docs/AGENT_PROTOCOL.md` §5).
//!
//! §5 lists twenty-four fields. This slice carries the ones its acceptance
//! actually enforces — the allowed operation classes, the resource budget, the
//! expiry, and the identity of the authority read the run is based on — and
//! carries nothing it does not enforce. A field present but unchecked is worse
//! than an absent one: it reads as a control that exists.

use core::fmt;

use fgit_resource::ResourceVector;

use crate::capability::LogicalTime;
use crate::classes::ClassSet;
use crate::protocol::AuthorityReadReceipt;

/// Opaque run identity (`AGENT_PROTOCOL.md` §5.2).
///
/// §5.2 makes reusing a run ID with different bytes a terminal protocol
/// violation. This type carries the identity; committing the canonical run
/// bytes into it is the identity slice, not this one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RunId(u128);

impl RunId {
    /// Builds a run identity.
    #[must_use]
    pub const fn new(value: u128) -> Self {
        Self(value)
    }

    /// The raw value.
    #[must_use]
    pub const fn value(self) -> u128 {
        self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "run:{:032x}", self.0)
    }
}

/// The identity of the authority read a run is based on.
///
/// # This is NOT the §4.1 `AuthorityReadReceipt`
///
/// §4.1 defines a fourteen-field receipt, and `fgit-authority::HeadReadReceipt`
/// is documented as its storage-layer half. This type is neither: it is the
/// *identifying reference* a run carries so that which authority read it was
/// based on is fixed and tamper-evident.
///
/// It is deliberately named apart from `AuthorityReadReceipt` so it cannot be
/// mistaken for one. §4.1 warns that *"a backend ETag/version without an
/// authenticated head-body check is insufficient"*; carrying four fields of a
/// fourteen-field receipt and calling it the receipt would be exactly that
/// substitution. [`IntentRun::new_authenticated`] binds a run to the complete
/// receipt in the protocol slice; this legacy reference remains only for the
/// compatibility constructor and cannot authorize a workspace, context packet,
/// or publication request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityBasisRef {
    /// The repository the read was against.
    pub repository_id: u128,
    /// The authority head generation observed.
    pub authority_head_generation: u64,
    /// Digest of the head body observed, as the read's content identity.
    pub authority_head_digest: [u8; 32],
    /// When the read was verified, on the run's logical clock.
    pub verified_at: LogicalTime,
}

/// The machine-enforced scope of one agent run.
///
/// §5 is explicit that *"natural language may explain the goal; machine fields
/// enforce scope"*, and §5.1 that the objective *"cannot widen machine scope"*.
/// There is therefore no objective text in this type at all: a field that
/// cannot widen scope and is never read is not a control, and holding it here
/// would invite a reader to think it were one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentRun {
    run_id: RunId,
    base_authority: AuthorityBasisRef,
    authority_read_receipt: Option<AuthorityReadReceipt>,
    allowed_operation_classes: ClassSet,
    resource_budget: ResourceVector,
    expiry: LogicalTime,
}

impl IntentRun {
    /// Opens a run.
    ///
    /// # Errors
    ///
    /// [`RunRefused::EmptyScope`] when the run authorizes no class, so that a
    /// forgotten scope cannot present as a deliberately empty one.
    pub const fn new(
        run_id: RunId,
        base_authority: AuthorityBasisRef,
        allowed_operation_classes: ClassSet,
        resource_budget: ResourceVector,
        expiry: LogicalTime,
    ) -> Result<Self, RunRefused> {
        if allowed_operation_classes.is_empty() {
            return Err(RunRefused::EmptyScope);
        }
        Ok(Self {
            run_id,
            base_authority,
            authority_read_receipt: None,
            allowed_operation_classes,
            resource_budget,
            expiry,
        })
    }

    /// Opens a run from a complete, store-authenticated §4.1 authority receipt.
    ///
    /// The legacy four-field [`AuthorityBasisRef`] remains available for the
    /// original minimal compatibility slice. New protocol work must use this
    /// constructor: it derives that legacy reference from the full receipt and
    /// retains the receipt itself, so a caller cannot independently pair a
    /// chosen generation with another head or verifier profile.
    ///
    /// # Errors
    ///
    /// [`RunRefused::EmptyScope`] when the run authorizes no operation class.
    pub fn new_authenticated(
        run_id: RunId,
        authority_read_receipt: AuthorityReadReceipt,
        allowed_operation_classes: ClassSet,
        resource_budget: ResourceVector,
        expiry: LogicalTime,
    ) -> Result<Self, RunRefused> {
        let repository_id = u128::from_be_bytes(*authority_read_receipt.repository_id().as_bytes());
        let authority_head_id = authority_read_receipt.authority_head_id();
        let digest = authority_head_id
            .as_internal_object_id()
            .digest()
            .as_bytes();
        let authority_head_digest: [u8; 32] =
            digest
                .try_into()
                .map_err(|_| RunRefused::AuthorityHeadDigestLength {
                    observed: digest.len(),
                })?;
        let base_authority = AuthorityBasisRef {
            repository_id,
            authority_head_generation: authority_read_receipt.authority_head_generation().get(),
            authority_head_digest,
            verified_at: authority_read_receipt.verified_at_logical_time(),
        };
        let mut run = Self::new(
            run_id,
            base_authority,
            allowed_operation_classes,
            resource_budget,
            expiry,
        )?;
        run.authority_read_receipt = Some(authority_read_receipt);
        Ok(run)
    }

    /// The run identity.
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// The authority read this run is based on.
    #[must_use]
    pub const fn base_authority(&self) -> AuthorityBasisRef {
        self.base_authority
    }

    /// The complete authenticated authority receipt for a run opened through
    /// [`Self::new_authenticated`].
    ///
    /// `None` identifies the legacy four-field construction path. Callers that
    /// create a workspace, context packet, or publication request must refuse
    /// that path instead of treating its identifying reference as a full
    /// authority receipt.
    #[must_use]
    pub const fn authority_read_receipt(&self) -> Option<&AuthorityReadReceipt> {
        self.authority_read_receipt.as_ref()
    }

    /// The operation classes this run may perform at all.
    #[must_use]
    pub const fn allowed_operation_classes(&self) -> ClassSet {
        self.allowed_operation_classes
    }

    /// The whole-run resource budget.
    #[must_use]
    pub const fn resource_budget(&self) -> ResourceVector {
        self.resource_budget
    }

    /// The instant after which the run performs no further effects.
    #[must_use]
    pub const fn expiry(&self) -> LogicalTime {
        self.expiry
    }

    /// Whether the run is still open at `now`.
    #[must_use]
    pub const fn is_open_at(&self, now: LogicalTime) -> bool {
        now.value() < self.expiry.value()
    }
}

/// Why a run could not be opened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunRefused {
    /// The run would authorize no operation class.
    EmptyScope,
    /// The legacy compatibility reference cannot represent the authenticated
    /// head identity's digest width.
    AuthorityHeadDigestLength {
        /// Digest width observed on the authenticated head identity.
        observed: usize,
    },
}

impl fmt::Display for RunRefused {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyScope => {
                formatter.write_str("an intent run must allow at least one operation class")
            }
            Self::AuthorityHeadDigestLength { observed } => write!(
                formatter,
                "authenticated authority-head digest has {observed} bytes; legacy basis requires 32"
            ),
        }
    }
}

impl core::error::Error for RunRefused {}
