//! Named status-check facts supplied by an authenticated admission boundary.
//!
//! Shape validation is not signature verification or a runner attestation.
//! Callers authenticate the issuer, verify its evidence and select each current
//! canonical result at the same basis as the ref update before constructing
//! these facts. A local process exit code alone cannot establish success here.

use fgit_types::{AsciiSlug, GitOid, RefName};

use super::{IssuerLabel, PolicyInstant};
use crate::error::PolicyInputRefusal;

/// A verified check's explicit result. Only `Success` satisfies a required check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum StatusCheckConclusion {
    Success,
    Failure,
    Cancelled,
    TimedOut,
    ActionRequired,
}

/// One verified result for an exact named check on an exact native commit.
///
/// This is an input fact, not durable evidence and not an authorization token.
/// Its constructor cannot establish the authenticity of caller-supplied fields.
/// The immutable fields keep unrelated generic receipt semantics unchanged.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StatusCheckReceipt {
    // This prefix is the semantic slot and defines canonical sort order.
    subject: RefName,
    commit: GitOid,
    name: AsciiSlug,
    issuer: IssuerLabel,
    conclusion: StatusCheckConclusion,
    issued_at: PolicyInstant,
    expires_at: PolicyInstant,
}

impl StatusCheckReceipt {
    /// Validate the native identity and half-open validity interval.
    ///
    /// This does not verify execution or authenticate the issuer. Callers must
    /// select one canonical result per (ref, commit, name); input construction
    /// refuses duplicate slots even when their conclusions happen to agree.
    pub fn try_new(
        name: AsciiSlug,
        issuer: IssuerLabel,
        subject: RefName,
        commit: GitOid,
        conclusion: StatusCheckConclusion,
        issued_at: PolicyInstant,
        expires_at: PolicyInstant,
    ) -> Result<Self, PolicyInputRefusal> {
        if commit.is_zero() {
            return Err(PolicyInputRefusal::StatusCheckCommitZero { name });
        }
        if expires_at <= issued_at {
            return Err(PolicyInputRefusal::StatusCheckWindowEmpty {
                name,
                issued_at,
                expires_at,
            });
        }
        Ok(Self {
            subject,
            commit,
            name,
            issuer,
            conclusion,
            issued_at,
            expires_at,
        })
    }

    /// The exact, case-sensitive required-check name.
    #[must_use]
    pub const fn name(&self) -> AsciiSlug {
        self.name
    }

    /// The authenticated issuer selected by the admission boundary.
    #[must_use]
    pub const fn issuer(&self) -> IssuerLabel {
        self.issuer
    }

    /// The exact ref whose proposed update this result concerns.
    #[must_use]
    pub const fn subject(&self) -> &RefName {
        &self.subject
    }

    /// The native commit whose execution was verified, including its hash domain.
    #[must_use]
    pub const fn commit(&self) -> GitOid {
        self.commit
    }

    /// The explicit result; presence or liveness alone does not imply success.
    #[must_use]
    pub const fn conclusion(&self) -> StatusCheckConclusion {
        self.conclusion
    }

    #[must_use]
    pub const fn issued_at(&self) -> PolicyInstant {
        self.issued_at
    }

    #[must_use]
    pub const fn expires_at(&self) -> PolicyInstant {
        self.expires_at
    }

    /// Whether `issued_at <= instant < expires_at`.
    #[must_use]
    pub const fn is_live_at(&self, instant: PolicyInstant) -> bool {
        self.issued_at.seconds() <= instant.seconds()
            && instant.seconds() < self.expires_at.seconds()
    }

    pub(super) const fn slot(&self) -> (&RefName, GitOid, AsciiSlug) {
        (&self.subject, self.commit, self.name)
    }
}
