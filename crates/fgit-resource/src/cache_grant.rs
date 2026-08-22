//! CALM-015 grants for bounded, authority-derived cache materializations.
//!
//! A cache grant is not an authority capability or an obligation class. It
//! only funds one bounded attempt to derive a discardable local view from one
//! exact authenticated authority basis. A successful attempt yields a
//! [`CachePermit`] that can validate a cache lookup; it cannot move a ref,
//! write authority, or publish durable state.

use crate::algebra::{BudgetGrant, Grade};
use crate::ids::OpaqueHandle;
use core::fmt;
use fgit_types::{HeadGeneration, RepositoryAuthorityHeadId, RepositoryId};

/// Grades a [`CacheGrant`] must hold before a materializer may begin work.
///
/// A cache warm decodes one immutable frame, accounts for it as one object,
/// and constructs a bounded resident view. The caller may reserve more, but
/// omitting any of these grades refuses before allocation or decode work.
pub const CACHE_REQUIRED_GRADES: &[Grade] = &[
    Grade::Bytes,
    Grade::Objects,
    Grade::CpuMicros,
    Grade::MemoryBytes,
];

/// The locally authorized scope of one discardable cache entry.
///
/// Scope policy belongs to the caller that owns tenant/repository/intent-run
/// disclosure. This L0 crate carries its identity verbatim without inventing
/// a competing policy domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheScope(OpaqueHandle);

impl CacheScope {
    /// Binds a cache entry to one caller-defined, locally authorized scope.
    #[must_use]
    pub const fn new(handle: OpaqueHandle) -> Self {
        Self(handle)
    }

    /// The scope handle carried verbatim by this grant.
    #[must_use]
    pub const fn handle(self) -> OpaqueHandle {
        self.0
    }
}

/// The exact authority basis and scope a cache entry is allowed to represent.
///
/// The head identity says which canonical head body was authenticated and the
/// generation says when. Carrying both closes an ABA-shaped stale-cache path:
/// an entry can never be reused merely because an equal head identity later
/// reappears at a different authenticated generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CacheBinding {
    repository: RepositoryId,
    authority_head: RepositoryAuthorityHeadId,
    generation: HeadGeneration,
    scope: CacheScope,
}

impl CacheBinding {
    /// Names the only repository, exact authenticated head, generation, and
    /// cache scope for which a derived cache result may be served.
    #[must_use]
    pub const fn new(
        repository: RepositoryId,
        authority_head: RepositoryAuthorityHeadId,
        generation: HeadGeneration,
        scope: CacheScope,
    ) -> Self {
        Self {
            repository,
            authority_head,
            generation,
            scope,
        }
    }

    /// The repository the cache entry belongs to.
    #[must_use]
    pub const fn repository(self) -> RepositoryId {
        self.repository
    }

    /// The exact authenticated authority head the entry represents.
    #[must_use]
    pub const fn authority_head(self) -> RepositoryAuthorityHeadId {
        self.authority_head
    }

    /// The authenticated head generation the entry represents.
    #[must_use]
    pub const fn generation(self) -> HeadGeneration {
        self.generation
    }

    /// The locally authorized cache scope.
    #[must_use]
    pub const fn scope(self) -> CacheScope {
        self.scope
    }
}

/// Why a cache lookup cannot serve a derived view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CacheGrantRefusal {
    /// No materialized entry exists for the requested cache lookup.
    Unmaterialized,
    /// The entry was derived from a different exact authenticated basis or
    /// local cache scope and must be discarded rather than served.
    BasisMismatch,
    /// The caller omitted a grade required before cache materialization work.
    MissingRequiredGrade(Grade),
}

impl fmt::Display for CacheGrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Unmaterialized => {
                f.write_str("discard cache and refuse: no materialized cache entry")
            }
            Self::BasisMismatch => f.write_str(
                "discard cache and refuse: authenticated basis does not match cache binding",
            ),
            Self::MissingRequiredGrade(grade) => {
                write!(f, "cache materialization requires non-zero {grade}")
            }
        }
    }
}

impl std::error::Error for CacheGrantRefusal {}

/// A bounded reservation to materialize one authenticated, discardable cache
/// entry.
///
/// `CacheGrant` is intentionally not an [`crate::ObligationKind`]: CALM-015
/// is a `monotone_scoped` derived view, not a durable publication or external
/// effect. The grant is unforgeable without a ledger-issued [`BudgetGrant`].
/// Its drop path returns that budget and discards the unmaterialized attempt;
/// losing a cache never changes canonical truth.
#[must_use = "a cache grant must be accepted at its exact authenticated basis or discarded"]
#[derive(Debug)]
pub struct CacheGrant {
    binding: CacheBinding,
    budget: Option<BudgetGrant>,
}

impl CacheGrant {
    /// Reserves bounded resources before materialization work begins.
    ///
    /// Missing grades refuse immediately and return `budget` to its ledger,
    /// so an unfunded caller cannot begin decode or allocation work.
    pub fn reserve(binding: CacheBinding, budget: BudgetGrant) -> Result<Self, CacheGrantRefusal> {
        let amount = budget.amount();
        if let Some(grade) = CACHE_REQUIRED_GRADES
            .iter()
            .copied()
            .find(|grade| amount.get(*grade) == 0)
        {
            let _released = budget.release();
            return Err(CacheGrantRefusal::MissingRequiredGrade(grade));
        }
        Ok(Self {
            binding,
            budget: Some(budget),
        })
    }

    /// The exact binding this reservation is allowed to materialize.
    #[must_use]
    pub const fn binding(&self) -> CacheBinding {
        self.binding
    }

    /// Accepts a materialized view only after the caller authenticated the
    /// exact basis it was reserved for.
    ///
    /// A mismatch returns a typed refusal. The grant is then dropped, which
    /// returns its budget; no [`CachePermit`] exists on that path.
    pub fn accept(mut self, authenticated: CacheBinding) -> Result<CachePermit, CacheGrantRefusal> {
        if self.binding != authenticated {
            return Err(CacheGrantRefusal::BasisMismatch);
        }
        self.release_budget();
        Ok(CachePermit {
            binding: self.binding,
        })
    }

    /// Explicitly discards an unmaterialized or cancelled cache attempt.
    pub fn discard(mut self) {
        self.release_budget();
    }

    fn release_budget(&mut self) {
        if let Some(budget) = self.budget.take() {
            let _released = budget.release();
        }
    }
}

impl Drop for CacheGrant {
    fn drop(&mut self) {
        self.release_budget();
    }
}

/// A non-authoritative witness that a cache entry was materialized for one
/// exact authenticated basis.
///
/// This type has no mutation, publication, or authority API. Cache owners use
/// [`Self::require_matching`] before reading a local view; on either refusal
/// path they discard the view and re-read authority.
#[must_use = "a cache permit must be checked against the current authenticated basis before serving a cache entry"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachePermit {
    binding: CacheBinding,
}

impl CachePermit {
    /// The exact non-authoritative binding this permit witnesses.
    #[must_use]
    pub const fn binding(self) -> CacheBinding {
        self.binding
    }

    /// Refuses an absent cache entry separately from an entry whose exact
    /// authenticated binding does not match `authenticated`.
    ///
    /// The permitted result contains no authority capability; it merely says
    /// that the caller may use its already-local derived cache view.
    pub fn require_matching(
        candidate: Option<&Self>,
        authenticated: CacheBinding,
    ) -> Result<(), CacheGrantRefusal> {
        let Some(candidate) = candidate else {
            return Err(CacheGrantRefusal::Unmaterialized);
        };
        if candidate.binding != authenticated {
            return Err(CacheGrantRefusal::BasisMismatch);
        }
        Ok(())
    }
}
