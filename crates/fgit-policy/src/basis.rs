//! The typed facts a policy is evaluated against: the input root.
//!
//! Everything a rule can look at is a field of [`PolicyInputRoot`]. There is
//! no second source. That is what makes the evaluator a pure function of its
//! two arguments, and it is why the evaluation instant is a field here rather
//! than a clock read: evidence expiry is decided against a time the caller
//! supplied and can reproduce.
//!
//! ## This is the receive-pack basis
//!
//! A receive-pack decision has exactly these parts — the ref commands being
//! decided, the authenticated principal behind them, the evidence offered with
//! them, the repository aggregates they are decided against, and the instant.
//! FG-043b and FG-043r construct this type directly. Nothing translates.

use std::collections::{BTreeMap, BTreeSet};

use fgit_types::native::GitOid;
use fgit_types::refs::RefName;
use fgit_types::{PrincipalId, PrincipalSnapshotId};

use crate::error::PolicyInputRefusal;

/// Largest number of ref updates one input root may carry.
pub const MAX_SUBJECTS: usize = 65_536;

/// Largest number of evidence receipts one input root may carry.
pub const MAX_RECEIPTS: usize = 65_536;

/// Largest number of aggregate readings one input root may carry.
pub const MAX_AGGREGATES: usize = 1_024;

/// Largest number of team or capability labels one principal may carry.
pub const MAX_PRINCIPAL_LABELS: usize = 4_096;

/// The one namespace prefix a canonical ref scope is read from.
const CANONICAL_REF_PREFIX: &[u8] = b"refs";

slug_newtype!(
    EvidenceKind,
    "EvidenceKind",
    "The class of an evidence receipt, for example `code-review`."
);
slug_newtype!(
    IssuerLabel,
    "IssuerLabel",
    "The service a policy is willing to accept evidence from."
);
slug_newtype!(
    AggregateName,
    "AggregateName",
    "The name of one aggregate state reading."
);
slug_newtype!(
    LabelName,
    "LabelName",
    "One membership or capability label carried by a principal."
);

/// An instant, in whole seconds, supplied by the caller.
///
/// The zero point is the caller's, and the only operations are comparison and
/// a saturating difference, so nothing here can be mistaken for a wall clock
/// this crate read. Evidence expiry is decided against this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PolicyInstant(u64);

impl PolicyInstant {
    /// Builds an instant from whole seconds.
    #[must_use]
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// The instant as whole seconds.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }

    /// Seconds elapsed from `earlier` to this instant, saturating at zero.
    #[must_use]
    pub const fn saturating_since(self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

impl core::fmt::Display for PolicyInstant {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// What kind of principal made a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PrincipalKind {
    /// A person.
    Human,
    /// An automated identity operated by a person or team.
    Machine,
    /// A coding agent acting under an intent run.
    Agent,
    /// A first-party service acting for the forge itself.
    Service,
}

impl PrincipalKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 4] = [Self::Human, Self::Machine, Self::Agent, Self::Service];

    /// The stable lowercase token used in source text and in traces.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Machine => "machine",
            Self::Agent => "agent",
            Self::Service => "service",
        }
    }

    /// Parses the stable token, refusing anything else.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.token() == token)
    }

    /// The stable numeric code point used in canonical bytes.
    #[must_use]
    pub const fn code_point(self) -> u8 {
        match self {
            Self::Human => 1,
            Self::Machine => 2,
            Self::Agent => 3,
            Self::Service => 4,
        }
    }

    /// Resolves a code point, refusing one the closed set does not name.
    #[must_use]
    pub const fn from_code_point(code_point: u8) -> Option<Self> {
        match code_point {
            1 => Some(Self::Human),
            2 => Some(Self::Machine),
            3 => Some(Self::Agent),
            4 => Some(Self::Service),
            _ => None,
        }
    }
}

/// How strongly a principal authenticated, as an ordinal.
///
/// The order is the point: a rule writes `actor.authentication >=
/// multi_factor` and means every strength at or above it, so adding a stronger
/// method later does not silently exclude it from rules that already exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum AuthenticationStrength {
    /// No authentication was performed.
    None,
    /// One factor, such as a password or a bearer token.
    SingleFactor,
    /// Two or more independent factors.
    MultiFactor,
    /// A factor bound to hardware the principal holds.
    HardwareBacked,
}

impl AuthenticationStrength {
    /// Every strength, weakest first.
    pub const ALL: [Self; 4] = [
        Self::None,
        Self::SingleFactor,
        Self::MultiFactor,
        Self::HardwareBacked,
    ];

    /// The stable lowercase token used in source text and in traces.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SingleFactor => "single_factor",
            Self::MultiFactor => "multi_factor",
            Self::HardwareBacked => "hardware_backed",
        }
    }

    /// Parses the stable token, refusing anything else.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.token() == token)
    }

    /// The ordinal rank, weakest zero.
    #[must_use]
    pub const fn rank(self) -> u64 {
        match self {
            Self::None => 0,
            Self::SingleFactor => 1,
            Self::MultiFactor => 2,
            Self::HardwareBacked => 3,
        }
    }

    /// The stable numeric code point used in canonical bytes.
    ///
    /// One more than the rank, so that a zero byte is never a valid strength
    /// and a truncated body cannot decode as `none`.
    #[must_use]
    pub const fn code_point(self) -> u8 {
        match self {
            Self::None => 1,
            Self::SingleFactor => 2,
            Self::MultiFactor => 3,
            Self::HardwareBacked => 4,
        }
    }

    /// Resolves a code point, refusing one the closed set does not name.
    #[must_use]
    pub const fn from_code_point(code_point: u8) -> Option<Self> {
        match code_point {
            1 => Some(Self::None),
            2 => Some(Self::SingleFactor),
            3 => Some(Self::MultiFactor),
            4 => Some(Self::HardwareBacked),
            _ => None,
        }
    }
}

/// The shape of one ref command.
///
/// Whether an update is a fast-forward is a fact about the commit graph, which
/// this crate does not have and does not want. The caller decides it and says
/// so here; that is the one place the answer enters policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RefUpdateKind {
    /// The ref does not exist and would be created.
    Create,
    /// The ref exists and the new value has the old value as an ancestor.
    FastForward,
    /// The ref exists and the new value does not have the old value as an
    /// ancestor.
    NonFastForward,
    /// The ref exists and would be removed.
    Delete,
}

impl RefUpdateKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 4] = [
        Self::Create,
        Self::FastForward,
        Self::NonFastForward,
        Self::Delete,
    ];

    /// The stable lowercase token used in source text and in traces.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::FastForward => "fast_forward",
            Self::NonFastForward => "non_fast_forward",
            Self::Delete => "delete",
        }
    }

    /// Parses the stable token, refusing anything else.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.token() == token)
    }

    /// The stable numeric code point used in canonical bytes.
    #[must_use]
    pub const fn code_point(self) -> u8 {
        match self {
            Self::Create => 1,
            Self::FastForward => 2,
            Self::NonFastForward => 3,
            Self::Delete => 4,
        }
    }

    /// Resolves a code point, refusing one the closed set does not name.
    #[must_use]
    pub const fn from_code_point(code_point: u8) -> Option<Self> {
        match code_point {
            1 => Some(Self::Create),
            2 => Some(Self::FastForward),
            3 => Some(Self::NonFastForward),
            4 => Some(Self::Delete),
            _ => None,
        }
    }
}

/// One ref command, with the basis value it was decided against.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RefUpdateFact {
    name: RefName,
    previous: Option<GitOid>,
    next: Option<GitOid>,
    kind: RefUpdateKind,
    force_requested: bool,
}

impl RefUpdateFact {
    /// Builds a ref update, refusing a shape that contradicts its kind.
    ///
    /// A creation that names a previous value, or a deletion that names a next
    /// one, is not a command with an odd field: it is two different claims
    /// about the same basis, and accepting it would let a rule that reads
    /// `ref.update` disagree with a rule that reads the values.
    pub fn try_new(
        name: RefName,
        previous: Option<GitOid>,
        next: Option<GitOid>,
        kind: RefUpdateKind,
        force_requested: bool,
    ) -> Result<Self, PolicyInputRefusal> {
        let expected_previous = !matches!(kind, RefUpdateKind::Create);
        let expected_next = !matches!(kind, RefUpdateKind::Delete);
        if previous.is_some() != expected_previous || next.is_some() != expected_next {
            return Err(PolicyInputRefusal::UpdateShapeInconsistent {
                name: name.as_bytes().to_vec(),
                kind,
                previous_present: previous.is_some(),
                next_present: next.is_some(),
            });
        }
        Ok(Self {
            name,
            previous,
            next,
            kind,
            force_requested,
        })
    }

    /// The ref this command targets.
    #[must_use]
    pub const fn name(&self) -> &RefName {
        &self.name
    }

    /// The value the ref held in the pinned basis.
    #[must_use]
    pub const fn previous(&self) -> Option<&GitOid> {
        self.previous.as_ref()
    }

    /// The value the ref would hold afterwards.
    #[must_use]
    pub const fn next(&self) -> Option<&GitOid> {
        self.next.as_ref()
    }

    /// The shape of the command.
    #[must_use]
    pub const fn kind(&self) -> RefUpdateKind {
        self.kind
    }

    /// Whether the client asked for a forced update.
    #[must_use]
    pub const fn force_requested(&self) -> bool {
        self.force_requested
    }

    /// The protection scope the ref belongs to, or an empty slice for a ref
    /// outside the canonical `refs/` namespace.
    ///
    /// `refs/heads/main` scopes to `heads`, so a rule covers a namespace
    /// without enumerating its members.
    #[must_use]
    pub fn scope(&self) -> &[u8] {
        if !self.name.is_under(CANONICAL_REF_PREFIX) {
            return &[];
        }
        self.name.components().nth(1).unwrap_or(&[])
    }
}

/// The attributes of the principal a decision is made for.
///
/// This is a projection, not a body. FG-042a owns the principal snapshot; a
/// caller that holds one fills these fields in from it. Keeping the projection
/// here means the policy vocabulary does not move when that body's schema
/// does, and it means this crate authenticates nobody.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PrincipalFacts {
    principal: PrincipalId,
    snapshot: PrincipalSnapshotId,
    kind: PrincipalKind,
    authentication: AuthenticationStrength,
    teams: BTreeSet<LabelName>,
    capabilities: BTreeSet<LabelName>,
}

impl PrincipalFacts {
    /// Builds the principal facts, refusing a repeated label.
    ///
    /// A repeat is refused rather than collapsed because a caller that
    /// supplied one is describing a membership set it does not itself have a
    /// canonical form for, and silently collapsing would hide that.
    pub fn try_new(
        principal: PrincipalId,
        snapshot: PrincipalSnapshotId,
        kind: PrincipalKind,
        authentication: AuthenticationStrength,
        teams: &[LabelName],
        capabilities: &[LabelName],
    ) -> Result<Self, PolicyInputRefusal> {
        Ok(Self {
            principal,
            snapshot,
            kind,
            authentication,
            teams: label_set("teams", teams)?,
            capabilities: label_set("capabilities", capabilities)?,
        })
    }

    /// The authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }

    /// The principal snapshot the attributes were read from.
    #[must_use]
    pub const fn snapshot(&self) -> PrincipalSnapshotId {
        self.snapshot
    }

    /// What kind of principal this is.
    #[must_use]
    pub const fn kind(&self) -> PrincipalKind {
        self.kind
    }

    /// How strongly the principal authenticated.
    #[must_use]
    pub const fn authentication(&self) -> AuthenticationStrength {
        self.authentication
    }

    /// The principal's team memberships.
    #[must_use]
    pub const fn teams(&self) -> &BTreeSet<LabelName> {
        &self.teams
    }

    /// The principal's capabilities.
    #[must_use]
    pub const fn capabilities(&self) -> &BTreeSet<LabelName> {
        &self.capabilities
    }
}

fn label_set(
    field: &'static str,
    labels: &[LabelName],
) -> Result<BTreeSet<LabelName>, PolicyInputRefusal> {
    if labels.len() > MAX_PRINCIPAL_LABELS {
        return Err(PolicyInputRefusal::CountExceeded {
            field,
            observed: labels.len(),
            limit: MAX_PRINCIPAL_LABELS,
        });
    }
    let mut set = BTreeSet::new();
    for label in labels {
        if !set.insert(*label) {
            return Err(PolicyInputRefusal::DuplicateLabel {
                field,
                label: *label,
            });
        }
    }
    Ok(set)
}

/// One evidence receipt offered with a request.
///
/// The window is half-open: a receipt is live for an instant `t` when
/// `issued_at <= t` and `t < expires_at`. An empty window is refused at
/// construction, so "expired before it was issued" is not a state the
/// evaluator has to have an opinion about.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EvidenceReceipt {
    kind: EvidenceKind,
    issuer: IssuerLabel,
    subject: RefName,
    issued_at: PolicyInstant,
    expires_at: PolicyInstant,
}

impl EvidenceReceipt {
    /// Builds a receipt, refusing an empty validity window.
    pub fn try_new(
        kind: EvidenceKind,
        issuer: IssuerLabel,
        subject: RefName,
        issued_at: PolicyInstant,
        expires_at: PolicyInstant,
    ) -> Result<Self, PolicyInputRefusal> {
        if expires_at <= issued_at {
            return Err(PolicyInputRefusal::ReceiptWindowEmpty {
                kind,
                issued_at,
                expires_at,
            });
        }
        Ok(Self {
            kind,
            issuer,
            subject,
            issued_at,
            expires_at,
        })
    }

    /// The class of evidence.
    #[must_use]
    pub const fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// The service that issued it.
    #[must_use]
    pub const fn issuer(&self) -> IssuerLabel {
        self.issuer
    }

    /// The ref the receipt is about.
    #[must_use]
    pub const fn subject(&self) -> &RefName {
        &self.subject
    }

    /// When the receipt became live.
    #[must_use]
    pub const fn issued_at(&self) -> PolicyInstant {
        self.issued_at
    }

    /// When the receipt stops being live.
    #[must_use]
    pub const fn expires_at(&self) -> PolicyInstant {
        self.expires_at
    }

    /// Whether the receipt is live at `instant`.
    #[must_use]
    pub const fn is_live_at(&self, instant: PolicyInstant) -> bool {
        self.issued_at.seconds() <= instant.seconds()
            && instant.seconds() < self.expires_at.seconds()
    }
}

/// Everything a policy is evaluated against.
///
/// Construction canonicalises: receipts are sorted and deduplicated, aggregate
/// readings are keyed, and a repeated ref command is refused. The evaluator
/// therefore never sees a collection whose order came from the caller, which
/// is what makes a trace reproduce byte for byte when the same facts arrive in
/// a different order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyInputRoot {
    principal: PrincipalFacts,
    updates: Vec<RefUpdateFact>,
    receipts: Vec<EvidenceReceipt>,
    aggregates: BTreeMap<AggregateName, u64>,
    instant: PolicyInstant,
}

impl PolicyInputRoot {
    /// Builds the input root, refusing duplicates and over-large collections.
    ///
    /// The ref commands keep the caller's order, because a receive-pack
    /// command list is ordered and a trace that renumbered it would be harder
    /// to line up against the wire. Nothing else keeps caller order.
    pub fn try_new(
        principal: PrincipalFacts,
        updates: Vec<RefUpdateFact>,
        receipts: &[EvidenceReceipt],
        aggregates: &[(AggregateName, u64)],
        instant: PolicyInstant,
    ) -> Result<Self, PolicyInputRefusal> {
        if updates.len() > MAX_SUBJECTS {
            return Err(PolicyInputRefusal::CountExceeded {
                field: "updates",
                observed: updates.len(),
                limit: MAX_SUBJECTS,
            });
        }
        if receipts.len() > MAX_RECEIPTS {
            return Err(PolicyInputRefusal::CountExceeded {
                field: "receipts",
                observed: receipts.len(),
                limit: MAX_RECEIPTS,
            });
        }
        if aggregates.len() > MAX_AGGREGATES {
            return Err(PolicyInputRefusal::CountExceeded {
                field: "aggregates",
                observed: aggregates.len(),
                limit: MAX_AGGREGATES,
            });
        }

        let mut seen_targets = BTreeSet::new();
        for update in &updates {
            if !seen_targets.insert(update.name().clone()) {
                return Err(PolicyInputRefusal::DuplicateSubject {
                    name: update.name().as_bytes().to_vec(),
                });
            }
        }

        let mut ordered = receipts.to_vec();
        ordered.sort();
        for window in ordered.windows(2) {
            if window[0] == window[1] {
                return Err(PolicyInputRefusal::DuplicateReceipt {
                    kind: window[0].kind(),
                });
            }
        }

        let mut keyed = BTreeMap::new();
        for (name, reading) in aggregates {
            if keyed.insert(*name, *reading).is_some() {
                return Err(PolicyInputRefusal::DuplicateAggregate { name: *name });
            }
        }

        Ok(Self {
            principal,
            updates,
            receipts: ordered,
            aggregates: keyed,
            instant,
        })
    }

    /// The principal the decision is made for.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalFacts {
        &self.principal
    }

    /// The ref commands being decided, in the caller's order.
    #[must_use]
    pub fn updates(&self) -> &[RefUpdateFact] {
        &self.updates
    }

    /// The offered receipts, in canonical order.
    #[must_use]
    pub fn receipts(&self) -> &[EvidenceReceipt] {
        &self.receipts
    }

    /// The aggregate readings, keyed by name.
    #[must_use]
    pub const fn aggregates(&self) -> &BTreeMap<AggregateName, u64> {
        &self.aggregates
    }

    /// The instant the decision is made at.
    #[must_use]
    pub const fn instant(&self) -> PolicyInstant {
        self.instant
    }
}
