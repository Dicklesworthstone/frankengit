//! SubIntent delegation, ancestry verification, and bounded fan-out
//! (`docs/AGENT_PROTOCOL.md` §6.2, §13).
//!
//! # The Normative Delegation Contract
//!
//! AGENT_PROTOCOL.md §6.2 states:
//!
//! > "Delegation may only intersect selectors, reduce quotas, shorten expiry,
//! > narrow operations, bind additional identities, and add caveats. A verifier
//! > checks the complete ancestry. Missing ancestry or amplification is refused."
//!
//! And §13 defines the [`SubIntent`] control record:
//!
//! > "A child receives a SubIntent, attenuated capabilities, bounded budget, exact
//! > inputs, output schema, and evidence requirements. The parent cannot delegate
//! > authority or budget it does not possess.
//! > The child returns an immutable result bundle. The parent validates schema,
//! > commitments, evidence, and authority ancestry before use. Child prose is
//! > untrusted data. Recursion depth, fan-out, aggregate budget, context duplication,
//! > and wall-clock are bounded."
//!
//! # Conservation and Bounded Multi-Agent Governance
//!
//! Multi-agent systems without conservation risk unbounded resource explosion:
//! an agent allocating 100% of its budget to N sub-agents multiplies resources
//! by N. This module enforces aggregate budget conservation:
//!
//! ```text
//! sum_{c in active_children} budget(c) <= initial_budget
//! ```
//!
//! Proven by construction: [`SubIntentFanOutTracker`] manages the parent's budget
//! using [`fgit_resource::ResourceVector::split`] and [`fgit_resource::ResourceVector::combine`].
//! Budget cannot be synthesized. Recursion depth and fan-out are strictly bounded.

use core::fmt;
use std::collections::BTreeMap;

use fgit_codec::{CodecRefusal, Encoder};
use fgit_crypto::{DigestHasher, GitHashAlgorithm, Sha256};
use fgit_resource::{ResourceError, ResourceVector};

use crate::broker::AgentInstanceId;
use crate::capability::{
    Capability, CapabilityId, ChainRefused, LogicalTime, SealedCapability, verify_chain,
};
use crate::classes::{ClassSet, OperationClass};
use crate::ecc::{EvidenceClass, IndependenceDimension};
use crate::intent::{IntentRun, RunId};

/// Domain separation tag for sub-intent canonical commitment.
pub const SUBINTENT_DOMAIN: &[u8] = b"frankengit.agent.subintent.v1\0";

/// Maximum recursion depth for sub-intent delegation trees.
pub const MAX_DELEGATION_DEPTH: u16 = 4;

/// Maximum active concurrent child sub-intents per parent run.
pub const MAX_DELEGATION_FAN_OUT: usize = 16;

/// Maximum input commitments attached to a single sub-intent.
pub const MAX_SUBINTENT_INPUT_COMMITMENTS: usize = 256;

/// Maximum cumulative duplicate context bytes across concurrent sibling sub-intents.
pub const MAX_CONTEXT_DUPLICATION_BYTES: u64 = 32 * 1024 * 1024; // 32 MiB

/// Maximum caveats attached to a single sub-intent.
pub const MAX_SUBINTENT_CAVEATS: usize = 64;

/// Maximum additional identities bound to a single sub-intent.
pub const MAX_SUBINTENT_IDENTITIES: usize = 16;

/// Maximum capabilities delegated in a single sub-intent.
pub const MAX_SUBINTENT_CAPABILITIES: usize = 32;

/// Stable cryptographic identity of a SubIntent.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SubIntentId([u8; 32]);

impl SubIntentId {
    /// Builds a sub-intent ID from raw bytes.
    #[must_use]
    pub const fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw 32-byte digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for SubIntentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("subintent:")?;
        write_hex(formatter, &self.0)
    }
}

/// A scope selector restricting the targets of delegated operations (§6.2).
///
/// Delegation may only intersect selectors (narrow or retain identical scope).
/// Widening a selector (e.g., child requesting a broader path prefix than parent)
/// is amplification and is refused.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Selector {
    /// Workspace path prefix (e.g. "crates/fgit-agent/").
    PathPrefix(String),
    /// Ref name or pattern prefix (e.g. "refs/heads/feature/").
    RefPrefix(String),
    /// Network destination or domain class.
    Destination(String),
}

impl Selector {
    /// Checks whether `self` (child selector) is an attenuation (narrowing or identical)
    /// of `parent`.
    #[must_use]
    pub fn is_attenuation_of(&self, parent: &Self) -> bool {
        match (self, parent) {
            (Self::PathPrefix(child), Self::PathPrefix(parent)) => {
                child.starts_with(parent.as_str())
            }
            (Self::RefPrefix(child), Self::RefPrefix(parent)) => {
                child.starts_with(parent.as_str())
            }
            (Self::Destination(child), Self::Destination(parent)) => {
                child == parent || child.ends_with(&format!(".{parent}"))
            }
            _ => false,
        }
    }
}

/// Additional policy caveats bound to delegated execution (§6.2).
///
/// Delegation may only ADD caveats. A child omitting any caveat present in its
/// parent is an attenuation violation and is refused.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Caveat {
    /// Restricts workspace access or refs to a specific selector.
    ScopedSelector(Selector),
    /// Bounds the maximum context bytes this branch may receive.
    MaxContextBytes(u64),
    /// Explicitly disallows an operation class even if granted by capability.
    DisallowedClass(OperationClass),
    /// Requires that any evidence produced by this sub-agent have verified independence.
    RequireIndependence(IndependenceDimension),
    /// Opaque custom policy caveat with domain-separated tag and payload digest.
    Custom {
        /// Numerical tag distinguishing caveat types.
        tag: u32,
        /// Canonical digest of the caveat constraint payload.
        payload_digest: [u8; 32],
    },
}

/// Permitted disclosure level for sub-agent results and evidence.
///
/// Delegation may only maintain or narrow disclosure (lower numerical value).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum DisclosurePolicy {
    /// Confidential to parent run; no external or peer disclosure without parent mediation.
    ConfidentialParentOnly = 0,
    /// Results may be shared with siblings in the same delegation tree.
    SiblingVisible = 1,
    /// Evidence records only may be published.
    PublicEvidenceOnly = 2,
    /// Full disclosure including internal intermediate steps.
    FullAudit = 3,
}

impl DisclosurePolicy {
    /// Checks whether `self` is as restrictive or more restrictive than `parent`.
    #[must_use]
    pub const fn is_attenuation_of(self, parent: Self) -> bool {
        (self as u8) <= (parent as u8)
    }
}

/// An attenuated capability bundled with its complete root-to-leaf ancestry chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedCapability {
    parent_capability_ref: CapabilityId,
    chain: Vec<SealedCapability>,
    selectors: Vec<Selector>,
}

impl DelegatedCapability {
    /// Creates a delegated capability bundle.
    #[must_use]
    pub const fn new(
        parent_capability_ref: CapabilityId,
        chain: Vec<SealedCapability>,
        selectors: Vec<Selector>,
    ) -> Self {
        Self {
            parent_capability_ref,
            chain,
            selectors,
        }
    }

    /// The parent capability identity this was attenuated from.
    #[must_use]
    pub const fn parent_capability_ref(&self) -> CapabilityId {
        self.parent_capability_ref
    }

    /// Full root-first sealed capability chain from root to this leaf capability.
    #[must_use]
    pub fn chain(&self) -> &[SealedCapability] {
        &self.chain
    }

    /// Mutable access to the chain (for constructing test tampered chains).
    pub fn chain_mut(&mut self) -> &mut Vec<SealedCapability> {
        &mut self.chain
    }

    /// Selectors bound to this capability.
    #[must_use]
    pub fn selectors(&self) -> &[Selector] {
        &self.selectors
    }

    /// The leaf capability at the end of the chain, if present.
    #[must_use]
    pub fn leaf(&self) -> Option<&Capability> {
        self.chain.last().map(SealedCapability::capability)
    }
}

/// Parameters for constructing an immutable [`SubIntent`].
#[derive(Clone, Debug)]
pub struct SubIntentParams {
    /// Distinct run identity for the sub-agent.
    pub child_run_id: RunId,
    /// The parent run delegating this work.
    pub parent_run_id: RunId,
    /// Canonical digest of the objective description.
    pub objective_digest: [u8; 32],
    /// Immutable input commitments (context packets, object digests).
    pub input_commitments: Vec<[u8; 32]>,
    /// Expected output schema identifier.
    pub output_schema_id: [u8; 32],
    /// Delegated capabilities with complete ancestry chains.
    pub attenuated_capabilities: Vec<DelegatedCapability>,
    /// Resource budget allocated to this sub-intent.
    pub budget: ResourceVector,
    /// Logical deadline by which the sub-intent must complete.
    pub deadline: LogicalTime,
    /// Required evidence classes the child must produce.
    pub required_evidence: Vec<EvidenceClass>,
    /// Disclosure policy.
    pub disclosure_policy: DisclosurePolicy,
    /// Additional authorized agent identities.
    pub additional_identities: Vec<AgentInstanceId>,
    /// Policy caveats.
    pub caveats: Vec<Caveat>,
    /// Delegation recursion depth (0 for direct children of root agent).
    pub depth: u16,
    /// Approximate context size in bytes for context-duplication bounding.
    pub context_bytes: u64,
}

/// An authoritative SubIntent delegation record (`AGENT_PROTOCOL.md` §13).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubIntent {
    id: SubIntentId,
    child_run_id: RunId,
    parent_run_id: RunId,
    objective_digest: [u8; 32],
    input_commitments: Vec<[u8; 32]>,
    output_schema_id: [u8; 32],
    attenuated_capabilities: Vec<DelegatedCapability>,
    budget: ResourceVector,
    deadline: LogicalTime,
    required_evidence: Vec<EvidenceClass>,
    disclosure_policy: DisclosurePolicy,
    additional_identities: Vec<AgentInstanceId>,
    caveats: Vec<Caveat>,
    depth: u16,
    context_bytes: u64,
}

impl SubIntent {
    /// Builds and canonically seals a SubIntent.
    ///
    /// # Errors
    ///
    /// Refuses self-delegation, empty capabilities, or bounds violations
    /// on counts of commitments, caveats, identities, or capabilities.
    pub fn build(params: SubIntentParams) -> Result<Self, SubIntentRefusal> {
        if params.child_run_id == params.parent_run_id {
            return Err(SubIntentRefusal::SelfDelegationNotAllowed {
                run_id: params.child_run_id,
            });
        }
        if params.attenuated_capabilities.is_empty() {
            return Err(SubIntentRefusal::EmptyCapabilities);
        }
        if params.attenuated_capabilities.len() > MAX_SUBINTENT_CAPABILITIES {
            return Err(SubIntentRefusal::TooManyCapabilities {
                observed: params.attenuated_capabilities.len(),
                limit: MAX_SUBINTENT_CAPABILITIES,
            });
        }
        if params.input_commitments.len() > MAX_SUBINTENT_INPUT_COMMITMENTS {
            return Err(SubIntentRefusal::TooManyInputCommitments {
                observed: params.input_commitments.len(),
                limit: MAX_SUBINTENT_INPUT_COMMITMENTS,
            });
        }
        if params.caveats.len() > MAX_SUBINTENT_CAVEATS {
            return Err(SubIntentRefusal::TooManyCaveats {
                observed: params.caveats.len(),
                limit: MAX_SUBINTENT_CAVEATS,
            });
        }
        if params.additional_identities.len() > MAX_SUBINTENT_IDENTITIES {
            return Err(SubIntentRefusal::TooManyIdentities {
                observed: params.additional_identities.len(),
                limit: MAX_SUBINTENT_IDENTITIES,
            });
        }

        let id = SubIntentId(
            subintent_commitment(&params)
                .map_err(SubIntentRefusal::CanonicalCommitmentFailure)?,
        );

        Ok(Self {
            id,
            child_run_id: params.child_run_id,
            parent_run_id: params.parent_run_id,
            objective_digest: params.objective_digest,
            input_commitments: params.input_commitments,
            output_schema_id: params.output_schema_id,
            attenuated_capabilities: params.attenuated_capabilities,
            budget: params.budget,
            deadline: params.deadline,
            required_evidence: params.required_evidence,
            disclosure_policy: params.disclosure_policy,
            additional_identities: params.additional_identities,
            caveats: params.caveats,
            depth: params.depth,
            context_bytes: params.context_bytes,
        })
    }

    /// SubIntent cryptographic identity.
    #[must_use]
    pub const fn id(&self) -> SubIntentId {
        self.id
    }

    /// Child run identity.
    #[must_use]
    pub const fn child_run_id(&self) -> RunId {
        self.child_run_id
    }

    /// Parent run identity.
    #[must_use]
    pub const fn parent_run_id(&self) -> RunId {
        self.parent_run_id
    }

    /// Objective commitment digest.
    #[must_use]
    pub const fn objective_digest(&self) -> &[u8; 32] {
        &self.objective_digest
    }

    /// Input commitments.
    #[must_use]
    pub fn input_commitments(&self) -> &[[u8; 32]] {
        &self.input_commitments
    }

    /// Expected output schema identifier.
    #[must_use]
    pub const fn output_schema_id(&self) -> &[u8; 32] {
        &self.output_schema_id
    }

    /// Attenuated capabilities.
    #[must_use]
    pub fn attenuated_capabilities(&self) -> &[DelegatedCapability] {
        &self.attenuated_capabilities
    }

    /// Mutable attenuated capabilities (for creating tampered instances in adversarial tests).
    pub fn attenuated_capabilities_mut(&mut self) -> &mut Vec<DelegatedCapability> {
        &mut self.attenuated_capabilities
    }

    /// Allocated resource budget.
    #[must_use]
    pub const fn budget(&self) -> ResourceVector {
        self.budget
    }

    /// Logical deadline.
    #[must_use]
    pub const fn deadline(&self) -> LogicalTime {
        self.deadline
    }

    /// Required evidence classes.
    #[must_use]
    pub fn required_evidence(&self) -> &[EvidenceClass] {
        &self.required_evidence
    }

    /// Disclosure policy.
    #[must_use]
    pub const fn disclosure_policy(&self) -> DisclosurePolicy {
        self.disclosure_policy
    }

    /// Additional authorized agent identities.
    #[must_use]
    pub fn additional_identities(&self) -> &[AgentInstanceId] {
        &self.additional_identities
    }

    /// Policy caveats.
    #[must_use]
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Delegation depth.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Context size in bytes.
    #[must_use]
    pub const fn context_bytes(&self) -> u64 {
        self.context_bytes
    }
}

/// Operational bounds for sub-intent delegation trees.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationLimits {
    /// Maximum recursion depth allowed.
    pub max_depth: u16,
    /// Maximum active concurrent child sub-intents.
    pub max_fan_out: usize,
    /// Maximum cumulative duplicate context bytes across concurrent children.
    pub max_context_duplication_bytes: u64,
}

impl Default for DelegationLimits {
    fn default() -> Self {
        Self {
            max_depth: MAX_DELEGATION_DEPTH,
            max_fan_out: MAX_DELEGATION_FAN_OUT,
            max_context_duplication_bytes: MAX_CONTEXT_DUPLICATION_BYTES,
        }
    }
}

/// Tracks fan-out, recursion depth, and aggregate budget conservation for one parent run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubIntentFanOutTracker {
    parent_run_id: RunId,
    initial_budget: ResourceVector,
    allocated_budget: ResourceVector,
    unallocated_budget: ResourceVector,
    active_children: BTreeMap<RunId, SubIntent>,
    cumulative_context_bytes: u64,
    depth: u16,
    limits: DelegationLimits,
    parent_caveats: Vec<Caveat>,
    parent_selectors: Vec<Selector>,
    parent_disclosure_policy: DisclosurePolicy,
}

impl SubIntentFanOutTracker {
    /// Creates a new delegation tracker for a root or parent run.
    #[must_use]
    pub fn new(
        parent_run_id: RunId,
        initial_budget: ResourceVector,
        depth: u16,
        limits: DelegationLimits,
        parent_caveats: Vec<Caveat>,
        parent_selectors: Vec<Selector>,
        parent_disclosure_policy: DisclosurePolicy,
    ) -> Self {
        Self {
            parent_run_id,
            initial_budget,
            allocated_budget: ResourceVector::ZERO,
            unallocated_budget: initial_budget,
            active_children: BTreeMap::new(),
            cumulative_context_bytes: 0,
            depth,
            limits,
            parent_caveats,
            parent_selectors,
            parent_disclosure_policy,
        }
    }

    /// Parent run identity.
    #[must_use]
    pub const fn parent_run_id(&self) -> RunId {
        self.parent_run_id
    }

    /// Initial whole-run budget.
    #[must_use]
    pub const fn initial_budget(&self) -> ResourceVector {
        self.initial_budget
    }

    /// Sum of budgets currently allocated to active child sub-intents.
    #[must_use]
    pub const fn allocated_budget(&self) -> ResourceVector {
        self.allocated_budget
    }

    /// Remaining unallocated budget available for new delegations.
    #[must_use]
    pub const fn unallocated_budget(&self) -> ResourceVector {
        self.unallocated_budget
    }

    /// Number of active child sub-intents.
    #[must_use]
    pub fn active_children_count(&self) -> usize {
        self.active_children.len()
    }

    /// Recursion depth of this tracker.
    #[must_use]
    pub const fn depth(&self) -> u16 {
        self.depth
    }

    /// Configured limits.
    #[must_use]
    pub const fn limits(&self) -> DelegationLimits {
        self.limits
    }

    /// Proves that aggregate budget conservation strictly holds at this instant:
    /// `allocated_budget + unallocated_budget == initial_budget`.
    #[must_use]
    pub fn assert_budget_conservation(&self) -> bool {
        match self.allocated_budget.combine(&self.unallocated_budget) {
            Ok(total) => total == self.initial_budget,
            Err(_) => false,
        }
    }

    /// Admits a child SubIntent into the delegation tree.
    ///
    /// Checks:
    /// 1. Parent run identity matches.
    /// 2. Parent run holds `OperationClass::DelegateSubIntent`.
    /// 3. SubIntent deadline is contained within parent expiry.
    /// 4. Child run ID is unique (not already active).
    /// 5. Recursion depth does not exceed configured limit.
    /// 6. Active child count does not exceed fan-out limit.
    /// 7. Context duplication bytes do not exceed limit.
    /// 8. Aggregate budget conservation: child budget is split from `unallocated_budget`.
    /// 9. Ancestry verification: every capability chain verifies under `issuer_key`
    ///    with no missing or forged intermediate links.
    /// 10. Attenuation verification: selectors, caveats, quotas, and disclosure policies
    ///     only narrow, never amplify.
    ///
    /// # Errors
    ///
    /// [`SubIntentRefusal`] detailing the exact reason for refusal.
    pub fn admit_sub_intent(
        &mut self,
        sub_intent: &SubIntent,
        parent_run: &IntentRun,
        issuer_key: &[u8],
    ) -> Result<(), SubIntentRefusal> {
        if sub_intent.parent_run_id != parent_run.run_id() {
            return Err(SubIntentRefusal::ParentRunMismatch {
                expected: parent_run.run_id(),
                observed: sub_intent.parent_run_id,
            });
        }
        if !parent_run
            .allowed_operation_classes()
            .contains(OperationClass::DelegateSubIntent)
        {
            return Err(SubIntentRefusal::MissingDelegatePermission);
        }
        if sub_intent.deadline > parent_run.expiry() {
            return Err(SubIntentRefusal::DeadlineAmplified {
                requested: sub_intent.deadline,
                parent_expiry: parent_run.expiry(),
            });
        }
        if self.active_children.contains_key(&sub_intent.child_run_id) {
            return Err(SubIntentRefusal::DuplicateChildRunId {
                child_run_id: sub_intent.child_run_id,
            });
        }

        // Recursion depth bound
        if sub_intent.depth > self.limits.max_depth {
            return Err(SubIntentRefusal::RecursionDepthExceeded {
                observed: sub_intent.depth,
                limit: self.limits.max_depth,
            });
        }
        let expected_depth = self
            .depth
            .checked_add(1)
            .ok_or(SubIntentRefusal::RecursionDepthExceeded {
                observed: u16::MAX,
                limit: self.limits.max_depth,
            })?;
        if sub_intent.depth != expected_depth {
            return Err(SubIntentRefusal::DepthMismatch {
                expected: expected_depth,
                observed: sub_intent.depth,
            });
        }

        // Fan-out bound
        if self.active_children.len() >= self.limits.max_fan_out {
            return Err(SubIntentRefusal::FanOutLimitExceeded {
                observed: self.active_children.len() + 1,
                limit: self.limits.max_fan_out,
            });
        }

        // Context duplication bound
        let prospective_context = self
            .cumulative_context_bytes
            .saturating_add(sub_intent.context_bytes);
        if prospective_context > self.limits.max_context_duplication_bytes {
            return Err(SubIntentRefusal::ContextDuplicationExceeded {
                observed_bytes: prospective_context,
                limit_bytes: self.limits.max_context_duplication_bytes,
            });
        }

        // Aggregate budget conservation check: split from unallocated pool
        let (allocated, remaining) = self
            .unallocated_budget
            .split(&sub_intent.budget)
            .map_err(|deficit| SubIntentRefusal::AggregateBudgetExceeded {
                deficit,
                requested: sub_intent.budget,
                available: self.unallocated_budget,
            })?;

        // Full ancestry and capability attenuation verification
        for delegated in &sub_intent.attenuated_capabilities {
            if delegated.chain.len() < 2 {
                return Err(SubIntentRefusal::ChainRefused(
                    ChainRefused::MissingAncestry {
                        index: 0,
                        id: delegated.parent_capability_ref,
                    },
                ));
            }
            let leaf =
                verify_chain(&delegated.chain, issuer_key).map_err(SubIntentRefusal::ChainRefused)?;

            // Intermediate parent link binding check: link immediately preceding leaf
            // must match parent_capability_ref
            let parent_link_index = delegated.chain.len() - 2;
            let parent_link = &delegated.chain[parent_link_index];
            if parent_link.capability().id() != delegated.parent_capability_ref {
                return Err(SubIntentRefusal::ChainRefused(
                    ChainRefused::AncestryMismatch {
                        index: delegated.chain.len() - 1,
                        named: delegated.parent_capability_ref,
                        actual: parent_link.capability().id(),
                    },
                ));
            }

            // Quota check against leaf capability: leaf quota must dominate sub-intent budget
            // or the capability's own quota is exceeded
            if let Some(deficit) = leaf.quota().first_deficit(&sub_intent.budget) {
                return Err(SubIntentRefusal::QuotaAmplified { deficit });
            }

            // Selectors check: child selector must be an attenuation of parent selector
            for child_selector in &delegated.selectors {
                for parent_selector in &self.parent_selectors {
                    if !child_selector.is_attenuation_of(parent_selector) {
                        return Err(SubIntentRefusal::SelectorAmplified {
                            parent_selector: parent_selector.clone(),
                            child_selector: child_selector.clone(),
                        });
                    }
                }
            }
        }

        // Caveats check: child must retain ALL parent caveats (monotonicity)
        for parent_caveat in &self.parent_caveats {
            if !sub_intent.caveats.contains(parent_caveat) {
                return Err(SubIntentRefusal::CaveatDropped {
                    required_caveat: parent_caveat.clone(),
                });
            }
        }

        // Caveat enforcement: MaxContextBytes
        for caveat in &sub_intent.caveats {
            if let Caveat::MaxContextBytes(max_bytes) = caveat {
                if sub_intent.context_bytes > *max_bytes {
                    return Err(SubIntentRefusal::ContextDuplicationExceeded {
                        observed_bytes: sub_intent.context_bytes,
                        limit_bytes: *max_bytes,
                    });
                }
            }
        }

        // Disclosure policy attenuation check
        if !sub_intent
            .disclosure_policy
            .is_attenuation_of(self.parent_disclosure_policy)
        {
            return Err(SubIntentRefusal::DisclosurePolicyAmplified {
                requested: sub_intent.disclosure_policy,
                parent: self.parent_disclosure_policy,
            });
        }

        // Commit admission into active state
        self.unallocated_budget = remaining;
        self.allocated_budget = self
            .allocated_budget
            .combine(&allocated)
            .expect("allocated fits by algebra split");
        self.cumulative_context_bytes = prospective_context;
        self.active_children
            .insert(sub_intent.child_run_id, sub_intent.clone());

        debug_assert!(
            self.assert_budget_conservation(),
            "conservation invariant must hold after admission"
        );

        Ok(())
    }

    /// Releases a completed or cancelled child sub-intent, returning unspent budget
    /// to the parent's unallocated budget pool.
    ///
    /// # Errors
    ///
    /// Returns refusal if `child_run_id` is unknown, or if `unspent_budget`
    /// exceeds the child's originally allocated budget.
    pub fn release_sub_intent(
        &mut self,
        child_run_id: RunId,
        unspent_budget: ResourceVector,
    ) -> Result<(), SubIntentRefusal> {
        let child = self
            .active_children
            .remove(&child_run_id)
            .ok_or(SubIntentRefusal::ChildRunNotFound { child_run_id })?;

        if let Some(deficit) = child.budget.first_deficit(&unspent_budget) {
            self.active_children.insert(child_run_id, child);
            return Err(SubIntentRefusal::QuotaAmplified { deficit });
        }

        let (returned, remaining_alloc) = self
            .allocated_budget
            .split(&unspent_budget)
            .map_err(|deficit| {
                self.active_children.insert(child_run_id, child.clone());
                SubIntentRefusal::AggregateBudgetExceeded {
                    deficit,
                    requested: unspent_budget,
                    available: self.allocated_budget,
                }
            })?;

        self.allocated_budget = remaining_alloc;
        self.unallocated_budget = self
            .unallocated_budget
            .combine(&returned)
            .expect("conservation holds");
        self.cumulative_context_bytes = self
            .cumulative_context_bytes
            .saturating_sub(child.context_bytes);

        debug_assert!(
            self.assert_budget_conservation(),
            "conservation invariant must hold after release"
        );

        Ok(())
    }

    /// Spawns a descendant tracker for an active child sub-intent, establishing
    /// the next hierarchical delegation tier with incremented depth.
    pub fn spawn_child_tracker(
        &self,
        child_run_id: RunId,
        limits: DelegationLimits,
    ) -> Result<Self, SubIntentRefusal> {
        let child_depth = self
            .depth
            .checked_add(1)
            .ok_or(SubIntentRefusal::RecursionDepthExceeded {
                observed: u16::MAX,
                limit: limits.max_depth,
            })?;
        if child_depth > limits.max_depth {
            return Err(SubIntentRefusal::RecursionDepthExceeded {
                observed: child_depth,
                limit: limits.max_depth,
            });
        }

        let child = self
            .active_children
            .get(&child_run_id)
            .ok_or(SubIntentRefusal::ChildRunNotFound { child_run_id })?;

        let mut child_selectors = self.parent_selectors.clone();
        for cap in child.attenuated_capabilities() {
            child_selectors.extend(cap.selectors().iter().cloned());
        }
        let mut child_caveats = self.parent_caveats.clone();
        child_caveats.extend(child.caveats().iter().cloned());

        Ok(Self {
            parent_run_id: child_run_id,
            initial_budget: child.budget(),
            allocated_budget: ResourceVector::ZERO,
            unallocated_budget: child.budget(),
            active_children: BTreeMap::new(),
            cumulative_context_bytes: 0,
            depth: child_depth,
            limits,
            parent_caveats: child_caveats,
            parent_selectors: child_selectors,
            parent_disclosure_policy: child.disclosure_policy(),
        })
    }
}

/// Standalone verifier checking the complete capability ancestry and attenuation
/// of a SubIntent against a parent run and cryptographic issuer key.
///
/// # Errors
///
/// Refuses amplification, broken or forged ancestry, missing delegate permissions,
/// or window/deadline violations.
pub fn verify_sub_intent_ancestry(
    sub_intent: &SubIntent,
    parent_run: &IntentRun,
    issuer_key: &[u8],
) -> Result<(), SubIntentRefusal> {
    if sub_intent.parent_run_id != parent_run.run_id() {
        return Err(SubIntentRefusal::ParentRunMismatch {
            expected: parent_run.run_id(),
            observed: sub_intent.parent_run_id,
        });
    }
    if !parent_run
        .allowed_operation_classes()
        .contains(OperationClass::DelegateSubIntent)
    {
        return Err(SubIntentRefusal::MissingDelegatePermission);
    }
    if sub_intent.deadline > parent_run.expiry() {
        return Err(SubIntentRefusal::DeadlineAmplified {
            requested: sub_intent.deadline,
            parent_expiry: parent_run.expiry(),
        });
    }
    if sub_intent.attenuated_capabilities.is_empty() {
        return Err(SubIntentRefusal::EmptyCapabilities);
    }

    for delegated in &sub_intent.attenuated_capabilities {
        if delegated.chain.len() < 2 {
            return Err(SubIntentRefusal::ChainRefused(
                ChainRefused::MissingAncestry {
                    index: 0,
                    id: delegated.parent_capability_ref,
                },
            ));
        }
        let leaf =
            verify_chain(&delegated.chain, issuer_key).map_err(SubIntentRefusal::ChainRefused)?;

        let parent_link = &delegated.chain[delegated.chain.len() - 2];
        if parent_link.capability().id() != delegated.parent_capability_ref {
            return Err(SubIntentRefusal::ChainRefused(
                ChainRefused::AncestryMismatch {
                    index: delegated.chain.len() - 1,
                    named: delegated.parent_capability_ref,
                    actual: parent_link.capability().id(),
                },
            ));
        }

        if let Some(deficit) = leaf.quota().first_deficit(&sub_intent.budget) {
            return Err(SubIntentRefusal::QuotaAmplified { deficit });
        }
    }

    Ok(())
}

/// Reasons why a SubIntent issuance, delegation, or verification is refused.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SubIntentRefusal {
    /// Parent run lacks the DelegateSubIntent permission class.
    MissingDelegatePermission,
    /// SubIntent deadline extends past parent run expiry.
    DeadlineAmplified {
        /// Requested sub-intent deadline.
        requested: LogicalTime,
        /// Parent expiry.
        parent_expiry: LogicalTime,
    },
    /// SubIntent specifies no capabilities.
    EmptyCapabilities,
    /// Exceeded maximum capability count.
    TooManyCapabilities {
        /// Observed count.
        observed: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Exceeded maximum caveats count.
    TooManyCaveats {
        /// Observed count.
        observed: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Exceeded maximum additional identities.
    TooManyIdentities {
        /// Observed count.
        observed: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Exceeded maximum input commitments.
    TooManyInputCommitments {
        /// Observed count.
        observed: usize,
        /// Configured limit.
        limit: usize,
    },
    /// Recursion depth limit exceeded.
    RecursionDepthExceeded {
        /// Observed depth.
        observed: u16,
        /// Limit.
        limit: u16,
    },
    /// SubIntent depth does not match tracker depth + 1.
    DepthMismatch {
        /// Expected depth.
        expected: u16,
        /// Observed depth.
        observed: u16,
    },
    /// Fan-out limit exceeded for this parent run.
    FanOutLimitExceeded {
        /// Prospective active child count.
        observed: usize,
        /// Maximum allowed.
        limit: usize,
    },
    /// Aggregate budget exceeded: child requests more budget than parent has unallocated.
    AggregateBudgetExceeded {
        /// Exact deficit error.
        deficit: ResourceError,
        /// Requested amount.
        requested: ResourceVector,
        /// Currently available unallocated budget.
        available: ResourceVector,
    },
    /// Cumulative context duplication bytes exceeded limit.
    ContextDuplicationExceeded {
        /// Observed cumulative bytes.
        observed_bytes: u64,
        /// Limit bytes.
        limit_bytes: u64,
    },
    /// Selector amplified: child selector is broader than or incompatible with parent.
    SelectorAmplified {
        /// Parent selector.
        parent_selector: Selector,
        /// Child selector that amplified scope.
        child_selector: Selector,
    },
    /// Quota amplified: requested budget exceeds capability quota.
    QuotaAmplified {
        /// Deficit error.
        deficit: ResourceError,
    },
    /// Operations amplified: child requested operations parent does not hold.
    OperationsAmplified {
        /// Classes added.
        added: ClassSet,
        /// Parent classes.
        parent: ClassSet,
    },
    /// Disclosure policy was widened.
    DisclosurePolicyAmplified {
        /// Requested disclosure policy.
        requested: DisclosurePolicy,
        /// Parent disclosure policy.
        parent: DisclosurePolicy,
    },
    /// Child dropped a caveat required by its parent.
    CaveatDropped {
        /// Dropped caveat.
        required_caveat: Caveat,
    },
    /// Capability chain ancestry check failed.
    ChainRefused(ChainRefused),
    /// Child run ID is identical to parent run ID.
    SelfDelegationNotAllowed {
        /// Run ID.
        run_id: RunId,
    },
    /// Duplicate child run ID.
    DuplicateChildRunId {
        /// Child run ID.
        child_run_id: RunId,
    },
    /// Parent run ID mismatch.
    ParentRunMismatch {
        /// Expected parent run ID.
        expected: RunId,
        /// Observed parent run ID.
        observed: RunId,
    },
    /// Child run not found in active children map.
    ChildRunNotFound {
        /// Child run ID.
        child_run_id: RunId,
    },
    /// Canonical commitment encoding failure.
    CanonicalCommitmentFailure(CodecRefusal),
}

impl SubIntentRefusal {
    /// Returns true if this refusal is due to an authority amplification attempt.
    #[must_use]
    pub fn is_amplification(&self) -> bool {
        match self {
            Self::SelectorAmplified { .. }
            | Self::DeadlineAmplified { .. }
            | Self::QuotaAmplified { .. }
            | Self::OperationsAmplified { .. }
            | Self::DisclosurePolicyAmplified { .. }
            | Self::ChainRefused(
                ChainRefused::OperationsAmplified { .. }
                | ChainRefused::QuotaAmplified { .. }
                | ChainRefused::WindowWidened { .. },
            ) => true,
            _ => false,
        }
    }

    /// Returns true if this refusal is due to broken, missing, or forged capability ancestry.
    #[must_use]
    pub fn is_ancestry_failure(&self) -> bool {
        match self {
            Self::ChainRefused(
                ChainRefused::MissingAncestry { .. }
                | ChainRefused::AuthenticatorMismatch { .. }
                | ChainRefused::AncestryMismatch { .. }
                | ChainRefused::ParentTagMismatch { .. }
                | ChainRefused::ParentTagMissing { .. }
                | ChainRefused::EmptyChain
                | ChainRefused::RootCarriesParentTag,
            )
            | Self::EmptyCapabilities
            | Self::ParentRunMismatch { .. } => true,
            _ => false,
        }
    }
}

impl fmt::Display for SubIntentRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDelegatePermission => {
                formatter.write_str("parent run lacks the DelegateSubIntent permission class")
            }
            Self::DeadlineAmplified {
                requested,
                parent_expiry,
            } => write!(
                formatter,
                "sub-intent deadline {requested} extends past parent expiry {parent_expiry}"
            ),
            Self::EmptyCapabilities => {
                formatter.write_str("a sub-intent must delegate at least one capability")
            }
            Self::TooManyCapabilities { observed, limit } => write!(
                formatter,
                "sub-intent delegates {observed} capabilities; limit is {limit}"
            ),
            Self::TooManyCaveats { observed, limit } => write!(
                formatter,
                "sub-intent carries {observed} caveats; limit is {limit}"
            ),
            Self::TooManyIdentities { observed, limit } => write!(
                formatter,
                "sub-intent binds {observed} identities; limit is {limit}"
            ),
            Self::TooManyInputCommitments { observed, limit } => write!(
                formatter,
                "sub-intent carries {observed} input commitments; limit is {limit}"
            ),
            Self::RecursionDepthExceeded { observed, limit } => write!(
                formatter,
                "delegation recursion depth {observed} exceeds limit {limit}"
            ),
            Self::DepthMismatch { expected, observed } => write!(
                formatter,
                "sub-intent depth {observed} does not match expected depth {expected}"
            ),
            Self::FanOutLimitExceeded { observed, limit } => write!(
                formatter,
                "delegation fan-out {observed} exceeds limit {limit}"
            ),
            Self::AggregateBudgetExceeded {
                deficit,
                requested,
                available,
            } => write!(
                formatter,
                "aggregate budget exceeded: deficit {deficit}; requested {requested}, available {available}"
            ),
            Self::ContextDuplicationExceeded {
                observed_bytes,
                limit_bytes,
            } => write!(
                formatter,
                "context duplication {observed_bytes} bytes exceeds limit {limit_bytes} bytes"
            ),
            Self::SelectorAmplified {
                parent_selector,
                child_selector,
            } => write!(
                formatter,
                "selector amplification: child selector {child_selector:?} does not narrow parent {parent_selector:?}"
            ),
            Self::QuotaAmplified { deficit } => {
                write!(formatter, "quota amplification: {deficit}")
            }
            Self::OperationsAmplified { added, parent } => write!(
                formatter,
                "operations amplified: adds {added} to parent holding {parent}"
            ),
            Self::DisclosurePolicyAmplified { requested, parent } => write!(
                formatter,
                "disclosure policy amplified: requested {requested:?} is broader than parent {parent:?}"
            ),
            Self::CaveatDropped { required_caveat } => write!(
                formatter,
                "child dropped required parent caveat: {required_caveat:?}"
            ),
            Self::ChainRefused(chain_refusal) => {
                write!(formatter, "ancestry chain refused: {chain_refusal}")
            }
            Self::SelfDelegationNotAllowed { run_id } => write!(
                formatter,
                "self-delegation is forbidden: child run {run_id} equals parent"
            ),
            Self::DuplicateChildRunId { child_run_id } => write!(
                formatter,
                "duplicate child run {child_run_id} is already active"
            ),
            Self::ParentRunMismatch { expected, observed } => write!(
                formatter,
                "parent run mismatch: expected {expected}, observed {observed}"
            ),
            Self::ChildRunNotFound { child_run_id } => {
                write!(formatter, "child run {child_run_id} not found in active children")
            }
            Self::CanonicalCommitmentFailure(refusal) => {
                write!(formatter, "sub-intent canonical commitment failure: {refusal}")
            }
        }
    }
}

impl core::error::Error for SubIntentRefusal {}

fn subintent_commitment(params: &SubIntentParams) -> Result<[u8; 32], CodecRefusal> {
    let mut encoder = Encoder::with_capacity(1024);
    encoder.write_raw(SUBINTENT_DOMAIN);
    encoder.write_raw(&params.child_run_id.value().to_be_bytes());
    encoder.write_raw(&params.parent_run_id.value().to_be_bytes());
    encoder.write_raw(&params.objective_digest);
    encoder.write_scalar(params.input_commitments.len() as u64);
    for commitment in &params.input_commitments {
        encoder.write_raw(commitment);
    }
    encoder.write_raw(&params.output_schema_id);
    encoder.write_scalar(params.attenuated_capabilities.len() as u64);
    for cap in &params.attenuated_capabilities {
        encoder.write_raw(&cap.parent_capability_ref.value().to_be_bytes());
        encoder.write_scalar(cap.chain.len() as u64);
        for link in &cap.chain {
            encoder.write_raw(link.tag());
            encoder.write_raw(&link.capability().id().value().to_be_bytes());
        }
    }
    for (_grade, amount) in params.budget.pairs() {
        encoder.write_scalar(amount);
    }
    encoder.write_scalar(params.deadline.value());
    encoder.write_scalar(params.required_evidence.len() as u64);
    for ev in &params.required_evidence {
        encoder.write_raw_byte(*ev as u8);
    }
    encoder.write_raw_byte(params.disclosure_policy as u8);
    encoder.write_scalar(params.additional_identities.len() as u64);
    for id in &params.additional_identities {
        encoder.write_raw(&id.value().to_be_bytes());
    }
    encoder.write_scalar(u64::from(params.depth));
    encoder.write_scalar(params.context_bytes);

    let bytes = encoder.into_bytes();
    let mut hasher = <Sha256 as GitHashAlgorithm>::Hasher::new();
    hasher.update(&bytes);
    Ok(hasher.finish())
}

fn write_hex(formatter: &mut fmt::Formatter<'_>, bytes: &[u8; 32]) -> fmt::Result {
    for byte in bytes {
        write!(formatter, "{byte:02x}")?;
    }
    Ok(())
}
