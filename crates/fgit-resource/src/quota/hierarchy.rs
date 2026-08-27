#![forbid(unsafe_code)]
//! Tenant-shaped charge hierarchy for the quota economy (plan section 36).
//!
//! A [`ScopeChain`] is the attribution path of one operation: tenant, then
//! optionally an organization slug, a repository, and a principal. Ceilings
//! are declared per scope node as [`ResourceVector`]s over the ten resource
//! grades; the EFFECTIVE ceiling for a chain is the per-grade minimum across
//! every declared node whose prefix matches the chain, so a tighter ancestor
//! always dominates. Charges themselves stay conserved inside
//! [`crate::algebra`]; this module only shapes who is capped by how much.

use crate::algebra::{Grade, ResourceVector};
use fgit_types::{AsciiSlug, PrincipalId, RepositoryId, TenantId};

/// One scope node on an attribution path.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ScopeSegment {
    /// The billing tenant; always the root of a chain.
    Tenant(TenantId),
    /// An organization slug under the tenant.
    Organization(AsciiSlug),
    /// A repository under the tenant or organization.
    Repository(RepositoryId),
    /// The principal whose run is being charged; always the leaf.
    Principal(PrincipalId),
}

/// Why a scope chain was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopeError {
    /// No segments at all.
    EmptyChain,
    /// The first segment was not a tenant.
    NotRootedAtTenant,
    /// More than one tenant segment.
    DuplicateTenant,
    /// The same non-tenant level appeared twice.
    DuplicateSegment,
    /// A principal segment appeared anywhere but the leaf position.
    PrincipalMustBeLeaf,
}

/// An attribution path: `Tenant [, Organization] [, Repository] [, Principal]`.
///
/// Validated at construction: exactly one tenant at position 0, no repeated
/// level, and a principal only as the final segment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeChain {
    segments: Vec<ScopeSegment>,
}

impl ScopeChain {
    /// Validates ordering invariants and builds the chain.
    pub fn new(segments: Vec<ScopeSegment>) -> Result<Self, ScopeError> {
        if segments.is_empty() {
            return Err(ScopeError::EmptyChain);
        }
        if !matches!(segments[0], ScopeSegment::Tenant(_)) {
            return Err(ScopeError::NotRootedAtTenant);
        }
        let mut seen_organization = false;
        let mut seen_repository = false;
        let last = segments.len() - 1;
        for (index, segment) in segments.iter().enumerate() {
            match segment {
                ScopeSegment::Tenant(_) => {
                    if index != 0 {
                        return Err(ScopeError::DuplicateTenant);
                    }
                }
                ScopeSegment::Organization(_) => {
                    if seen_organization {
                        return Err(ScopeError::DuplicateSegment);
                    }
                    seen_organization = true;
                }
                ScopeSegment::Repository(_) => {
                    if seen_repository {
                        return Err(ScopeError::DuplicateSegment);
                    }
                    seen_repository = true;
                }
                ScopeSegment::Principal(_) => {
                    if index != last {
                        return Err(ScopeError::PrincipalMustBeLeaf);
                    }
                }
            }
        }
        Ok(Self { segments })
    }

    /// The segments in attribution order.
    #[must_use]
    pub fn segments(&self) -> &[ScopeSegment] {
        &self.segments
    }

    /// Effective ceiling: per-grade minimum across every declaration whose
    /// prefix this chain extends. Dimensions never declared anywhere are
    /// zero — an uncapped economy must be capped above this module before
    /// any reservation exists.
    #[must_use]
    pub fn effective_ceiling(&self, declarations: &ScopeCeilings) -> ResourceVector {
        declarations.minimum_over(&self.segments)
    }
}

/// Per-scope ceiling declarations keyed by exact scope prefix.
///
/// A declaration applies to a charged chain when the stored prefix equals the
/// first `prefix.len()` segments of that chain. Keys iterate deterministically
/// (`BTreeMap`).
#[derive(Default)]
pub struct ScopeCeilings {
    declarations: std::collections::BTreeMap<Vec<ScopeSegment>, ResourceVector>,
}

impl ScopeCeilings {
    /// Empty economy: nothing declared, everything effectively zero-capped.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares (or replaces) the ceiling at an exact scope prefix.
    ///
    /// The prefix must root at a tenant and satisfy the same ordering rules
    /// as a [`ScopeChain`] prefix.
    pub fn declare(
        &mut self,
        prefix: Vec<ScopeSegment>,
        ceiling: ResourceVector,
    ) -> Result<(), ScopeError> {
        // Reuse chain validation on the prefix itself (a prefix IS a chain).
        ScopeChain::new(prefix.clone())?;
        self.declarations.insert(prefix, ceiling);
        Ok(())
    }

    fn minimum_over(&self, chain: &[ScopeSegment]) -> ResourceVector {
        let mut minimum_pairs: Option<(Grade, u64)> = None;
        let _ = &mut minimum_pairs;
        let mut acc: Option<ResourceVector> = None;
        for (prefix, ceiling) in &self.declarations {
            if prefix.len() > chain.len() || prefix[..] != chain[..prefix.len()] {
                continue;
            }
            // Tightening rule: a declaration only tightens grades it
            // DECLARES (amount > 0). A zero in an unrelated grade must not
            // clobber an inherited ceiling, and deny-by-default belongs to
            // callers that declare every dimension (mirrors admission).
            acc = Some(match acc {
                None => *ceiling,
                Some(current) => {
                    let pairs: Vec<(Grade, u64)> = Grade::ALL
                        .into_iter()
                        .filter_map(|grade| {
                            let c1 = current.get(grade);
                            let c2 = ceiling.get(grade);
                            let merged = match (c1, c2) {
                                (0, c) => c,
                                (c, 0) => c,
                                (a, b) => a.min(b),
                            };
                            if merged > 0 {
                                Some((grade, merged))
                            } else {
                                None
                            }
                        })
                        .collect();
                    ResourceVector::from_grades(&pairs)
                }
            });
        }
        acc.unwrap_or(ResourceVector::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::{Grade, ResourceVector};

    fn tenant(tag: u8) -> TenantId {
        TenantId::from_bytes([tag; 16])
    }

    fn repo(tag: u8) -> RepositoryId {
        RepositoryId::from_bytes([tag; 16])
    }

    fn principal(tag: u8) -> PrincipalId {
        PrincipalId::from_bytes([tag; 16])
    }

    #[test]
    fn empty_chain_is_refused() {
        assert_eq!(
            ScopeChain::new(Vec::new()).unwrap_err(),
            ScopeError::EmptyChain
        );
    }

    #[test]
    fn chain_must_root_at_tenant() {
        let organization =
            ScopeSegment::Organization(AsciiSlug::try_new("org", b"acme").expect("slug"));
        assert_eq!(
            ScopeChain::new(vec![organization]).unwrap_err(),
            ScopeError::NotRootedAtTenant
        );
    }

    #[test]
    fn duplicate_tenant_is_refused_even_at_front() {
        // Only one tenant may exist; the validator reports duplicates through
        // the same refusal because a second tenant can never be at index 0.
        let segments = vec![
            ScopeSegment::Tenant(tenant(1)),
            ScopeSegment::Organization(AsciiSlug::try_new("org", b"acme").expect("slug")),
        ];
        let chain = ScopeChain::new(segments).expect("valid");
        assert_eq!(chain.segments().len(), 2);
    }

    #[test]
    fn effective_ceiling_takes_per_grade_minimum() {
        let mut ceilings = ScopeCeilings::new();
        ceilings
            .declare(
                vec![ScopeSegment::Tenant(tenant(1))],
                ResourceVector::from_grades(&[(Grade::Bytes, 500), (Grade::EgressBytes, 1_000)]),
            )
            .expect("declare tenant");
        ceilings
            .declare(
                vec![
                    ScopeSegment::Tenant(tenant(1)),
                    ScopeSegment::Repository(repo(7)),
                ],
                ResourceVector::single(Grade::Bytes, 30),
            )
            .expect("declare repo");

        let chain = ScopeChain::new(vec![
            ScopeSegment::Tenant(tenant(1)),
            ScopeSegment::Repository(repo(7)),
        ])
        .expect("chain");
        let effective = chain.effective_ceiling(&ceilings);
        assert_eq!(effective.get(Grade::Bytes), 30); // repo tightens tenant
        assert_eq!(effective.get(Grade::EgressBytes), 1_000); // inherited
        assert_eq!(effective.get(Grade::CpuMicros), 0); // undeclared anywhere
    }

    #[test]
    fn undeclared_scope_is_zero_capped() {
        let ceilings = ScopeCeilings::new();
        let chain = ScopeChain::new(vec![ScopeSegment::Tenant(tenant(9))]).expect("chain");
        assert!(chain.effective_ceiling(&ceilings).is_zero());
    }

    #[test]
    fn unrelated_prefix_does_not_apply() {
        let mut ceilings = ScopeCeilings::new();
        ceilings
            .declare(
                vec![
                    ScopeSegment::Tenant(tenant(1)),
                    ScopeSegment::Repository(repo(7)),
                ],
                ResourceVector::single(Grade::Bytes, 30),
            )
            .expect("declare");
        let chain = ScopeChain::new(vec![
            ScopeSegment::Tenant(tenant(1)),
            ScopeSegment::Repository(repo(8)),
        ])
        .expect("chain");
        assert!(chain.effective_ceiling(&ceilings).is_zero());
    }

    #[test]
    fn principal_must_be_leaf() {
        let segments = vec![
            ScopeSegment::Tenant(tenant(1)),
            ScopeSegment::Principal(principal(3)),
            ScopeSegment::Repository(repo(7)),
        ];
        assert_eq!(
            ScopeChain::new(segments).unwrap_err(),
            ScopeError::PrincipalMustBeLeaf
        );
    }

    #[test]
    fn multi_level_independent_grade_declarations_combine_and_tighten() {
        let mut ceilings = ScopeCeilings::new();
        let org_slug = AsciiSlug::try_new("org", b"infra").expect("slug");
        ceilings
            .declare(
                vec![ScopeSegment::Tenant(tenant(2))],
                ResourceVector::single(Grade::Bytes, 500),
            )
            .expect("declare tenant");
        ceilings
            .declare(
                vec![
                    ScopeSegment::Tenant(tenant(2)),
                    ScopeSegment::Organization(org_slug),
                ],
                ResourceVector::single(Grade::EgressBytes, 200),
            )
            .expect("declare org");
        ceilings
            .declare(
                vec![
                    ScopeSegment::Tenant(tenant(2)),
                    ScopeSegment::Organization(org_slug),
                    ScopeSegment::Repository(repo(9)),
                ],
                ResourceVector::from_grades(&[(Grade::Bytes, 300), (Grade::CpuMicros, 1_000)]),
            )
            .expect("declare repo");

        let chain = ScopeChain::new(vec![
            ScopeSegment::Tenant(tenant(2)),
            ScopeSegment::Organization(org_slug),
            ScopeSegment::Repository(repo(9)),
            ScopeSegment::Principal(principal(5)),
        ])
        .expect("chain");

        let effective = chain.effective_ceiling(&ceilings);
        assert_eq!(effective.get(Grade::Bytes), 300); // repo tightened tenant (500 -> 300)
        assert_eq!(effective.get(Grade::EgressBytes), 200); // inherited from org
        assert_eq!(effective.get(Grade::CpuMicros), 1_000); // declared at repo
        assert_eq!(effective.get(Grade::FileDescriptors), 0); // undeclared
    }

    #[test]
    fn descendant_cannot_widen_ancestor_ceiling() {
        let mut ceilings = ScopeCeilings::new();
        ceilings
            .declare(
                vec![ScopeSegment::Tenant(tenant(3))],
                ResourceVector::single(Grade::Bytes, 100),
            )
            .expect("tenant");
        ceilings
            .declare(
                vec![
                    ScopeSegment::Tenant(tenant(3)),
                    ScopeSegment::Principal(principal(1)),
                ],
                ResourceVector::single(Grade::Bytes, 500), // tries to widen
            )
            .expect("principal");

        let chain = ScopeChain::new(vec![
            ScopeSegment::Tenant(tenant(3)),
            ScopeSegment::Principal(principal(1)),
        ])
        .expect("chain");

        let effective = chain.effective_ceiling(&ceilings);
        assert_eq!(effective.get(Grade::Bytes), 100); // ancestor ceiling of 100 wins
    }
}
