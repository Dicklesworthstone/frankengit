//! Repository-owned exact-branch review requirements. This is canonical forge
//! metadata, not a node-local configuration file or caller-selected merge option.
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PolicyEpoch, PrincipalId, RefName, RefusalCode};
use crate::{AggregateId, AggregateVersion, ExpectedVersion, ForgeEvent, ForgeEventPayload};
use super::invalid_native;

pub const MAX_PROTECTION_ADMINISTRATORS: usize = 32;
pub const MAX_PROTECTED_BRANCHES: usize = 128;
pub const MAX_BRANCH_REVIEWERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchReviewRule {
    pub target: RefName,
    pub reviewers: Vec<PrincipalId>,
}

/// Complete replacement, never an implicit merge with mutable latest state.
/// An empty rule list disables branch requirements but retains administration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepositoryProtectionPolicy {
    pub administrators: Vec<PrincipalId>,
    pub branches: Vec<BranchReviewRule>,
}
impl RepositoryProtectionPolicy {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        validate_principals(&self.administrators, MAX_PROTECTION_ADMINISTRATORS)?;
        if self.branches.len() > MAX_PROTECTED_BRANCHES
            || self.branches.windows(2).any(|pair| pair[0].target >= pair[1].target)
        { return Err(invalid_native("protection.branches")); }
        for rule in &self.branches {
            if !rule.target.as_bytes().starts_with(b"refs/heads/") {
                return Err(invalid_native("protection.branch_namespace"));
            }
            validate_principals(&rule.reviewers, MAX_BRANCH_REVIEWERS)?;
        }
        Ok(())
    }
    pub fn reviewers(&self, target: &RefName) -> Option<&[PrincipalId]> {
        self.branches.binary_search_by(|rule| rule.target.cmp(target)).ok()
            .map(|index| self.branches[index].reviewers.as_slice())
    }
    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        write_principals(out, &self.administrators)?;
        out.write_sequence("protection.branches", &self.branches, |out, rule| {
            out.write_ref_name(&rule.target)?;
            write_principals(out, &rule.reviewers)
        })
    }
    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let administrators = read_principals(input, MAX_PROTECTION_ADMINISTRATORS)?;
        let mut count = 0;
        let branches = input.read_sequence("protection.branches", |input| {
            count += 1;
            if count > MAX_PROTECTED_BRANCHES { return Err(invalid_native("protection.branches")); }
            Ok(BranchReviewRule { target: input.read_ref_name()?,
                reviewers: read_principals(input, MAX_BRANCH_REVIEWERS)? })
        })?;
        let policy = Self { administrators, branches };
        policy.validate()?;
        Ok(policy)
    }
}
fn validate_principals(values: &[PrincipalId], limit: usize) -> Result<(), CodecRefusal> {
    if values.is_empty() || values.len() > limit
        || values.windows(2).any(|pair| pair[0] >= pair[1])
    { return Err(invalid_native("protection.principals")); }
    Ok(())
}
fn write_principals(out: &mut Encoder, values: &[PrincipalId]) -> Result<(), CodecRefusal> {
    out.write_sequence("protection.principals", values, |out, principal| {
        out.write_opaque_id(principal.as_bytes()); Ok(())
    })
}
fn read_principals(input: &mut Decoder<'_>, limit: usize) -> Result<Vec<PrincipalId>, CodecRefusal> {
    let mut count = 0;
    let values = input.read_sequence("protection.principals", |input| {
        count += 1;
        if count > limit { return Err(invalid_native("protection.principals")); }
        Ok(PrincipalId::from_bytes(input.read_opaque_id("protection.principal")?))
    })?;
    validate_principals(&values, limit)?;
    Ok(values)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProtectionEvent {
    pub actor: PrincipalId,
    /// Expected predecessor epoch, not the epoch after this activation.
    pub expected_policy_epoch: PolicyEpoch,
    pub policy: RepositoryProtectionPolicy,
}
impl NativeProtectionEvent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        self.policy.validate()?;
        self.activated_epoch().map_err(|_| invalid_native("protection.epoch_exhausted"))?;
        Ok(())
    }
    pub fn activated_epoch(&self) -> Result<PolicyEpoch, RefusalCode> {
        self.expected_policy_epoch.next().map_err(|_| RefusalCode::ResourceBudgetExceeded)
    }
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.actor.as_bytes());
        out.write_scalar(self.expected_policy_epoch.get());
        self.policy.write(out)
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let value = Self {
            actor: PrincipalId::from_bytes(input.read_opaque_id("protection.actor")?),
            expected_policy_epoch: PolicyEpoch::try_new(input.read_scalar("protection.epoch")?)
                .map_err(|_| invalid_native("protection.epoch"))?,
            policy: RepositoryProtectionPolicy::read(input)?,
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionCommand {
    pub expected_version: ExpectedVersion,
    pub expected_policy_epoch: PolicyEpoch,
    pub policy: RepositoryProtectionPolicy,
}
impl ProtectionCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        let change = NativeProtectionEvent { actor, expected_policy_epoch: self.expected_policy_epoch,
            policy: self.policy.clone() };
        change.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version.next().map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent { aggregate: AggregateId::RepositoryProtection, version,
            payload: ForgeEventPayload::RepositoryProtectionChangedNative(change) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_codec::{DecodeLimits, decode_body, encode_body};
    fn policy() -> RepositoryProtectionPolicy {
        RepositoryProtectionPolicy { administrators: vec![PrincipalId::from_bytes([1;16])],
            branches: vec![BranchReviewRule { target: RefName::try_new(b"refs/heads/main").unwrap(),
                reviewers: vec![PrincipalId::from_bytes([2;16])] }] }
    }
    #[test]
    fn exact_admin_rule_epoch_and_version_semantics_are_canonically_bound() {
        let command = ProtectionCommand { expected_version: ExpectedVersion::NewStream,
            expected_policy_epoch: PolicyEpoch::FIRST, policy: policy() };
        let event = command.proposed_event(PrincipalId::from_bytes([1;16])).unwrap();
        let encoded = encode_body(&event).unwrap();
        assert_eq!(decode_body::<ForgeEvent>(&encoded, DecodeLimits::DEFAULT).unwrap(), event);
        for end in 0..encoded.len() {
            assert!(decode_body::<ForgeEvent>(&encoded[..end], DecodeLimits::DEFAULT).is_err());
        }
        for field in 0..5 {
            let mut other = command.clone();
            match field {
                0 => other.policy.administrators[0] = PrincipalId::from_bytes([3;16]),
                1 => other.policy.branches[0].reviewers[0] = PrincipalId::from_bytes([3;16]),
                2 => other.policy.branches.clear(),
                3 => other.expected_policy_epoch = PolicyEpoch::try_new(2).unwrap(),
                _ => other.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST),
            }
            assert_ne!(encode_body(&other.proposed_event(PrincipalId::from_bytes([1;16])).unwrap()).unwrap(), encoded);
        }
        let mut wrong = event;
        wrong.aggregate = AggregateId::Issue(crate::IssueNumber::FIRST);
        assert!(encode_body(&wrong).is_err());
    }
    #[test]
    fn duplicate_unsorted_empty_and_non_branch_requirements_refuse() {
        for field in 0..6 {
            let mut value = policy();
            match field {
                0 => value.administrators.clear(),
                1 => value.administrators.push(value.administrators[0]),
                2 => value.branches[0].reviewers.clear(),
                3 => { let duplicate = value.branches[0].reviewers[0]; value.branches[0].reviewers.push(duplicate); },
                4 => value.branches.push(value.branches[0].clone()),
                _ => value.branches[0].target = RefName::try_new(b"refs/tags/release").unwrap(),
            }
            assert!(value.validate().is_err(), "field {field}");
        }
        let mut empty = policy(); empty.branches.clear(); empty.validate().unwrap();
        assert!(empty.reviewers(&RefName::try_new(b"refs/heads/main").unwrap()).is_none());
    }
}
