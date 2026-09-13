//! Canonical, repository-scoped required-review policy. This profile does not
//! infer roles, signatures, checks, or approvals from caller-supplied booleans.
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PolicyEpoch, PrincipalId, RefName, RefusalCode};

pub const MAX_PROTECTED_BRANCHES: usize = 64;
pub const MAX_POLICY_ADMINISTRATORS: usize = 32;
pub const MAX_BRANCH_REVIEWERS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedBranch {
    pub name: RefName,
    /// Every listed principal must approve the exact candidate. The original
    /// PR opener and merge submitter cannot satisfy these requirements.
    pub reviewers: Vec<PrincipalId>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewProtection {
    /// Existing administrators authorize the NEXT replacement, not its authors.
    pub administrators: Vec<PrincipalId>,
    /// Empty disables protection without erasing policy ownership/history.
    pub branches: Vec<ProtectedBranch>,
}
fn principals(values: &[PrincipalId], maximum: usize) -> Result<(), CodecRefusal> {
    if values.is_empty() || values.len() > maximum || values.windows(2).any(|p| p[0] >= p[1]) {
        return Err(invalid_native("review_protection.principals"));
    }
    Ok(())
}
impl ReviewProtection {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        principals(&self.administrators, MAX_POLICY_ADMINISTRATORS)?;
        if self.branches.len() > MAX_PROTECTED_BRANCHES
            || self.branches.windows(2).any(|p| p[0].name >= p[1].name)
        {
            return Err(invalid_native("review_protection.branches"));
        }
        for branch in &self.branches {
            if !branch.name.as_bytes().starts_with(b"refs/heads/") {
                return Err(invalid_native("review_protection.branch_namespace"));
            }
            principals(&branch.reviewers, MAX_BRANCH_REVIEWERS)?;
        }
        Ok(())
    }
    pub fn branch(&self, name: &RefName) -> Option<&ProtectedBranch> {
        self.branches
            .binary_search_by(|rule| rule.name.cmp(name))
            .ok()
            .map(|i| &self.branches[i])
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeProtectionEvent {
    pub actor: PrincipalId,
    /// Policy evaluation always uses this predecessor epoch. Successful
    /// publication advances it exactly once, invalidating earlier approvals.
    pub expected_epoch: PolicyEpoch,
    pub protection: ReviewProtection,
}
impl NativeProtectionEvent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        self.protection.validate()?;
        self.expected_epoch
            .next()
            .map_err(|_| invalid_native("review_protection.epoch"))?;
        Ok(())
    }
    pub fn resulting_epoch(&self) -> Result<PolicyEpoch, RefusalCode> {
        self.expected_epoch
            .next()
            .map_err(|_| RefusalCode::ResourceBudgetExceeded)
    }
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.actor.as_bytes());
        out.write_scalar(self.expected_epoch.get());
        out.write_scalar(self.protection.administrators.len() as u32);
        for id in &self.protection.administrators {
            out.write_opaque_id(id.as_bytes());
        }
        out.write_scalar(self.protection.branches.len() as u32);
        for branch in &self.protection.branches {
            out.write_ref_name(&branch.name)?;
            out.write_scalar(branch.reviewers.len() as u32);
            for id in &branch.reviewers {
                out.write_opaque_id(id.as_bytes());
            }
        }
        Ok(())
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        fn count(
            input: &mut Decoder<'_>,
            field: &'static str,
            maximum: usize,
        ) -> Result<usize, CodecRefusal> {
            let value = input.read_scalar::<u32>(field)? as usize;
            if value > maximum {
                return Err(invalid_native(field));
            }
            Ok(value)
        }
        fn people(
            input: &mut Decoder<'_>,
            maximum: usize,
        ) -> Result<Vec<PrincipalId>, CodecRefusal> {
            let n = count(input, "review_protection.principals", maximum)?;
            let mut ids = Vec::new();
            for _ in 0..n {
                ids.push(PrincipalId::from_bytes(
                    input.read_opaque_id("review_protection.principal")?,
                ));
            }
            principals(&ids, maximum)?;
            Ok(ids)
        }
        let actor = PrincipalId::from_bytes(input.read_opaque_id("review_protection.actor")?);
        let expected_epoch =
            PolicyEpoch::try_new(input.read_scalar::<u64>("review_protection.epoch")?)?;
        let administrators = people(input, MAX_POLICY_ADMINISTRATORS)?;
        let n = count(input, "review_protection.branches", MAX_PROTECTED_BRANCHES)?;
        let mut branches = Vec::new();
        for _ in 0..n {
            let name = input.read_ref_name()?;
            let reviewers = people(input, MAX_BRANCH_REVIEWERS)?;
            branches.push(ProtectedBranch { name, reviewers });
        }
        let value = Self {
            actor,
            expected_epoch,
            protection: ReviewProtection {
                administrators,
                branches,
            },
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectionCommand {
    pub expected_version: ExpectedVersion,
    pub expected_epoch: PolicyEpoch,
    pub protection: ReviewProtection,
}
impl ProtectionCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        let change = NativeProtectionEvent {
            actor,
            expected_epoch: self.expected_epoch,
            protection: self.protection.clone(),
        };
        change
            .validate()
            .map_err(|_| RefusalCode::EvidenceInvalid)?;
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::ReviewProtection,
            version,
            payload: ForgeEventPayload::ReviewProtectionChanged(change),
        })
    }
}
/// Called against an authority-selected predecessor on every publication attempt.
/// Bootstrap is a trusted repository-operator action, not remote self-enrolment.
pub fn validate_transition(
    previous: Option<&ForgeEvent>,
    next: &ForgeEvent,
    epoch: PolicyEpoch,
) -> Result<(), RefusalCode> {
    let ForgeEventPayload::ReviewProtectionChanged(change) = &next.payload else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    if next.aggregate != AggregateId::ReviewProtection {
        return Err(RefusalCode::EvidenceInvalid);
    }
    change
        .validate()
        .map_err(|_| RefusalCode::EvidenceInvalid)?;
    if change.expected_epoch != epoch {
        return Err(RefusalCode::EvidenceStale);
    }
    match previous {
        None => {
            if next.version != AggregateVersion::FIRST {
                return Err(RefusalCode::EvidenceStale);
            }
            if !change.protection.administrators.contains(&change.actor) {
                return Err(RefusalCode::ProtectedRefTransitionDenied);
            }
        }
        Some(previous) => {
            let ForgeEventPayload::ReviewProtectionChanged(old) = &previous.payload else {
                return Err(RefusalCode::EvidenceInvalid);
            };
            old.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
            if previous.aggregate != next.aggregate
                || !previous.version.is_immediate_predecessor_of(next.version)
                || old.resulting_epoch()? != epoch
            {
                return Err(RefusalCode::EvidenceStale);
            }
            if !old.protection.administrators.contains(&change.actor) {
                return Err(RefusalCode::ProtectedRefTransitionDenied);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
