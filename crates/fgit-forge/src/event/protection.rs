//! Canonical, repository-scoped review, workflow and merge-queue protection. Trust
//! is explicitly granted by the current policy administrators, never by a job.
use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PolicyEpoch, PrincipalId, RefName, RefusalCode};

pub const MAX_PROTECTED_BRANCHES: usize = 64;
pub const MAX_POLICY_ADMINISTRATORS: usize = 32;
pub const MAX_BRANCH_REVIEWERS: usize = 32;
pub const MAX_BRANCH_REQUIRED_CHECKS: usize = 32;
pub const MAX_BRANCH_PATH_REVIEWS: usize = 32;
pub const MAX_POLICY_PATH_REVIEWS: usize = 256;
pub const MAX_PATH_REVIEW_PATH_BYTES: usize = 4096;
pub const MAX_POLICY_PATH_REVIEW_BYTES: usize = 64 * 1024;
pub const MAX_REF_POLICY_SOURCE_BYTES: usize = fgit_policy::syntax::MAX_SOURCE_LEN;
pub const MAX_REF_POLICY_FRAME_BYTES: usize =
    fgit_policy::reference_profile::MAX_REFERENCE_POLICY_BYTES;

/// Compile the exact bounded factual profile used by every administration
/// transport. This does not stage or activate the resulting snapshot.
pub fn compile_ref_policy(
    source: &str,
) -> Result<fgit_policy::PolicySnapshot, RefPolicyCompileRefusal> {
    let snapshot = fgit_policy::compile_and_seal(source)
        .map_err(|error| RefPolicyCompileRefusal::Compile(Box::new(error)))?;
    fgit_policy::reference_profile::classify(&snapshot)
        .map_err(RefPolicyCompileRefusal::Profile)?;
    Ok(snapshot)
}

/// Stable factual-profile label for operator and transport projections.
pub fn ref_policy_profile_name(
    snapshot: &fgit_policy::PolicySnapshot,
) -> Result<&'static str, RefPolicyCompileRefusal> {
    fgit_policy::reference_profile::classify(snapshot)
        .map(|profile| profile.name())
        .map_err(RefPolicyCompileRefusal::Profile)
}

/// Accept only the exact canonical bytes and supported factual profile. The
/// same decoder serves activation commands and historical event readers.
pub fn decode_ref_policy(frame: &[u8]) -> Result<fgit_policy::PolicySnapshot, CodecRefusal> {
    decode_ref_policy_with_limits(frame, fgit_codec::DecodeLimits::DEFAULT)
}
fn decode_ref_policy_with_limits(
    frame: &[u8],
    inherited: fgit_codec::DecodeLimits,
) -> Result<fgit_policy::PolicySnapshot, CodecRefusal> {
    if frame.len() > MAX_REF_POLICY_FRAME_BYTES {
        return Err(invalid_native("review_protection.ref_policy_bytes"));
    }
    let snapshot = fgit_policy::PolicySnapshot::decode(
        frame,
        fgit_codec::DecodeLimits {
            frame_bytes: (MAX_REF_POLICY_FRAME_BYTES as u64).min(inherited.frame_bytes),
            // The canonical envelope reads its entire payload as one byte
            // string. Literal sizes remain bounded by the reference profile.
            byte_string_bytes: (MAX_REF_POLICY_FRAME_BYTES as u64).min(inherited.byte_string_bytes),
            elements: 4096.min(inherited.elements),
            depth: 32.min(inherited.depth.saturating_sub(1)),
        },
    )?;
    if snapshot.encode()? != frame {
        return Err(invalid_native("review_protection.ref_policy_noncanonical"));
    }
    fgit_policy::reference_profile::classify(&snapshot)
        .map_err(|_| invalid_native("review_protection.ref_policy"))?;
    Ok(snapshot)
}

#[derive(Debug)]
pub enum RefPolicyCompileRefusal {
    Compile(Box<fgit_policy::PolicyCompileRefusal>),
    Profile(fgit_policy::reference_profile::ReferencePolicyRefusal),
}
impl core::fmt::Display for RefPolicyCompileRefusal {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Compile(error) => write!(out, "repository ref policy compilation: {error}"),
            Self::Profile(error) => core::fmt::Display::fmt(error, out),
        }
    }
}
impl std::error::Error for RefPolicyCompileRefusal {}

/// One administrator-selected trusted publisher and exact workflow job. The
/// configured branch must still name the proposed NEW commit at admission.
/// The newest canonical matching observation must conclude Success.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequiredWorkflowCheck {
    pub source_ref: RefName,
    pub publisher: PrincipalId,
    pub graph_root: [u8; 32],
    pub job: String,
}
impl RequiredWorkflowCheck {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if !self.source_ref.as_bytes().starts_with(b"refs/heads/")
            || self.job.is_empty()
            || self.job.len() > super::workflow_check::MAX_CHECK_JOB_BYTES
            || self.job.chars().any(char::is_control)
        {
            return Err(invalid_native("review_protection.required_check"));
        }
        Ok(())
    }
}

/// One exact candidate job from an administrator-selected publisher. Unlike an
/// ordinary required check, this selector has no current CI-branch lease: the
/// canonical observation must bind the original PR subject and actual candidate.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequiredCandidateWorkflowCheck {
    pub publisher: PrincipalId,
    pub graph_root: [u8; 32],
    pub job: String,
}
impl RequiredCandidateWorkflowCheck {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.job.is_empty()
            || self.job.len() > super::workflow_check::MAX_CHECK_JOB_BYTES
            || self.job.chars().any(char::is_control)
        {
            return Err(invalid_native("review_protection.required_candidate_check"));
        }
        Ok(())
    }
}

/// Matching uses native Git path bytes, without Unicode or filesystem
/// normalization. Subtree includes the named entry and slash-separated children.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum PathReviewScope {
    Exact,
    Subtree,
}

/// An additional independent approval quorum for the actual target-to-candidate
/// tree delta. Every matching rule applies; ordering never selects a winner.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathReviewRule {
    pub path: Vec<u8>,
    pub scope: PathReviewScope,
    pub reviewers: Vec<PrincipalId>,
    pub required_approvals: u16,
}
impl PathReviewRule {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        if self.path.is_empty()
            || self.path.len() > MAX_PATH_REVIEW_PATH_BYTES
            || self.path.contains(&0)
            || self
                .path
                .split(|byte| *byte == b'/')
                .any(|part| part.is_empty() || part == b"." || part == b"..")
        {
            return Err(invalid_native("review_protection.path"));
        }
        principals(&self.reviewers, MAX_BRANCH_REVIEWERS)?;
        if self.required_approvals == 0
            || usize::from(self.required_approvals) > self.reviewers.len()
        {
            return Err(invalid_native("review_protection.path_approvals"));
        }
        Ok(())
    }

    #[must_use]
    pub fn selector_key(&self) -> (&[u8], PathReviewScope) {
        (&self.path, self.scope)
    }

    #[must_use]
    pub fn matches(&self, changed_path: &[u8]) -> bool {
        changed_path == self.path.as_slice()
            || (self.scope == PathReviewScope::Subtree
                && changed_path.starts_with(&self.path)
                && changed_path.get(self.path.len()) == Some(&b'/'))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedBranch {
    pub name: RefName,
    /// Eligible principals whose latest exact-candidate votes can count. The
    /// original PR opener and merge submitter cannot satisfy this requirement.
    pub reviewers: Vec<PrincipalId>,
    /// Required distinct approvals. Legacy policies decode to reviewers.len();
    /// review-bearing rules require 1..=reviewers.len(), other rules zero.
    pub required_approvals: u16,
    /// Strictly sorted, unique exact selectors. Empty grants no workflow trust.
    pub required_checks: Vec<RequiredWorkflowCheck>,
    /// Exact unpublished-candidate selectors, sorted and unique independently
    /// of ordinary checks. Both vectors share the same total selector ceiling.
    /// Historical policy encodings decode to an empty vector.
    pub required_candidate_checks: Vec<RequiredCandidateWorkflowCheck>,
    /// Ref changes must come from a canonically validated landing of a queue
    /// targeting this branch. A caller-provided queue receipt is not authority.
    /// Historical policy encodings decode to false.
    pub require_merge_queue: bool,
    /// Strictly sorted by (raw path bytes, scope), without duplicate selectors.
    /// Historical policy encodings decode to an empty vector.
    pub path_reviews: Vec<PathReviewRule>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewProtection {
    /// Existing administrators authorize the NEXT replacement, not its authors.
    pub administrators: Vec<PrincipalId>,
    /// Empty disables protection without erasing policy ownership/history.
    pub branches: Vec<ProtectedBranch>,
    /// Optional complete repository ref policy. Its canonical bytes are retained
    /// in the administrator-authorized event; immutable placement alone never
    /// selects it. None disables the DSL component on complete replacement.
    pub ref_policy: Option<fgit_policy::PolicySnapshot>,
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
        if let Some(snapshot) = &self.ref_policy {
            fgit_policy::reference_profile::classify(snapshot)
                .map_err(|_| invalid_native("review_protection.ref_policy"))?;
        }
        if self.branches.len() > MAX_PROTECTED_BRANCHES
            || self.branches.windows(2).any(|p| p[0].name >= p[1].name)
        {
            return Err(invalid_native("review_protection.branches"));
        }
        let mut path_rules = 0_usize;
        let mut path_bytes = 0_usize;
        for branch in &self.branches {
            if !branch.name.as_bytes().starts_with(b"refs/heads/") {
                return Err(invalid_native("review_protection.branch_namespace"));
            }
            if !branch.reviewers.is_empty() {
                principals(&branch.reviewers, MAX_BRANCH_REVIEWERS)?;
            }
            if usize::from(branch.required_approvals) > branch.reviewers.len()
                || (branch.required_approvals == 0) != branch.reviewers.is_empty()
            {
                return Err(invalid_native("review_protection.required_approvals"));
            }
            if (branch.reviewers.is_empty()
                && branch.required_checks.is_empty()
                && branch.required_candidate_checks.is_empty()
                && branch.path_reviews.is_empty()
                && !branch.require_merge_queue)
                || branch
                    .required_checks
                    .len()
                    .checked_add(branch.required_candidate_checks.len())
                    .is_none_or(|total| total > MAX_BRANCH_REQUIRED_CHECKS)
                || branch
                    .required_checks
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                || branch
                    .required_candidate_checks
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(invalid_native("review_protection.required_checks"));
            }
            for check in &branch.required_checks {
                check.validate()?;
            }
            for check in &branch.required_candidate_checks {
                check.validate()?;
            }
            if branch.path_reviews.len() > MAX_BRANCH_PATH_REVIEWS
                || branch
                    .path_reviews
                    .windows(2)
                    .any(|pair| pair[0].selector_key() >= pair[1].selector_key())
            {
                return Err(invalid_native("review_protection.path_reviews"));
            }
            path_rules = path_rules
                .checked_add(branch.path_reviews.len())
                .filter(|total| *total <= MAX_POLICY_PATH_REVIEWS)
                .ok_or_else(|| invalid_native("review_protection.path_reviews"))?;
            for rule in &branch.path_reviews {
                rule.validate()?;
                path_bytes = path_bytes
                    .checked_add(rule.path.len())
                    .filter(|total| *total <= MAX_POLICY_PATH_REVIEW_BYTES)
                    .ok_or_else(|| invalid_native("review_protection.path_bytes"))?;
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn has_required_checks(&self) -> bool {
        self.branches
            .iter()
            .any(|branch| !branch.required_checks.is_empty())
    }
    #[must_use]
    pub fn has_required_candidate_checks(&self) -> bool {
        self.branches
            .iter()
            .any(|branch| !branch.required_candidate_checks.is_empty())
    }
    /// Path-scoped quorums require the explicit path-review wire kind. An old
    /// reader must refuse that required kind instead of discarding its rules.
    #[must_use]
    pub fn has_path_reviews(&self) -> bool {
        self.branches
            .iter()
            .any(|branch| !branch.path_reviews.is_empty())
    }
    /// Queue-bearing policies require the explicit queue wire kind. Policies
    /// without this restriction retain every historical byte and identity.
    #[must_use]
    pub fn has_required_merge_queue(&self) -> bool {
        self.branches
            .iter()
            .any(|branch| branch.require_merge_queue)
    }
    /// A non-unanimous rule requires the explicit quorum wire kind. Unanimous
    /// defaults retain their historical canonical bytes and request identity.
    #[must_use]
    pub fn has_review_quorum(&self) -> bool {
        self.branches
            .iter()
            .any(|branch| usize::from(branch.required_approvals) != branch.reviewers.len())
    }
    #[must_use]
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
        let with_paths = self.protection.has_path_reviews();
        let with_candidates = with_paths || self.protection.has_required_candidate_checks();
        let with_queue = with_candidates || self.protection.has_required_merge_queue();
        // Kinds 16 through 18 wrap an explicitly named protection encoding.
        // No queue restriction means exactly the historical base and bytes.
        if self.protection.ref_policy.is_some() {
            out.write_scalar(if with_paths {
                26_u32
            } else if with_candidates {
                21_u32
            } else if with_queue {
                19_u32
            } else if self.protection.has_review_quorum() {
                14_u32
            } else if self.protection.has_required_checks() {
                13_u32
            } else {
                9_u32
            });
        }
        out.write_opaque_id(self.actor.as_bytes());
        out.write_scalar(self.expected_epoch.get());
        out.write_scalar(self.protection.administrators.len() as u32);
        for id in &self.protection.administrators {
            out.write_opaque_id(id.as_bytes());
        }
        out.write_scalar(self.protection.branches.len() as u32);
        let with_quorum = with_queue || self.protection.has_review_quorum();
        let with_checks = with_quorum || self.protection.has_required_checks();
        for branch in &self.protection.branches {
            out.write_ref_name(&branch.name)?;
            out.write_scalar(branch.reviewers.len() as u32);
            for id in &branch.reviewers {
                out.write_opaque_id(id.as_bytes());
            }
            // Kinds 9 and 13 retain every historical byte. Kinds 14 and 19 carry
            // the threshold and check count on EVERY branch, even empty checks.
            if with_quorum {
                out.write_scalar(branch.required_approvals);
            }
            if with_checks {
                out.write_scalar(branch.required_checks.len() as u32);
                for check in &branch.required_checks {
                    out.write_ref_name(&check.source_ref)?;
                    out.write_opaque_id(check.publisher.as_bytes());
                    out.write_raw(&check.graph_root);
                    out.write_bytes("review_protection.check_job", check.job.as_bytes())?;
                }
            }
            if with_queue {
                out.write_bool(branch.require_merge_queue);
            }
            if with_candidates {
                out.write_scalar(branch.required_candidate_checks.len() as u32);
                for check in &branch.required_candidate_checks {
                    out.write_opaque_id(check.publisher.as_bytes());
                    out.write_raw(&check.graph_root);
                    out.write_bytes(
                        "review_protection.candidate_check_job",
                        check.job.as_bytes(),
                    )?;
                }
            }
            if with_paths {
                out.write_scalar(branch.path_reviews.len() as u32);
                for rule in &branch.path_reviews {
                    out.write_bytes("review_protection.path", &rule.path)?;
                    out.write_scalar(match rule.scope {
                        PathReviewScope::Exact => 0_u8,
                        PathReviewScope::Subtree => 1_u8,
                    });
                    out.write_scalar(rule.reviewers.len() as u32);
                    for id in &rule.reviewers {
                        out.write_opaque_id(id.as_bytes());
                    }
                    out.write_scalar(rule.required_approvals);
                }
            }
        }
        if let Some(snapshot) = &self.protection.ref_policy {
            out.write_bytes("review_protection.ref_policy", &snapshot.encode()?)?;
        }
        Ok(())
    }
    pub(super) fn read_with_policy(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Self::read_with_profile(
            input,
            fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceFactsV1,
        )
    }
    pub(super) fn read_with_actor_policy(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Self::read_with_profile(
            input,
            fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceActorIdV1,
        )
    }
    pub(super) fn read_with_authentication_policy(
        input: &mut Decoder<'_>,
    ) -> Result<Self, CodecRefusal> {
        Self::read_with_profile(
            input,
            fgit_policy::reference_profile::ReferencePolicyProfile::ReferenceAuthenticationV1,
        )
    }
    fn read_with_profile(
        input: &mut Decoder<'_>,
        profile: fgit_policy::reference_profile::ReferencePolicyProfile,
    ) -> Result<Self, CodecRefusal> {
        let (checks, quorum, queue, candidates, paths) =
            match input.read_scalar::<u32>("review_protection.base_kind")? {
                9 => (false, false, false, false, false),
                13 => (true, false, false, false, false),
                14 => (true, true, false, false, false),
                19 => (true, true, true, false, false),
                21 => (true, true, true, true, false),
                26 => (true, true, true, true, true),
                _ => return Err(invalid_native("review_protection.base_kind")),
            };
        let mut value = Self::read_profile(input, checks, quorum, queue, candidates, paths)?;
        let frame = input.read_bytes("review_protection.ref_policy")?;
        let snapshot = decode_ref_policy_with_limits(frame, input.limits())?;
        if fgit_policy::reference_profile::classify(&snapshot).ok() != Some(profile) {
            return Err(invalid_native("review_protection.ref_policy_profile"));
        }
        value.protection.ref_policy = Some(snapshot);
        value.validate()?;
        Ok(value)
    }
    pub(super) fn read(
        input: &mut Decoder<'_>,
        with_checks: bool,
        with_quorum: bool,
        with_queue: bool,
    ) -> Result<Self, CodecRefusal> {
        Self::read_profile(input, with_checks, with_quorum, with_queue, false, false)
    }
    pub(super) fn read_with_candidate_checks(
        input: &mut Decoder<'_>,
    ) -> Result<Self, CodecRefusal> {
        Self::read_profile(input, true, true, true, true, false)
    }
    pub(super) fn read_with_path_reviews(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Self::read_profile(input, true, true, true, true, true)
    }
    fn read_profile(
        input: &mut Decoder<'_>,
        with_checks: bool,
        with_quorum: bool,
        with_queue: bool,
        with_candidates: bool,
        with_paths: bool,
    ) -> Result<Self, CodecRefusal> {
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
            allow_empty: bool,
        ) -> Result<Vec<PrincipalId>, CodecRefusal> {
            let n = count(input, "review_protection.principals", maximum)?;
            let mut ids = Vec::new();
            for _ in 0..n {
                ids.push(PrincipalId::from_bytes(
                    input.read_opaque_id("review_protection.principal")?,
                ));
            }
            if !allow_empty || !ids.is_empty() {
                principals(&ids, maximum)?;
            }
            Ok(ids)
        }
        let actor = PrincipalId::from_bytes(input.read_opaque_id("review_protection.actor")?);
        let expected_epoch =
            PolicyEpoch::try_new(input.read_scalar::<u64>("review_protection.epoch")?)?;
        let administrators = people(input, MAX_POLICY_ADMINISTRATORS, false)?;
        let n = count(input, "review_protection.branches", MAX_PROTECTED_BRANCHES)?;
        let mut branches = Vec::new();
        let mut remaining_path_rules = MAX_POLICY_PATH_REVIEWS;
        let mut remaining_path_bytes = MAX_POLICY_PATH_REVIEW_BYTES;
        for _ in 0..n {
            let name = input.read_ref_name()?;
            let reviewers = people(input, MAX_BRANCH_REVIEWERS, with_checks)?;
            let required_approvals = if with_quorum {
                input.read_scalar::<u16>("review_protection.required_approvals")?
            } else {
                reviewers.len() as u16
            };
            let mut required_checks = Vec::new();
            if with_checks {
                let n = count(
                    input,
                    "review_protection.required_checks",
                    MAX_BRANCH_REQUIRED_CHECKS,
                )?;
                for _ in 0..n {
                    let source_ref = input.read_ref_name()?;
                    let publisher = PrincipalId::from_bytes(
                        input.read_opaque_id("review_protection.check_publisher")?,
                    );
                    let mut graph_root = [0; 32];
                    graph_root.copy_from_slice(input.take("review_protection.check_graph", 32)?);
                    let job = input.read_bytes("review_protection.check_job")?;
                    if job.len() > super::workflow_check::MAX_CHECK_JOB_BYTES {
                        return Err(invalid_native("review_protection.check_job"));
                    }
                    let job = std::str::from_utf8(job)
                        .map_err(|_| invalid_native("review_protection.check_job"))?
                        .to_owned();
                    required_checks.push(RequiredWorkflowCheck {
                        source_ref,
                        publisher,
                        graph_root,
                        job,
                    });
                }
            }
            let require_merge_queue =
                with_queue && input.read_bool("review_protection.require_merge_queue")?;
            let mut required_candidate_checks = Vec::new();
            if with_candidates {
                let n = count(
                    input,
                    "review_protection.required_candidate_checks",
                    MAX_BRANCH_REQUIRED_CHECKS - required_checks.len(),
                )?;
                for _ in 0..n {
                    let publisher = PrincipalId::from_bytes(
                        input.read_opaque_id("review_protection.candidate_check_publisher")?,
                    );
                    let mut graph_root = [0; 32];
                    graph_root.copy_from_slice(
                        input.take("review_protection.candidate_check_graph", 32)?,
                    );
                    let job = input.read_bytes("review_protection.candidate_check_job")?;
                    if job.len() > super::workflow_check::MAX_CHECK_JOB_BYTES {
                        return Err(invalid_native("review_protection.candidate_check_job"));
                    }
                    let job = std::str::from_utf8(job)
                        .map_err(|_| invalid_native("review_protection.candidate_check_job"))?
                        .to_owned();
                    required_candidate_checks.push(RequiredCandidateWorkflowCheck {
                        publisher,
                        graph_root,
                        job,
                    });
                }
            }
            let mut path_reviews = Vec::new();
            if with_paths {
                let n = count(
                    input,
                    "review_protection.path_reviews",
                    MAX_BRANCH_PATH_REVIEWS.min(remaining_path_rules),
                )?;
                remaining_path_rules -= n;
                for _ in 0..n {
                    let path = input.read_bytes("review_protection.path")?;
                    if path.len() > MAX_PATH_REVIEW_PATH_BYTES.min(remaining_path_bytes) {
                        return Err(invalid_native("review_protection.path_bytes"));
                    }
                    remaining_path_bytes -= path.len();
                    let scope = match input.read_scalar::<u8>("review_protection.path_scope")? {
                        0 => PathReviewScope::Exact,
                        1 => PathReviewScope::Subtree,
                        _ => return Err(invalid_native("review_protection.path_scope")),
                    };
                    let rule = PathReviewRule {
                        path: path.to_vec(),
                        scope,
                        reviewers: people(input, MAX_BRANCH_REVIEWERS, false)?,
                        required_approvals: input
                            .read_scalar::<u16>("review_protection.path_approvals")?,
                    };
                    rule.validate()?;
                    path_reviews.push(rule);
                }
            }
            branches.push(ProtectedBranch {
                name,
                reviewers,
                required_approvals,
                required_checks,
                required_candidate_checks,
                require_merge_queue,
                path_reviews,
            });
        }
        let value = Self {
            actor,
            expected_epoch,
            protection: ReviewProtection {
                administrators,
                branches,
                ref_policy: None,
            },
        };
        value.validate()?;
        // Queue kind 19 always carries quorum/check fields and at least one
        // true queue flag. Historical kinds retain their smallest encoding.
        let canonical_kind = if with_paths {
            with_candidates
                && with_queue
                && with_quorum
                && with_checks
                && value.protection.has_path_reviews()
        } else if with_candidates {
            with_queue
                && with_quorum
                && with_checks
                && value.protection.has_required_candidate_checks()
        } else if with_queue {
            with_quorum && with_checks && value.protection.has_required_merge_queue()
        } else {
            value.protection.has_review_quorum() == with_quorum
                && (with_quorum || value.protection.has_required_checks() == with_checks)
                && (!with_quorum || with_checks)
        };
        if !canonical_kind {
            return Err(invalid_native("review_protection.check_kind"));
        }
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

#[cfg(test)]
mod quorum_tests;

#[cfg(test)]
mod ref_policy_tests;

#[cfg(test)]
mod authentication_policy_tests;

#[cfg(test)]
mod queue_tests;

#[cfg(test)]
mod candidate_check_tests;

#[cfg(test)]
mod path_review_tests;
