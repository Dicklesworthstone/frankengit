//! Exact PR candidates admitted on an operator-owned CI branch before execution.
//! Local custody suppresses retries; ordinary sealed ref admission owns truth.
use super::{
    File, GitOid, NodeRequestContext, NodeWorkspaceRefusal, OneNode, OpenOptions, OpenOptionsExt,
    Path, RefName, RepositoryAuthorityHeadId, Selected, TrustedRefWorkflowPoll,
    TrustedWorkflowArtifactConfig, TrustedWorkflowFailure, WorkflowLimits, cancellation,
    commitment, hex, invalid, invalid_owned, io, merge_queue, pull_request, reporting,
    sha256_digest, workspace_request_live, write_new,
};
use fgit_authority::IdempotencyKey;
use fgit_forge::event::review::ReviewSubject;
use fgit_forge::preparation::{
    MergeCommitStyle, MergeMetadata, MergePreparation, MergeProfile, PreparationLimits,
};
use fgit_forge::{AggregateVersion, PullRequestNumber};
use fgit_pack::full_bundle::FullBundleLimits;
use fgit_pack::full_bundle::retarget::RetargetedBundle;
use fgit_types::{DecisionOutcome, PrincipalId};
use fgit_wire::visibility::RefVisibility;

/// Explicit trusted-operator permission to replace one fixed CI branch under
/// an exact old-tip lease. It never permits moving either PR branch, bypassing
/// branch protection, or running a conflicted/stale candidate. Metadata is
/// deterministic input; the host clock and repository text cannot supply it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestMergeWatchConfig {
    reference: RefName,
    principal: PrincipalId,
    metadata: MergeMetadata,
    profile: MergeProfile,
    style: MergeCommitStyle,
}
impl PullRequestMergeWatchConfig {
    pub fn try_new(
        reference: RefName,
        principal: PrincipalId,
        metadata: MergeMetadata,
        profile: MergeProfile,
        style: MergeCommitStyle,
    ) -> std::io::Result<Self> {
        if !reference.as_bytes().starts_with(b"refs/heads/") || reference.as_bytes().len() > 4096 {
            return Err(std::io::Error::other(
                "merge candidate requires a bounded CI branch",
            ));
        }
        metadata
            .validate()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        Ok(Self {
            reference,
            principal,
            metadata,
            profile,
            style,
        })
    }
    #[must_use]
    pub const fn reference(&self) -> &RefName {
        &self.reference
    }
    #[must_use]
    pub const fn principal(&self) -> PrincipalId {
        self.principal
    }
    #[must_use]
    pub const fn metadata(&self) -> &MergeMetadata {
        &self.metadata
    }
    #[must_use]
    pub const fn profile(&self) -> MergeProfile {
        self.profile
    }
    #[must_use]
    pub const fn style(&self) -> MergeCommitStyle {
        self.style
    }

    const fn profile_name(&self) -> &'static str {
        match self.profile {
            MergeProfile::PathMergeV1 => "path",
            MergeProfile::ExactRenamesV1 => "exact-renames",
        }
    }
    const fn style_name(&self) -> &'static str {
        match self.style {
            MergeCommitStyle::TwoParent => "merge-commit",
            MergeCommitStyle::Squash => "squash",
        }
    }
    fn identity(&self) -> [u8; 32] {
        commitment(&[
            b"frankengit/pull-request-merge-watch-config/v1",
            self.reference.as_bytes(),
            self.principal.as_bytes(),
            self.metadata.author.as_bytes(),
            self.metadata.committer.as_bytes(),
            &self.metadata.timestamp.to_be_bytes(),
            &self.metadata.message,
            self.profile_name().as_bytes(),
            self.style_name().as_bytes(),
        ])
    }
    pub(super) fn bind(&self, root: &Path) -> Result<(), TrustedWorkflowFailure> {
        reporting::bind_identity(root, "merge-config", &self.identity())
    }
}

pub(super) fn scope(
    node: &OneNode,
    reference: &RefName,
    directory: &[u8],
    number: u64,
) -> [u8; 32] {
    // Configuration is bound immutably INSIDE the scope. Changing it must not
    // escape responsibility for a prior unknown ref decision or execution.
    commitment(&[
        b"frankengit/pull-request-merge-workflow-watch/v1",
        &pull_request::scope(node, reference, directory, number),
    ])
}

pub(super) enum Preparation {
    Ready(Prepared),
    Idle(&'static str),
}

pub(super) struct Prepared {
    pub commit: GitOid,
    pub bundle: Vec<u8>,
    subject: ReviewSubject,
    source_head: RepositoryAuthorityHeadId,
    base: GitOid,
    tree: GitOid,
    expected_old: Option<GitOid>,
    publication_key: [u8; 32],
    queue: Option<merge_queue::QueueSelection>,
}
impl Prepared {
    pub(super) fn to_json(
        &self,
        config: &PullRequestMergeWatchConfig,
        request: &NodeRequestContext,
    ) -> Result<String, TrustedWorkflowFailure> {
        let parents = match config.style {
            MergeCommitStyle::TwoParent => format!(
                "\"{}\",\"{}\"",
                self.subject.target_tip, self.subject.source_tip
            ),
            MergeCommitStyle::Squash => format!("\"{}\"", self.subject.target_tip),
        };
        let expected = self
            .expected_old
            .map_or_else(|| "null".into(), |id| format!("\"{id}\""));
        let mut json = format!(
            concat!(
                "{{\"ref_hex\":\"{}\",\"commit\":\"{}\",\"tree\":\"{}\",\"base\":\"{}\",",
                "\"expected_old\":{},\"principal\":\"{}\",\"publication_key\":\"{}\",",
                "\"bundle_sha256\":\"{}\",\"method\":\"{}\",\"profile\":\"{}\",",
                "\"author_hex\":\"{}\",\"committer_hex\":\"{}\",\"timestamp\":\"{}\",",
                "\"message_hex\":\"{}\",\"policy_epoch\":\"{}\",\"parents\":[{}]}}"
            ),
            hex(config.reference.as_bytes()),
            self.commit,
            self.tree,
            self.base,
            expected,
            config.principal,
            hex(&self.publication_key),
            hex(&sha256_digest(&self.bundle)),
            config.style_name(),
            config.profile_name(),
            hex(config.metadata.author.as_bytes()),
            hex(config.metadata.committer.as_bytes()),
            config.metadata.timestamp,
            hex(&config.metadata.message),
            self.subject.policy_epoch.get(),
            parents,
        );
        if self.queue.is_some() {
            let mut live = || workspace_request_live(request);
            let landing = self.landing_bundle(config, &mut live)?;
            let digest = landing
                .sha256(&mut live)
                .map_err(|error| invalid_owned(error.to_string()))?;
            json.pop();
            json.push_str(&format!(
                ",\"landing_bundle\":\"landing.bundle\",\"landing_bundle_sha256\":\"{}\"}}",
                hex(&digest),
            ));
        }
        Ok(json)
    }

    fn landing_bundle(
        &self,
        config: &PullRequestMergeWatchConfig,
        live: &mut impl fgit_pack::Deadline,
    ) -> Result<RetargetedBundle<'_>, TrustedWorkflowFailure> {
        RetargetedBundle::parse(
            &self.bundle,
            config.reference(),
            &self.subject.target_ref,
            self.commit,
            FullBundleLimits::default(),
            live,
        )
        .map_err(|error| invalid_owned(error.to_string()))
    }

    /// Retain a target-advertised copy of the exact tested pack as a ready
    /// landing artifact. Only its bounded header changes; streaming borrows
    /// the candidate pack instead of allocating another full bundle buffer.
    pub(super) fn retain_landing_bundle(
        &self,
        config: &PullRequestMergeWatchConfig,
        request: &NodeRequestContext,
        directory: &Path,
    ) -> Result<(), TrustedWorkflowFailure> {
        if self.queue.is_none() {
            return Ok(());
        }
        let mut live = || workspace_request_live(request);
        let landing = self.landing_bundle(config, &mut live)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(directory.join("landing.bundle"))
            .map_err(io)?;
        landing
            .write_to(&mut file, &mut live)
            .map_err(|error| invalid_owned(error.to_string()))?;
        file.sync_all()
            .and_then(|()| File::open(directory)?.sync_all())
            .map_err(io)
    }
}

pub(super) fn retained_event(path: &Path) -> Result<String, TrustedWorkflowFailure> {
    // Metadata contributes at most 128 KiB of hex, plus bounded ref names.
    String::from_utf8(reporting::read_private(
        &path.join("event.json"),
        192 * 1024,
    )?)
    .map_err(|_| invalid("invalid retained merge event UTF-8"))
}

impl OneNode {
    /// Watch an exact current native PR, prepare its selected merge/squash tree,
    /// admit it on the configured CI ref, then execute canonical candidate files.
    /// PR branch/path filters retain the original target and incoming source.
    ///
    /// The explicit principal authorizes exact-old CI ref rewrites. Candidate
    /// bytes, original old-tip lease and stable key are synced before admission.
    /// Any failure after reservation retains custody and blocks automatic replay.
    /// Conflicts and stale PR metadata never reserve an event or run a script.
    pub async fn poll_trusted_pull_request_merge_workflows_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        number: u64,
        directory: &[u8],
        parent: &Path,
        read_prefixes: &[Vec<u8>],
        limits: WorkflowLimits,
        artifacts: Option<&TrustedWorkflowArtifactConfig>,
        merge: &PullRequestMergeWatchConfig,
    ) -> Result<TrustedRefWorkflowPoll, TrustedWorkflowFailure> {
        self.poll_selected_workflows_in(
            request,
            reference,
            directory,
            parent,
            read_prefixes,
            limits,
            artifacts,
            Some(number),
            None,
            Some(merge),
        )
        .await
    }

    pub(super) async fn prepare_watched_merge_in(
        &self,
        request: &NodeRequestContext,
        reference: &RefName,
        selected: &Selected,
        config: &PullRequestMergeWatchConfig,
        event: [u8; 32],
    ) -> Result<Preparation, TrustedWorkflowFailure> {
        let pull = selected
            .pull
            .as_ref()
            .ok_or_else(|| invalid("merge watch requires a PR"))?;
        if config.reference == pull.target || config.reference == *reference {
            return Err(invalid("CI branch must differ from both PR branches"));
        }
        if pull.recorded_source != selected.commit || pull.recorded_target != pull.target_commit {
            return Ok(Preparation::Idle("pull_request_stale"));
        }
        let state = match self.materialize_admission_in(request).await {
            Ok(state) => state,
            Err(error) if cancellation::materialization(&error) => {
                return Ok(Preparation::Idle("stopped_before_reservation"));
            }
            Err(error) => {
                return Err(TrustedWorkflowFailure::Source(
                    NodeWorkspaceRefusal::Authority(Box::new(error)),
                ));
            }
        };
        if state.basis().id() != selected.head {
            return Ok(Preparation::Idle("source_moved"));
        }
        if state
            .snapshot()
            .hidden_refs
            .hides(config.reference.as_bytes())
        {
            return Err(invalid("merge candidate CI branch is unavailable"));
        }
        let expected_old = state.snapshot().refs.get(&config.reference).copied();
        let subject = ReviewSubject {
            pull_request: PullRequestNumber::try_new(pull.number)
                .ok_or_else(|| invalid("invalid PR number"))?,
            pull_request_version: AggregateVersion::try_new(pull.version)
                .ok_or_else(|| invalid("invalid PR version"))?,
            source_ref: reference.clone(),
            target_ref: pull.target.clone(),
            source_tip: selected.commit,
            target_tip: pull.target_commit,
            policy_epoch: pull.policy_epoch,
        };
        let artifact = if let Some(queue) = &selected.queue {
            self.prepare_queue_head_bundle_with_profile_in(
                request,
                queue.number,
                queue.version,
                &subject,
                &RefVisibility::new(),
                &config.metadata,
                PreparationLimits::default(),
                config.profile,
            )
            .await
            .map(|artifact| (artifact.source_head, artifact.outcome, artifact.bundle))
        } else {
            self.prepare_pull_request_bundle_with_options_in(
                request,
                &subject,
                &RefVisibility::new(),
                &config.metadata,
                PreparationLimits::default(),
                config.profile,
                config.style,
            )
            .await
            .map(|artifact| (artifact.source_head, artifact.outcome, artifact.bundle))
        };
        let (source_head, outcome, candidate_bundle) = match artifact {
            Ok(artifact) => artifact,
            Err(
                NodeWorkspaceRefusal::StaleWorkspaceBase | NodeWorkspaceRefusal::RefUnavailable,
            ) => {
                return Ok(Preparation::Idle(if selected.queue.is_some() {
                    "queue_head_stale"
                } else {
                    "pull_request_stale"
                }));
            }
            Err(NodeWorkspaceRefusal::Cancelled { .. }) => {
                return Ok(Preparation::Idle("stopped_before_reservation"));
            }
            Err(error) => return Err(TrustedWorkflowFailure::Source(error)),
        };
        if source_head != selected.head {
            return Ok(Preparation::Idle("source_moved"));
        }
        let plan = match outcome {
            MergePreparation::Clean(plan) => plan,
            MergePreparation::Conflicted { .. } => {
                return Ok(Preparation::Idle("merge_conflicted"));
            }
            MergePreparation::AlreadyUpToDate { .. } => {
                return Ok(Preparation::Idle("merge_up_to_date"));
            }
        };
        let bundle = rebind_bundle(
            candidate_bundle
                .as_deref()
                .ok_or_else(|| invalid("clean candidate has no bundle"))?,
            &pull.target,
            &config.reference,
            plan.commit,
            &mut || workspace_request_live(request),
        )?;
        Ok(Preparation::Ready(Prepared {
            commit: plan.commit,
            bundle,
            subject,
            source_head: selected.head,
            base: plan.base,
            tree: plan.tree,
            expected_old,
            publication_key: commitment(&[
                b"frankengit/watched-merge-ref-publication/v1",
                &event,
                &config.identity(),
            ]),
            queue: selected.queue.clone(),
        }))
    }

    pub(super) async fn publish_watched_merge_in(
        &self,
        request: &NodeRequestContext,
        prepared: &Prepared,
        config: &PullRequestMergeWatchConfig,
        directory: &Path,
    ) -> Result<RepositoryAuthorityHeadId, TrustedWorkflowFailure> {
        if let Some(queue) = &prepared.queue {
            self.validate_queue_workflow_candidate_in(
                request,
                queue,
                &prepared.subject,
                Some(prepared.source_head),
            )
            .await?;
        }
        // This lease is the one persisted BEFORE admission. Never refresh it
        // on a CAS refusal or derive a new key to escape a terminal decision.
        let key = IdempotencyKey::new(prepared.publication_key.to_vec())
            .map_err(|_| invalid("invalid candidate publication identity"))?;
        let session = crate::LoopbackReceiveSession::authenticated(config.principal, key);
        let admitted = self
            .import_incremental_git_bundle_at_head_durable_in(
                request,
                &session,
                &prepared.bundle,
                &[(config.reference.clone(), prepared.expected_old)],
                prepared.source_head,
                Default::default(),
            )
            .await
            .map_err(TrustedWorkflowFailure::Source)?;
        if admitted.commands.len() != 1 {
            return Err(invalid(
                "candidate publication returned an unexpected command set",
            ));
        }
        let command = &admitted.commands[0];
        let committed = matches!(command.terminal.outcome, DecisionOutcome::Committed { .. });
        let receipt = format!(
            "{{\"transaction_id\":\"{}\",\"committed\":{},\"publication_key\":\"{}\",\"candidate\":\"{}\"}}",
            command.tx_id,
            committed,
            hex(&prepared.publication_key),
            prepared.commit
        );
        write_new(
            &directory.join("candidate-publication.json"),
            receipt.as_bytes(),
        )
        .and_then(|()| File::open(directory)?.sync_all())
        .map_err(io)?;
        if !committed {
            return Err(invalid(
                "canonical candidate CI ref publication refused; original lease and identity retained",
            ));
        }
        // Publication advanced authority. Recheck the SAME original PR subject;
        // a changed PR, branch, or policy cannot silently select another run.
        if let Some(queue) = &prepared.queue {
            self.validate_queue_workflow_candidate_in(request, queue, &prepared.subject, None)
                .await
        } else {
            self.validate_pull_request_preparation_in(
                request,
                &prepared.subject,
                &RefVisibility::new(),
            )
            .await
            .map_err(TrustedWorkflowFailure::Source)
        }
    }
}

fn rebind_bundle(
    bytes: &[u8],
    original: &RefName,
    destination: &RefName,
    commit: GitOid,
    live: &mut impl fgit_pack::Deadline,
) -> Result<Vec<u8>, TrustedWorkflowFailure> {
    RetargetedBundle::parse(
        bytes,
        original,
        destination,
        commit,
        FullBundleLimits::default(),
        live,
    )
    .and_then(|bundle| bundle.into_vec(live))
    .map_err(|error| invalid_owned(error.to_string()))
}
