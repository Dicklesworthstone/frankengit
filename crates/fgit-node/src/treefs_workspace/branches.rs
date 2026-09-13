//! Local branch operations use ordinary atomic receive admission. No branch
//! database, synthetic import receipt, or new publication primitive is involved.

use std::cell::Cell;
use fgit_admission::{AdmissionContext, AdmissionLimits, AdmissionResult, CommandOutcome, SessionMapping};
use fgit_authority::{ExpectedOld, OutcomeLookup, ProposedNew, RefCommand, SealAttempt, SemanticRequest, RECEIVE_ADMISSION_SCHEMA};
use fgit_git_object::{ObjectType, ParseLimits};
use fgit_pack::{PackPlanner, PackWriteProfile, PackWriter};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_types::cell::{ReadMode, admits_read};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, encode_packets};
use fgit_wire::receive::{ReceiveContext, ReceiveLimits, ReceivePack, SignedPushProfile};
use fgit_wire::visibility::RefVisibility;
use crate::{LoopbackReceiveSession, NodeReceiveTransportRefusal, NodeRequestContext, OneNode, VerifiedFabricPackSource};
use crate::quarantine_validator::ProductionReceiveQuarantineHandoff;
use super::{NodeWorkspaceRefusal, workspace_request_live};
use super::publication::receive_error;

fn invalid(reason: &'static str) -> NodeWorkspaceRefusal {
    NodeWorkspaceRefusal::BranchOperation(reason)
}

fn branch_request(format: GitHashAlgorithm, commands: &[RefCommand]) -> Result<SemanticRequest, NodeWorkspaceRefusal> {
    if commands.is_empty() || commands.len() > 2 {
        return Err(invalid("one branch update or one two-command rename is required"));
    }
    for command in commands {
        if !command.name.as_bytes().starts_with(b"refs/heads/") || command.force {
            return Err(invalid("only non-forced branch references are accepted"));
        }
        let old = match command.expected_old {
            ExpectedOld::Absent => None,
            ExpectedOld::Exactly(oid) => Some(oid),
            ExpectedOld::Unspecified => return Err(invalid("an exact expected-old condition is required")),
        };
        let new = match command.proposed_new {
            ProposedNew::Delete => None,
            ProposedNew::Update(oid) => Some(oid),
        };
        if old.is_none() && new.is_none() {
            return Err(invalid("deletion requires an exact nonzero expected tip"));
        }
        if old.into_iter().chain(new).any(|oid| oid.is_zero() || oid.algorithm() != format) {
            return Err(NodeWorkspaceRefusal::ObjectFormatMismatch);
        }
    }
    if commands.len() == 2 {
        let deletion = commands.iter().find_map(|command| match (command.expected_old, command.proposed_new) {
            (ExpectedOld::Exactly(old), ProposedNew::Delete) => Some(old), _ => None,
        });
        let creation = commands.iter().find_map(|command| match (command.expected_old, command.proposed_new) {
            (ExpectedOld::Absent, ProposedNew::Update(new)) => Some(new), _ => None,
        });
        if deletion.is_none() || deletion != creation {
            return Err(invalid("rename must atomically delete and create the same exact commit"));
        }
    }
    SemanticRequest::build(RECEIVE_ADMISSION_SCHEMA, format, true, commands.to_vec(), vec![], vec![])
        .map_err(|_| invalid("invalid or duplicate branch command"))
}

impl OneNode {
    /// Atomically create, update, delete, or rename a local branch. One update
    /// carries an explicit expected-old condition; a rename is exactly an
    /// expected-tip deletion plus an absent-destination creation of that tip.
    /// The caller authenticates the session at the trusted local boundary.
    ///
    /// New tips must be verified native commits available through current
    /// visible refs. Empty but real Git packs go through production quarantine,
    /// including its bounded visible-reachability proof. Ref protection and
    /// exact-basis validation remain ordinary admission decisions. Default
    /// branch deletion/rename is refused, rather than leaving HEAD dangling;
    /// this operation does not rewrite PR metadata or repository configuration.
    ///
    /// Exact terminal retries precede serving/quota/current-object checks. An
    /// infrastructure error does not establish non-commit; the same scoped key
    /// remains recoverable through `recover_transaction_in`.
    pub async fn admit_branch_updates_durable_in(
        &self, request: &NodeRequestContext, session: &LoopbackReceiveSession,
        commands: &[RefCommand], limits: AdmissionLimits,
    ) -> Result<AdmissionResult, NodeWorkspaceRefusal> {
        let authenticated = session.authenticated_session()
            .ok_or_else(|| receive_error(NodeReceiveTransportRefusal::Unauthenticated))?;
        let semantic = branch_request(self.object_format, commands)?;
        let attempt = SealAttempt {
            tenant_id: self.tenant_id, repository_id: self.repository_id,
            authenticated_principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(), request: semantic,
        };
        let admission_error = |error| receive_error(NodeReceiveTransportRefusal::Admission(Box::new(error)));
        let (tx_id, _) = attempt.derive().map_err(|error| admission_error(error.into()))?;
        if let OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id, self.repository_id, tx_id,
        ).await.map_err(|error| admission_error(error.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| admission_error(error.into()))?;
            return Ok(AdmissionResult {
                session: SessionMapping { atomic: true, tx_ids: vec![tx_id] },
                commands: vec![CommandOutcome { tx_id, terminal }; commands.len()],
            });
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&authenticated.principal_id()).map_err(receive_error)?;
        let materialized = self.materialize_admission_in(request).await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        for command in attempt.request.ref_commands() {
            if materialized.snapshot().hidden_refs.hides(command.name.as_bytes()) {
                return Err(NodeWorkspaceRefusal::RefUnavailable);
            }
            if matches!(command.proposed_new, ProposedNew::Delete)
                && materialized.snapshot().head_target.as_ref() == Some(&command.name) {
                return Err(invalid("the authority-selected default branch cannot be deleted or renamed"));
            }
        }
        let mut receive_limits = ReceiveLimits::default();
        receive_limits.max_commands = 2;
        receive_limits.pack.max_object_bytes = receive_limits.pack.max_object_bytes
            .min(usize::try_from(self.max_object_bytes).unwrap_or(usize::MAX));
        let parse_limits = ParseLimits { tree_reference_bytes: self.object_format.digest_len(),
            max_object_bytes: receive_limits.pack.max_object_bytes, ..ParseLimits::default() };
        let exhaustion = Cell::new(None);
        let source = VerifiedFabricPackSource {
            fabric: &self.fabric, object_format: self.object_format,
            maximum_object_bytes: receive_limits.pack.max_object_bytes,
            database_context: request.authority(), database_exhaustion: &exhaustion, session_is_live: None,
        };
        let mut live = || workspace_request_live(request);
        let capability_bytes = format!("report-status atomic delete-refs object-format={}", self.object_format.as_str());
        let capabilities = Capabilities::parse_v1(capability_bytes.as_bytes(), &receive_limits.wire)
            .map_err(|_| invalid("branch receive capabilities could not be encoded"))?;
        let zero = "0".repeat(self.object_format.digest_len() * 2);
        let mut packets = Vec::with_capacity(commands.len() + 1);
        for (index, command) in attempt.request.ref_commands().iter().enumerate() {
            let old = match command.expected_old { ExpectedOld::Absent => zero.clone(), ExpectedOld::Exactly(oid) => oid.to_string(), ExpectedOld::Unspecified => return Err(invalid("an exact expected-old condition is required")) };
            let new = match command.proposed_new { ProposedNew::Delete => zero.clone(), ProposedNew::Update(oid) => oid.to_string() };
            let mut data = format!("{old} {new} ").into_bytes();
            data.extend_from_slice(command.name.as_bytes());
            if index == 0 { data.push(0); data.extend_from_slice(capability_bytes.as_bytes()); }
            packets.push(Packet::Data(data));
        }
        packets.push(Packet::Flush);
        let prefix = encode_packets(&packets, &receive_limits.wire)
            .map_err(|_| invalid("branch commands exceed the wire envelope"))?;
        let validator = self.production_quarantine_validator(&materialized, receive_limits.pack.clone(), parse_limits)
            .map_err(|code| receive_error(fgit_wire::receive::ReceiveError::AuthoritativeRefusal(code)))?;
        let format = match self.object_format { GitHashAlgorithm::Sha1 => GitObjectFormat::Sha1, GitHashAlgorithm::Sha256 => GitObjectFormat::Sha256 };
        let context = ReceiveContext::new(format, capabilities, receive_limits.clone(), SignedPushProfile::Refuse)
            .map_err(receive_error)?;
        let mut receive = ReceivePack::new(context).map_err(receive_error)?;
        receive.push_bytes(&prefix).map_err(receive_error)?;
        if attempt.request.ref_commands().iter().any(|command| matches!(command.proposed_new, ProposedNew::Update(_))) {
            let planner = PackPlanner::new(self.object_format, PackWriteProfile::STORED_V1, receive_limits.pack.clone());
            let plan = planner.plan(&source, &[], &mut live).map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
            let (pack, _) = PackWriter::new(receive_limits.pack).write(&plan, &mut live)
                .map_err(|error| NodeWorkspaceRefusal::MergePack(Box::new(error)))?;
            receive.push_bytes(&pack).map_err(receive_error)?;
        }
        let mut handoff = ProductionReceiveQuarantineHandoff::new(validator, materialized.basis().clone());
        receive.finish_with_handoff(&mut handoff, &mut live).map_err(receive_error)?;
        let validated = handoff.into_validated_receive().map_err(receive_error)?;
        // Check branch kinds using verified object bytes, not object-ID shape.
        // Quarantine already established visible reachability, before kind disclosure.
        for command in attempt.request.ref_commands() {
            if let ProposedNew::Update(oid) = command.proposed_new {
                if !materialized.selected_closure().closure().objects().contains(&oid) {
                    return Err(NodeWorkspaceRefusal::RefUnavailable);
                }
                if !live() { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: exhaustion.get() }); }
                let object = source.read_object(&oid);
                if !live() { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: exhaustion.get() }); }
                let (kind, _) = object.map_err(|_| invalid("branch target could not be verified"))?;
                if kind != ObjectType::Commit { return Err(NodeWorkspaceRefusal::CommitRequired); }
            }
        }
        let context = AdmissionContext { head_key: self.head_key.clone(), tenant_id: self.tenant_id,
            repository_id: self.repository_id, principal_id: authenticated.principal_id(),
            idempotency_key: authenticated.client_idempotency_key().clone(), object_format: self.object_format };
        self.admit_basis_bound_validated_receive_durable_in(request, &context, &validated, limits)
            .await.map_err(admission_error)
    }

    /// Bounded, byte-ordered branch listing at one authenticated current head.
    /// Returns (snapshot identity, rows, continuation reference). A continuation
    /// requires the first page's identity and fails if authority has moved.
    /// Caller visibility can only narrow canonical hidden-ref policy.
    pub async fn list_branch_refs_in(
        &self, request: &NodeRequestContext, visibility: &RefVisibility,
        after: Option<&RefName>, limit: u16, expected_head: Option<RepositoryAuthorityHeadId>,
    ) -> Result<(RepositoryAuthorityHeadId, Vec<(RefName, GitOid)>, Option<RefName>), NodeWorkspaceRefusal> {
        if !(1..=100).contains(&limit) { return Err(invalid("branch page limit must be 1..100")); }
        if after.is_some() && expected_head.is_none() { return Err(invalid("branch continuation requires a snapshot identity")); }
        if after.is_some_and(|name| !name.as_bytes().starts_with(b"refs/heads/")) { return Err(invalid("branch cursor must be a full branch reference")); }
        admits_read(self.cell_state(), ReadMode::Current).map_err(NodeWorkspaceRefusal::Cell)?;
        let selected = self.materialize_admission_in(request).await
            .map_err(|error| NodeWorkspaceRefusal::Authority(Box::new(error)))?;
        if expected_head.is_some_and(|head| head != selected.basis().id()) { return Err(invalid("branch snapshot moved")); }
        let mut rows = Vec::with_capacity(usize::from(limit));
        let mut next = None;
        for (name, oid) in &selected.snapshot().refs {
            if !workspace_request_live(request) { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }); }
            if !name.as_bytes().starts_with(b"refs/heads/") || after.is_some_and(|cursor| name <= cursor)
                || visibility.hides(name.as_bytes()) || selected.snapshot().hidden_refs.hides(name.as_bytes()) { continue; }
            if rows.len() == usize::from(limit) { next = rows.last().map(|(name, _): &(RefName, GitOid)| name.clone()); break; }
            rows.push((name.clone(), *oid));
        }
        if !workspace_request_live(request) { return Err(NodeWorkspaceRefusal::Cancelled { exhaustion: None }); }
        Ok((selected.basis().id(), rows, next))
    }
}

#[cfg(test)]
mod tests;
