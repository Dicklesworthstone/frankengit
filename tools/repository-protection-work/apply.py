import pathlib,sys
root=pathlib.Path.cwd();payload=pathlib.Path(sys.argv[1]).resolve()
changed=set()
def replace(name,old,new,count=1):
 p=root/name;text=p.read_text()
 assert text.count(old)==count,(name,old[:100],text.count(old),count)
 p.write_text(text.replace(old,new));changed.add(name)
def create(name,source):
 p=root/name;assert not p.exists(),name
 p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((payload/source).read_bytes());changed.add(name)
create('crates/fgit-forge/src/event/protection.rs','protection_event.rs')
create('crates/fgit-admission/src/merge/native/protection.rs','protection_admission.rs')
create('crates/fgit-node/src/treefs_workspace/protection.rs','protection_node.rs')
create('crates/fgit-node/src/treefs_workspace/protection_tests.rs','protection_tests.rs')
p='crates/fgit-forge/src/aggregate.rs'
replace(p,'    Issue(IssueNumber),','    Issue(IssueNumber),\n    /// Singleton repository review-protection administration.\n    RepositoryProtection,')
replace(p,'            Self::Issue(number) => write!(formatter, "issue/{number}"),','            Self::Issue(number) => write!(formatter, "issue/{number}"),\n            Self::RepositoryProtection => formatter.write_str("repository-protection"),')
p='crates/fgit-forge/src/event.rs'
replace(p,'pub mod issue;','pub mod issue;\npub mod protection;\nuse protection::NativeProtectionEvent;')
replace(p,'const KIND_NATIVE_ISSUE_CHANGED: u32 = 8;','const KIND_NATIVE_ISSUE_CHANGED: u32 = 8;\nconst KIND_NATIVE_REPOSITORY_PROTECTION_CHANGED: u32 = 9;')
replace(p,'    IssueChangedNative(NativeIssueEvent),','    IssueChangedNative(NativeIssueEvent),\n    /// Required singleton policy event. Existing event encodings are unchanged.\n    RepositoryProtectionChangedNative(NativeProtectionEvent),')
replace(p,'            Self::IssueChangedNative(_) => KIND_NATIVE_ISSUE_CHANGED,','            Self::IssueChangedNative(_) => KIND_NATIVE_ISSUE_CHANGED,\n            Self::RepositoryProtectionChangedNative(_) => KIND_NATIVE_REPOSITORY_PROTECTION_CHANGED,')
replace(p,'    match aggregate {\n','    match aggregate {\n        AggregateId::RepositoryProtection => { out.write_scalar(0_u64); out.write_scalar(5_u32); }\n')
replace(p,'    match kind {\n','    match kind {\n        5 => Ok(AggregateId::RepositoryProtection),\n')
replace(p,'fn validate_issue(event: &ForgeEvent) -> Result<(), CodecRefusal> {','''fn validate_issue(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::RepositoryProtection)
        != matches!(event.payload, ForgeEventPayload::RepositoryProtectionChangedNative(_))
    { return Err(invalid_native("protection.aggregate_kind")); }
    if let ForgeEventPayload::RepositoryProtectionChangedNative(change) = &event.payload {
        change.validate()?;
    }''')
replace(p,'        ForgeEventPayload::IssueChangedNative(change) => change.write(out)?,','        ForgeEventPayload::IssueChangedNative(change) => change.write(out)?,\n        ForgeEventPayload::RepositoryProtectionChangedNative(change) => change.write(out)?,')
replace(p,'        KIND_NATIVE_ISSUE_CHANGED => ForgeEventPayload::IssueChangedNative(NativeIssueEvent::read(input)?),','        KIND_NATIVE_ISSUE_CHANGED => ForgeEventPayload::IssueChangedNative(NativeIssueEvent::read(input)?),\n        KIND_NATIVE_REPOSITORY_PROTECTION_CHANGED => ForgeEventPayload::RepositoryProtectionChangedNative(NativeProtectionEvent::read(input)?),')
p='crates/fgit-forge/src/snapshot.rs'
replace(p,'ForgeEventPayload::IssueChangedNative(_) | ForgeEventPayload::PullRequestReviewedNative(_) => {','ForgeEventPayload::RepositoryProtectionChangedNative(_) | ForgeEventPayload::IssueChangedNative(_) | ForgeEventPayload::PullRequestReviewedNative(_) => {')
p='crates/fgit-reference/src/intent.rs'
replace(p,'    IssueChanged { issue: ForgeEntityId },','    IssueChanged { issue: ForgeEntityId },\n    /// Canonical repository policy replacement; it moves no Git ref.\n    RepositoryProtectionChanged { policy: ForgeEntityId },')
replace(p,'| Self::IssueChanged { .. } => None,','| Self::IssueChanged { .. } | Self::RepositoryProtectionChanged { .. } => None,')
replace(p,'            Self::IssueChanged { issue } => *issue,','            Self::IssueChanged { issue } => *issue,\n            Self::RepositoryProtectionChanged { policy } => *policy,')
p='crates/fgit-reference/src/trace.rs'
replace(p,'        ForgeEventKind::IssueChanged { issue } => {','        ForgeEventKind::RepositoryProtectionChanged { policy } => {\n            out.write_raw_byte(7); write_slug(out, "ForgeEntityId", policy.label())?;\n        }\n        ForgeEventKind::IssueChanged { issue } => {')
replace(p,'        6 => Ok(ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(read_slug(input, "ForgeEntityId")?) }),','        6 => Ok(ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(read_slug(input, "ForgeEntityId")?) }),\n        7 => Ok(ForgeEventKind::RepositoryProtectionChanged { policy: ForgeEntityId::new(read_slug(input, "ForgeEntityId")?) }),')
p='crates/fgit-reference/src/transition.rs'
replace(p,'| ForgeEventKind::IssueChanged { .. } => None,','| ForgeEventKind::IssueChanged { .. } | ForgeEventKind::RepositoryProtectionChanged { .. } => None,')
p='crates/fgit-txn/src/lib.rs'
replace(p,'        ForgeEventKind::IssueChanged { issue } => {','        ForgeEventKind::RepositoryProtectionChanged { policy } => {\n            out.write_raw_byte(7);\n            out.write_text("ForgeEntityId", policy.label().as_str())?;\n        }\n        ForgeEventKind::IssueChanged { issue } => {')
p='crates/fgit-admission/src/merge/prepare.rs'
replace(p,'    let aggregate_matches = match &event.payload {','    let aggregate_matches = match &event.payload {\n        ForgeEventPayload::RepositoryProtectionChangedNative(_) => event.aggregate == fgit_forge::AggregateId::RepositoryProtection,')
replace(p,'    let (kind, required_objects, ref_effect) = match &event.payload {','''    let resulting_policy_epoch = match &event.payload {
        ForgeEventPayload::RepositoryProtectionChangedNative(change) => {
            change.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
            if change.actor != context.principal_id || !attempt.request.ref_commands().is_empty()
                || !closure.objects.is_empty() || change.expected_policy_epoch != basis.body().policy_epoch
            { return Err(RefusalCode::EvidenceInvalid); }
            change.activated_epoch()?
        }
        _ => basis.body().policy_epoch,
    };
    let (kind, required_objects, ref_effect) = match &event.payload {
        ForgeEventPayload::RepositoryProtectionChangedNative(_) => {
            (ForgeEventKind::RepositoryProtectionChanged { policy: entity }, Vec::new(), None)
        }''')
replace(p,'policy_epoch: basis.body().policy_epoch, compaction_generation_link: None,','policy_epoch: resulting_policy_epoch, compaction_generation_link: None,')
p='crates/fgit-admission/src/merge/native.rs'
replace(p,'pub mod issues;','pub mod issues;\npub mod protection;')
replace(p,'            let closure = projection.validate_merge_async(store, cx, &basis, &authenticated, intent).await?;','''            let closure = projection.validate_merge_async(store, cx, &basis, &authenticated, intent).await?;
            protection::guard_native_merge(store, cx, &basis, intent, context.principal_id,
                &|| projection.merge_checkpoint(cx).is_err()).await?;
            projection.merge_checkpoint(cx).map_err(ProjectionFailure::Unavailable)?;''')
p='crates/fgit-admission/src/merge/native/review_gate.rs'
replace(p,'async fn verify_at<S, C>','pub(crate) async fn verify_at<S, C>')
p='crates/fgit-node/src/lib.rs'
replace(p,'pub use treefs_workspace::IssueReadRefusal;','pub use treefs_workspace::IssueReadRefusal;\npub use treefs_workspace::{RepositoryProtectionView, ProtectionReadRefusal};')
replace(p,'''            let is_cancelled = || stage_context.checkpoint().is_err();
            let provider = self''','''            let is_cancelled = || stage_context.checkpoint().is_err();
            let targets = match &fold.outcome {
                fgit_reference::effect::FoldOutcome::Folded(effects) => effects.refs.keys().cloned().collect::<Vec<_>>(),
                _ => return Err(AsyncProjectionFailure::Refuse(RefusalCode::ConflictingSemanticEffects)),
            };
            fgit_admission::merge::native::protection::guard_direct_refs(
                authority, &stage_context, basis, &targets, &is_cancelled).await?;
            let provider = self''')
# The historical legacy materializer has no independently authenticated native
# review intent. It must not become an alternate protected-ref publication path.
replace(p,'''        let is_cancelled = || cx.checkpoint().is_err();
        let delivery = fgit_admission::merge::native::delivery::read_in(''','''        let is_cancelled = || cx.checkpoint().is_err();
        let targets = prepared_basis.ref_state.refs().keys().chain(next_state.refs().keys())
            .filter(|name| prepared_basis.ref_state.refs().get(*name) != next_state.refs().get(*name))
            .cloned().collect::<BTreeSet<_>>().into_iter().collect::<Vec<_>>();
        fgit_admission::merge::native::protection::guard_direct_refs(
            authority, cx, basis, &targets, &is_cancelled).await?;
        let delivery = fgit_admission::merge::native::delivery::read_in(''')
p='crates/fgit-node/src/treefs_workspace.rs'
replace(p,'mod issues;','mod issues;\nmod protection;\npub use protection::{RepositoryProtectionView, ProtectionReadRefusal};')
p='crates/fgit-node/src/treefs_workspace/native_merge.rs'
replace(p,'''        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&principal).map_err(receive_error)?;''','''        if let fgit_authority::OutcomeLookup::Decided(terminal) = fgit_authority::resolve_outcome_async(
            &self.authority, request.authority(), &self.head_key, self.tenant_id, self.repository_id, tx_id,
        ).await.map_err(|error| map_admission(error.into()))? {
            fgit_authority::seal_request_async(&self.authority, request.authority(), &attempt)
                .await.map_err(|error| map_admission(error.into()))?;
            return Ok((tx_id, terminal));
        }
        self.receive_publication_admitted().map_err(receive_error)?;
        self.push_quota.evaluate(&principal).map_err(receive_error)?;''')
p='crates/fgit-node/src/treefs_workspace/review_tests.rs'
replace(p,'use super::*;','use super::*;\n#[path = "protection_tests.rs"]\nmod protection_tests;')
# Avoid overlapping index borrows in the new negative test, without weakening it.
p='crates/fgit-forge/src/event/protection.rs'
replace(p,'3 => value.branches[0].reviewers.push(value.branches[0].reviewers[0]),','3 => { let duplicate = value.branches[0].reviewers[0]; value.branches[0].reviewers.push(duplicate); },')
(pathlib.Path(sys.argv[2])).write_text('\n'.join(sorted(changed))+'\n')
print('INTENDED_PRODUCT_PATHS',sorted(changed),flush=True)
