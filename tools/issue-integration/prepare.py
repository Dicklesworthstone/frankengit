import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd();BASE='3dea22ef9c035427d557f7ad89fe40cd893e39fc'
def git(*args,cwd=ROOT):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-issue-native-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    changed=set();all_changed=set()
    def replace(rel,old,new):
        path=work/rel;text=path.read_text();assert text.count(old)==1,(rel,old[:100],text.count(old))
        path.write_text(text.replace(old,new));changed.add(rel)
    def add(rel,payload):
        path=work/rel;assert not path.exists();path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes((ROOT/'tools/issue-integration/payload'/payload).read_bytes());changed.add(rel)
    def commit(message):
        git('diff','--check',cwd=work)
        observed=set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())
        assert observed==changed,(observed,changed)
        git('add','--',*sorted(changed),cwd=work);git('commit','-m',message,cwd=work)
        print('PRODUCT_COMMIT',git('rev-parse','HEAD',cwd=work),message,flush=True)
        all_changed.update(changed);changed.clear()
    replace('crates/fgit-forge/tests/atomic_merge.rs','for unknown in [0_u32, 5, 99, u32::from(u16::MAX)]','for unknown in [0_u32, 9, 99, u32::from(u16::MAX)]')
    i='crates/fgit-reference/src/intent.rs'
    replace(i,'    /// Issue lifecycle or discussion changed; detailed action/text are sealed in its event batch.\n    IssueChanged { issue: ForgeEntityId },\n','')
    replace(i,'        target: RefName,\n    },\n}\n\nimpl ForgeEventKind','        target: RefName,\n    },\n    /// Issue lifecycle or discussion changed; detailed action/text are sealed in its event batch.\n    IssueChanged { issue: ForgeEntityId },\n}\n\nimpl ForgeEventKind')
    commit('test(forge): keep unknown-event refusals outside the implemented kind range')
    add('crates/fgit-admission/src/merge/native/metadata.rs','metadata.rs')
    add('crates/fgit-admission/src/merge/native/issues.rs','admission_issues.rs')
    replace('crates/fgit-admission/src/merge/native/issues.rs','let Some(text) = entry.stream().as_str().strip_prefix("issue/")','let label = entry.stream();\n        let Some(text) = label.as_str().strip_prefix("issue/")')
    replace('crates/fgit-admission/src/merge/native.rs','pub mod pull_request;','pub mod pull_request;\nmod metadata;\npub mod issues;')
    p='crates/fgit-admission/src/merge/native/pull_request.rs'
    path=work/p;text=path.read_text();start=text.index('pub async fn admit_pull_request_async<S, P>(');end=text.index('/// Read the exact event selected for one aggregate.',start)
    new='''pub async fn admit_pull_request_async<S, P>(
    store: &S, cx: &S::Context, context: &AdmissionContext,
    command: &PullRequestCommand, limits: AdmissionLimits, projection: &P,
) -> Result<TerminalOutcome, AdmissionError>
where S: AsyncAuthorityStore + ?Sized, P: PullRequestProjection<S> + ?Sized,
{
    limits.validate()?;
    let (event, attempt) = proposal(context, command)?;
    super::metadata::admit_metadata_async(store, cx, context, event, attempt,
        limits, projection, &PullRequestValidation(command)).await
}
struct PullRequestValidation<'a>(&'a PullRequestCommand);
impl<S, P> super::metadata::MetadataValidation<S, P> for PullRequestValidation<'_>
where S: AsyncAuthorityStore + ?Sized, P: PullRequestProjection<S> + ?Sized,
{
    fn precheck(&self, snapshot: &crate::AdmissionSnapshot) -> Result<(), ProjectionFailure> {
        if snapshot.hidden_refs.hides(self.0.data.source_ref.as_bytes())
            || snapshot.hidden_refs.hides(self.0.data.target_ref.as_bytes())
        { return Err(ProjectionFailure::Refuse(RefusalCode::HiddenRefUnauthorized)); }
        Ok(())
    }
    fn validate<'a>(&'a self, store: &'a S, cx: &'a S::Context,
        basis: &'a PublicationBasis, authenticated: &'a AuthenticatedHead,
        snapshot: &'a crate::AdmissionSnapshot, resolved: &'a super::super::NativeMergeBasis,
        event: &'a ForgeEvent, projection: &'a P,
    ) -> impl Future<Output = Result<ValidatedClosure, PreparationFailure>> + Send + 'a {
        async move {
            let command = self.0;
            let previous = frontier_event(store, cx, &resolved.forge, command.number).await?;
            validate_transition(previous.as_ref(), event).map_err(ProjectionFailure::Refuse)?;
            if command.action != PullRequestAction::Close
                && (snapshot.refs.get(&command.data.source_ref) != Some(&command.data.source_tip)
                    || snapshot.refs.get(&command.data.target_ref) != Some(&command.data.target_tip))
            { return Err(ProjectionFailure::Refuse(RefusalCode::TargetRefMoved).into()); }
            Ok(projection.validate_pull_request_async(store, cx, basis, authenticated, command).await?)
        }
    }
}

'''
    path.write_text(text[:start]+new+text[end:]);changed.add(p)
    replace(p,'AuthenticatedHead, OutcomeLookup, ScopedEntry','AuthenticatedHead, ScopedEntry')
    replace(p,'use fgit_chronicle::{PublicationBasis, PublicationPlan};','use fgit_chronicle::PublicationBasis;')
    replace(p,'use fgit_codec::{CanonicalForgePositionState, CryptoBodyIdentity};','use fgit_codec::CanonicalForgePositionState;')
    replace(p,'PreparationFailure, delivery, prepare_event, stage_prepared, storage, unavailable','PreparationFailure, delivery, storage, unavailable')
    p='crates/fgit-admission/src/merge/prepare.rs'
    replace(p,'        ForgeEventPayload::PullRequestReviewedNative(review) => event.aggregate == review.aggregate(),','        ForgeEventPayload::PullRequestReviewedNative(review) => event.aggregate == review.aggregate(),\n        ForgeEventPayload::IssueChangedNative(_) => matches!(event.aggregate, fgit_forge::AggregateId::Issue(_)),')
    replace(p,'        ForgeEventPayload::MergeCommittedNative(merge) => {','''        ForgeEventPayload::IssueChangedNative(change) => {
            change.action.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
            if change.actor != context.principal_id || !attempt.request.ref_commands().is_empty()
                || !closure.objects.is_empty()
            { return Err(RefusalCode::EvidenceInvalid); }
            (ForgeEventKind::IssueChanged { issue: entity }, Vec::new(), None)
        }
        ForgeEventPayload::MergeCommittedNative(merge) => {''')
    commit('feat(admission): publish versioned issues through shared canonical metadata admission')
    add('crates/fgit-node/src/treefs_workspace/issues.rs','node_issues.rs')
    add('crates/fgit-node/src/treefs_workspace/issues/tests.rs','node_issue_tests.rs')
    replace('crates/fgit-node/src/treefs_workspace.rs','mod pull_request;','mod pull_request;\nmod issues;\npub use issues::IssueReadRefusal;')
    replace('crates/fgit-node/src/lib.rs','mod treefs_workspace;','mod treefs_workspace;\npub use treefs_workspace::IssueReadRefusal;')
    commit('feat(node): add durable issue commands and snapshot-pinned issue timelines')
    source=git('rev-parse','HEAD',cwd=work);branch='tooling/issue-source-'+os.environ['GITHUB_SHA'][:12]
    assert set(git('diff','--name-only',BASE,source,cwd=work).splitlines())==all_changed
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
