import os,pathlib,subprocess,tempfile
ROOT=pathlib.Path.cwd()
BASE='87bcff779181b29381d486f0e903a43f0409731e'
def git(*args,cwd=ROOT):return subprocess.check_output(['git',*args],cwd=cwd,text=True).strip()
with tempfile.TemporaryDirectory(prefix='fg-issues-core-') as td:
    work=pathlib.Path(td)/'source';git('worktree','add','--detach',str(work),BASE)
    changed=set()
    def replace(rel,old,new):
        path=work/rel;text=path.read_text()
        assert text.count(old)==1,(rel,old[:120],text.count(old))
        path.write_text(text.replace(old,new));changed.add(rel)
    def add(rel,payload):
        path=work/rel;assert not path.exists();path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes((ROOT/'tools/issue-integration/payload'/payload).read_bytes());changed.add(rel)
    a='crates/fgit-forge/src/aggregate.rs'
    replace(a,'forge_counter!(\n    OrganisationNumber,','forge_counter!(IssueNumber, "Repository-scoped issue identity, distinct from a pull request number.");\nforge_counter!(\n    OrganisationNumber,')
    replace(a,'    PullRequestReview { pull_request: PullRequestNumber, reviewer: fgit_types::PrincipalId },\n}', '    PullRequestReview { pull_request: PullRequestNumber, reviewer: fgit_types::PrincipalId },\n    /// A canonical repository issue. Existing aggregate encodings are unchanged.\n    Issue(IssueNumber),\n}')
    replace(a,'pub(crate) const AGGREGATE_KIND_PULL_REQUEST_REVIEW: u32 = 3;', 'pub(crate) const AGGREGATE_KIND_PULL_REQUEST_REVIEW: u32 = 3;\n/// Required issue aggregate discriminator, appended without reusing a code point.\npub(crate) const AGGREGATE_KIND_ISSUE: u32 = 4;\nimpl From<IssueNumber> for AggregateId { fn from(number: IssueNumber) -> Self { Self::Issue(number) } }')
    replace(a,'            Self::PullRequest(number) => write!(formatter, "pull-request/{number}"),','            Self::Issue(number) => write!(formatter, "issue/{number}"),\n            Self::PullRequest(number) => write!(formatter, "pull-request/{number}"),')
    replace('crates/fgit-forge/src/lib.rs','    PullRequestNumber, TeamNumber,','    PullRequestNumber, TeamNumber, IssueNumber,')
    e='crates/fgit-forge/src/event.rs'
    replace(e,'    AggregateId, AggregateVersion, OrganisationNumber, PullRequestNumber, TeamNumber,','    AggregateId, AggregateVersion, OrganisationNumber, PullRequestNumber, TeamNumber, IssueNumber, AGGREGATE_KIND_ISSUE,')
    replace(e,'pub mod review;','pub mod review;\npub mod issue;\nuse issue::{NativeIssueEvent, IssueAction};')
    replace(e,'const KIND_NATIVE_PULL_REQUEST_REVIEWED: u32 = 7;','const KIND_NATIVE_PULL_REQUEST_REVIEWED: u32 = 7;\nconst KIND_NATIVE_ISSUE_CHANGED: u32 = 8;')
    replace(e,'    PullRequestReviewedNative(NativeReviewEvent),','    PullRequestReviewedNative(NativeReviewEvent),\n    /// Required issue event, retaining explicit changes rather than mutable latest state.\n    IssueChangedNative(NativeIssueEvent),')
    replace(e,'            Self::PullRequestReviewedNative(_) => KIND_NATIVE_PULL_REQUEST_REVIEWED,','            Self::PullRequestReviewedNative(_) => KIND_NATIVE_PULL_REQUEST_REVIEWED,\n            Self::IssueChangedNative(_) => KIND_NATIVE_ISSUE_CHANGED,')
    replace(e,'        AggregateId::PullRequest(number) => out.write_scalar(number.get()),','        AggregateId::Issue(number) => { out.write_scalar(0_u64); out.write_scalar(AGGREGATE_KIND_ISSUE); out.write_scalar(number.get()); }\n        AggregateId::PullRequest(number) => out.write_scalar(number.get()),')
    replace(e,'    match kind {\n        AGGREGATE_KIND_ORGANISATION', '    match kind {\n        AGGREGATE_KIND_ISSUE => Ok(AggregateId::Issue(counter("aggregate.issue", input.read_scalar::<u64>("aggregate.issue")?)?)),\n        AGGREGATE_KIND_ORGANISATION')
    replace(e,'fn write_event(out: &mut Encoder, event: &ForgeEvent) -> Result<(), CodecRefusal> {','fn validate_issue(event: &ForgeEvent) -> Result<(), CodecRefusal> {\n    if matches!(event.aggregate, AggregateId::Issue(_)) != matches!(event.payload, ForgeEventPayload::IssueChangedNative(_)) { return Err(invalid_native("issue.aggregate_kind")); }\n    if let ForgeEventPayload::IssueChangedNative(change) = &event.payload {\n        change.action.validate()?;\n        if matches!(change.action, IssueAction::Open { .. }) != (event.version == AggregateVersion::FIRST) { return Err(invalid_native("issue.aggregate_version")); }\n    }\n    Ok(())\n}\n\nfn write_event(out: &mut Encoder, event: &ForgeEvent) -> Result<(), CodecRefusal> {\n    validate_issue(event)?;')
    replace(e,'        ForgeEventPayload::PullRequestReviewedNative(review) => {\n            validate_review(event, review)?;', '        ForgeEventPayload::IssueChangedNative(change) => change.write(out)?,\n        ForgeEventPayload::PullRequestReviewedNative(review) => {\n            validate_review(event, review)?;')
    replace(e,'        KIND_NATIVE_PULL_REQUEST_REVIEWED => ForgeEventPayload::PullRequestReviewedNative(NativeReviewEvent::read(input)?),','        KIND_NATIVE_PULL_REQUEST_REVIEWED => ForgeEventPayload::PullRequestReviewedNative(NativeReviewEvent::read(input)?),\n        KIND_NATIVE_ISSUE_CHANGED => ForgeEventPayload::IssueChangedNative(NativeIssueEvent::read(input)?),')
    replace(e,'    let event = ForgeEvent { aggregate, version, payload };','    let event = ForgeEvent { aggregate, version, payload };\n    validate_issue(&event)?;')
    replace(e,'impl Counter for PullRequestNumber', 'impl Counter for IssueNumber { fn build(value: u64) -> Option<Self> { Self::try_new(value) } }\nimpl Counter for PullRequestNumber')
    replace('crates/fgit-forge/src/snapshot.rs','            ForgeEventPayload::PullRequestReviewedNative(_) => {','            ForgeEventPayload::IssueChangedNative(_) | ForgeEventPayload::PullRequestReviewedNative(_) => {')
    add('crates/fgit-forge/src/event/issue.rs','issue.rs')
    add('crates/fgit-forge/src/event/issue/tests.rs','issue_tests.rs')
    i='crates/fgit-reference/src/intent.rs'
    replace(i,'    PullRequestReviewed {\n        /// The independent', '    /// Issue lifecycle or discussion changed; detailed action/text are sealed in its event batch.\n    IssueChanged { issue: ForgeEntityId },\n    PullRequestReviewed {\n        /// The independent')
    replace(i,'| Self::PullRequestUpdated { .. } | Self::PullRequestReviewed { .. } => None,','| Self::PullRequestUpdated { .. } | Self::PullRequestReviewed { .. } | Self::IssueChanged { .. } => None,')
    replace(i,'            Self::PullRequestReviewed { review, .. } => *review,','            Self::PullRequestReviewed { review, .. } => *review,\n            Self::IssueChanged { issue } => *issue,')
    t='crates/fgit-reference/src/trace.rs'
    replace(t,'        ForgeEventKind::PullRequestReviewed { review, target } => {','        ForgeEventKind::IssueChanged { issue } => {\n            out.write_raw_byte(6); write_slug(out, "ForgeEntityId", issue.label())?;\n        }\n        ForgeEventKind::PullRequestReviewed { review, target } => {')
    replace(t,'        other => malformed("ForgeEventKind", u64::from(other)),','        6 => Ok(ForgeEventKind::IssueChanged { issue: ForgeEntityId::new(read_slug(input, "ForgeEntityId")?) }),\n        other => malformed("ForgeEventKind", u64::from(other)),')
    replace('crates/fgit-reference/src/transition.rs','            ForgeEventKind::PullRequestClosed { .. } => None,','            ForgeEventKind::PullRequestClosed { .. } | ForgeEventKind::IssueChanged { .. } => None,')
    git('diff','--check',cwd=work)
    assert set(git('diff','--name-only',cwd=work).splitlines())|set(git('ls-files','--others','--exclude-standard',cwd=work).splitlines())==changed
    git('config','user.name','Jeff Emanuel',cwd=work);git('config','user.email','35050222+Dicklesworthstone@users.noreply.github.com',cwd=work)
    git('add','--',*sorted(changed),cwd=work)
    git('commit','-m','feat(forge): add canonical issue lifecycle and stable explicit edit commands','-m','Add disjoint issue aggregate kind 4 and event kind 8 without changing historical encodings. Open/edit/comment/close/reopen replay uses exact predecessor versions; label sets and text are bounded and actor identity is supplied by admission. Reference fold and trace retain issue events without requiring a ref effect. This is the complete issue vocabulary and pure replay increment; durable node and CLI integration follows separately.',cwd=work)
    source=git('rev-parse','HEAD',cwd=work);branch='tooling/issue-source-'+os.environ['GITHUB_SHA'][:12]
    git('push','origin',source+':refs/heads/'+branch,cwd=work)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:out.write('source='+source+'\n')
    print('PRODUCT_SOURCE',source,branch,flush=True)
