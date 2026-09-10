//! Candidate review lifecycle and explicit review-gated local publication.
//! All authority belongs to the node. This CLI never counts cached approvals.
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use fgit_authority::{IdempotencyKey, TerminalOutcome};
use fgit_forge::{AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_forge::event::review::{CandidateBinding, CandidateReviewCommand, NativeReviewEvent,
    ReviewCommand, ReviewDecision, ReviewSubject, MAX_REVIEW_REASON_BYTES, CANDIDATE_REVIEW_PROFILE, REVIEW_PROFILE};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_types::{CANONICAL_CODEC_VERSION, DecisionOutcome, DigestAlgorithmId, DigestBytes,
    GitHashAlgorithm, HeadGeneration, PolicyEpoch, PrincipalId, RefName,
    RepositoryAuthorityHeadId, RepositoryId, TenantId, TxId};
use super::publication_support::{describe, parse_oid, quote, read_bundle, write_terminal_receipt};

const MAX_JSON: usize = 4 * 1024 * 1024;
const USAGE: &str = "\
usage: fg pr review <storage-root> <tenant-id> <repository-id> <pr-number> --trusted-local
  --principal <reviewer-id> --idempotency-key <key> --expected-version <pr-version>
  --review-version <own-stream-version; 0=new> --decision approve|request-changes|withdraw
  --source-ref <branch> --target-ref <branch> --source-tip <oid> --target-tip <oid>
  --merge-base <oid> --candidate <oid> --policy-epoch <n> [--reason <text>]
  [--bundle <path>; required except withdrawal]
usage: fg pr reviews <storage-root> <tenant-id> <repository-id> <pr-number> --trusted-local
  [--object-format sha1|sha256] [--limit <1..100>]
  [--after <reviewer-id> --expected-head <snapshot-token>]
usage: fg merge apply-reviewed <storage-root> <tenant-id> <repository-id> <pr-number> --trusted-local
  --principal <submitter-id> --idempotency-key <key> --expected-version <pr-version>
  --source-ref <branch> --target-ref <branch> --source-tip <oid> --target-tip <oid>
  --merge-base <oid> --candidate <oid> --policy-epoch <n> --bundle <path>
  --require-reviewer <id> [--require-reviewer <id> ...]

Reviews bind the actual merge commit, not merely its source branch. Every named
reviewer must approve that exact candidate and current PR/policy version. Opener
and submitter votes cannot satisfy apply-reviewed. This is an explicit sealed
request precondition, NOT repository-wide protected-ref configuration; existing
trusted-local merge/push APIs are not disabled. Local operator authorization is
required. Exit 0: committed mutation/complete page; 3: canonical refusal;
4: PR absent or hidden; 2: input/infrastructure/output error, not non-commit.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode { Review, Reviews, Apply }
#[derive(Debug)]
struct Scope { storage: PathBuf, tenant: TenantId, repository: RepositoryId, number: PullRequestNumber }
#[derive(Debug)]
struct Mutation {
    scope: Scope, principal: PrincipalId, key: Vec<u8>,
    command: CandidateReviewCommand, bundle: Option<PathBuf>, reviewers: Vec<PrincipalId>,
}
#[derive(Debug)]
struct ReadOptions {
    scope: Scope, format: GitHashAlgorithm, after: Option<PrincipalId>, limit: u16,
    head: Option<RepositoryAuthorityHeadId>,
}

pub(super) fn run(args: &[String], mode: Mode) -> Result<u8, String> {
    if args == ["--help"] { emit(&mut std::io::stdout().lock(), USAGE)?; return Ok(0); }
    if mode == Mode::Reviews { return run_read(parse_read(args)?); }
    let options = parse_mutation(args, mode)?;
    let input = options.bundle.as_ref().map(|path| read_bundle(path, 128 * 1024 * 1024)).transpose()?;
    let mut node = OneNode::open_existing(NodeConfig::new(options.scope.storage.clone(),
        options.scope.tenant, options.scope.repository).with_object_format(options.command.review.subject.source_tip.algorithm()))
        .map_err(|e| e.to_string())?;
    let operation = (|| -> Result<_, String> {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|e| e.to_string())?;
        let request = node.request_context();
        if mode == Mode::Review {
            let session = LoopbackReceiveSession::authenticated(options.principal,
                IdempotencyKey::new(options.key.clone()).map_err(|e| e.to_string())?);
            node.runtime().block_on(node.admit_candidate_review_durable_in(&request, &session,
                &options.command, input.as_deref(), Default::default())).map_err(|e| e.to_string())
        } else {
            let subject = &options.command.review.subject;
            node.runtime().block_on(node.apply_reviewed_merge_bundle_durable_in(&request,
                options.principal, &options.key, subject.pull_request, ExpectedVersion::Exactly(subject.pull_request_version),
                &options.command.candidate.merge(subject), input.as_deref().ok_or("reviewed merge requires bundle bytes")?,
                subject.policy_epoch, &options.reviewers)).map_err(|e| e.to_string())
        }
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let (tx, terminal) = operation.map_err(|error| format!(
        "no terminal outcome returned: {error}{}; this is not evidence of non-commit. Reconcile the identical request, principal and key; do not silently change reviewers or candidate",
        cleanup.as_ref().map_or_else(String::new, |e| format!("; node shutdown also failed: {e}"))))?;
    let receipt = render_terminal(&options, mode, tx, &terminal, cleanup.as_deref());
    if let Err(error) = write_terminal_receipt(&mut std::io::stdout().lock(), &receipt, tx, &terminal) {
        return Err(format!("{error}{}", cleanup.as_ref().map_or_else(String::new, |e| format!("; node shutdown also failed: {e}"))));
    }
    if let Some(error) = cleanup { return Err(format!("{}; node shutdown failed: {error}", describe(tx,&terminal))); }
    Ok(if matches!(terminal.outcome, DecisionOutcome::Committed { .. }) { 0 } else { 3 })
}

fn flags(args: &[String], mode: Mode) -> Result<(Scope, BTreeMap<&str,&str>, Vec<PrincipalId>),String> {
    if args.len() < 4 { return Err(USAGE.into()); }
    if args.len() > 128 || args.iter().any(|arg| arg.len() > 32 * 1024)
        || args.iter().map(String::len).sum::<usize>() > 128 * 1024
        || args[0].is_empty() || args[0].len() > 4096
    { return Err("review arguments exceed the bounded profile".into()); }
    let scope = Scope { storage: args[0].clone().into(),
        tenant: TenantId::from_hex(&args[1]).map_err(|_| "invalid tenant")?,
        repository: RepositoryId::from_hex(&args[2]).map_err(|_| "invalid repository")?,
        number: PullRequestNumber::try_new(decimal(&args[3])?).ok_or("PR number must be positive")? };
    let mut flags = BTreeMap::new(); let mut reviewers = BTreeSet::new(); let mut at = 4;
    while at < args.len() {
        let flag = args[at].as_str(); at += 1;
        let allowed = flag == "--trusted-local" || if mode == Mode::Reviews {
            matches!(flag, "--object-format" | "--after" | "--limit" | "--expected-head")
        } else {
            matches!(flag, "--principal" | "--idempotency-key" | "--expected-version" | "--source-ref"
                | "--target-ref" | "--source-tip" | "--target-tip" | "--merge-base" | "--candidate" | "--policy-epoch" | "--bundle")
                || (mode == Mode::Review && matches!(flag, "--review-version" | "--decision" | "--reason"))
                || (mode == Mode::Apply && flag == "--require-reviewer")
        };
        if !allowed { return Err(format!("unknown or inapplicable option {flag:?}")); }
        let value = if flag == "--trusted-local" { "" } else {
            let value = args.get(at).ok_or_else(|| format!("missing value for {flag}"))?; at += 1; value.as_str()
        };
        if flag == "--require-reviewer" {
            if reviewers.len() == 32 { return Err("at most 32 required reviewers".into()); }
            let reviewer = PrincipalId::from_hex(value).map_err(|_| "invalid required reviewer")?;
            if !reviewers.insert(reviewer) { return Err("duplicate required reviewer".into()); }
        } else if flags.insert(flag,value).is_some() { return Err(format!("duplicate {flag}")); }
    }
    if !flags.contains_key("--trusted-local") { return Err("--trusted-local is required; these are authorized local-operator commands".into()); }
    Ok((scope,flags,reviewers.into_iter().collect()))
}
fn required<'a>(flags: &BTreeMap<&str,&'a str>, key: &str) -> Result<&'a str,String> {
    flags.get(key).copied().ok_or_else(|| format!("{key} is required"))
}
fn parse_mutation(args: &[String], mode: Mode) -> Result<Mutation,String> {
    if mode == Mode::Reviews { return Err("read mode is not a mutation".into()); }
    let (scope, flags, reviewers) = flags(args, mode)?;
    let principal = PrincipalId::from_hex(required(&flags,"--principal")?).map_err(|_| "invalid principal")?;
    let key = required(&flags,"--idempotency-key")?.as_bytes().to_vec();
    IdempotencyKey::new(key.clone()).map_err(|_| "invalid bounded idempotency key")?;
    let pr_version = AggregateVersion::try_new(decimal(required(&flags,"--expected-version")?)?).ok_or("PR version must be positive")?;
    if mode == Mode::Apply { pr_version.next().map_err(|_| "PR version exhausted")?; }
    let subject = ReviewSubject { pull_request: scope.number, pull_request_version: pr_version,
        source_ref: RefName::try_new(required(&flags,"--source-ref")?.as_bytes()).map_err(|_| "invalid source ref")?,
        target_ref: RefName::try_new(required(&flags,"--target-ref")?.as_bytes()).map_err(|_| "invalid target ref")?,
        source_tip: parse_oid(required(&flags,"--source-tip")?)?, target_tip: parse_oid(required(&flags,"--target-tip")?)?,
        policy_epoch: PolicyEpoch::try_new(decimal(required(&flags,"--policy-epoch")?)?).map_err(|_| "invalid policy epoch")? };
    let candidate = CandidateBinding { merge_base: parse_oid(required(&flags,"--merge-base")?)?,
        commit: parse_oid(required(&flags,"--candidate")?)? };
    candidate.validate(&subject).map_err(|e| e.to_string())?;
    let (expected_version, decision, reason) = if mode == Mode::Review {
        let version = decimal(required(&flags,"--review-version")?)?;
        let version = if version == 0 { ExpectedVersion::NewStream } else {
            let old = AggregateVersion::try_new(version).ok_or("invalid reviewer version")?;
            old.next().map_err(|_| "reviewer version exhausted")?; ExpectedVersion::Exactly(old)
        };
        let decision = match required(&flags,"--decision")? {
            "approve" => ReviewDecision::Approve, "request-changes" => ReviewDecision::RequestChanges,
            "withdraw" => ReviewDecision::Withdraw, _ => return Err("unknown review decision".into()),
        };
        let reason = flags.get("--reason").copied().unwrap_or("");
        if reason.len() > MAX_REVIEW_REASON_BYTES { return Err("review reason exceeds 16 KiB".into()); }
        (version, decision, reason.to_owned())
    } else {
        if reviewers.is_empty() { return Err("--require-reviewer is required; no ungated fallback exists in apply-reviewed".into()); }
        if reviewers.contains(&principal) { return Err("submitter cannot be a required reviewer".into()); }
        (ExpectedVersion::NewStream, ReviewDecision::Approve, String::new())
    };
    let command = CandidateReviewCommand { candidate, review: ReviewCommand { expected_version, subject, decision, reason } };
    command.proposed_event(principal, command.review.subject.source_tip.algorithm()).map_err(|_| "invalid review subject or decision")?;
    let bundle = flags.get("--bundle").map(|path| {
        if path.is_empty() || path.len() > 4096 { Err("invalid bundle path".to_owned()) }
        else { Ok(PathBuf::from(*path)) }
    }).transpose()?;
    if mode == Mode::Review && decision == ReviewDecision::Withdraw {
        if bundle.is_some() { return Err("withdrawal needs the exact prior subject, not bundle bytes".into()); }
    } else if bundle.is_none() { return Err("--bundle is required for new approvals/change requests and reviewed publication".into()); }
    Ok(Mutation { scope, principal, key, command, bundle, reviewers })
}
fn parse_read(args: &[String]) -> Result<ReadOptions,String> {
    let (scope,flags,_) = flags(args,Mode::Reviews)?;
    let format = match flags.get("--object-format").copied().unwrap_or("sha1") {
        "sha1" => GitHashAlgorithm::Sha1, "sha256" => GitHashAlgorithm::Sha256, _ => return Err("invalid object format".into()),
    };
    let limit = flags.get("--limit").map_or(Ok(50), |s| decimal(s))?;
    if limit == 0 || limit > 100 { return Err("limit must be 1 through 100".into()); }
    let after = flags.get("--after").map(|s| PrincipalId::from_hex(s).map_err(|_| "invalid reviewer cursor".to_owned())).transpose()?;
    let head = flags.get("--expected-head").map(|s| parse_head(s)).transpose()?;
    if after.is_some() && head.is_none() { return Err("review continuation requires --expected-head from the first page".into()); }
    Ok(ReadOptions { scope,format,after,limit:limit as u16,head })
}

fn run_read(options: ReadOptions) -> Result<u8,String> {
    let mut node = OneNode::open_existing(NodeConfig::new(options.scope.storage.clone(), options.scope.tenant,
        options.scope.repository).with_object_format(options.format)).map_err(|e| e.to_string())?;
    let operation = (|| -> Result<_,String> {
        node.bring_into_service(HeadGeneration::FIRST).map_err(|e| e.to_string())?;
        let request = node.request_context();
        node.runtime().block_on(node.read_reviews_in(&request, &Default::default(), options.scope.number,
            options.after, options.limit, options.head)).map_err(|e| e.to_string())
    })();
    let cleanup = node.shutdown().err().map(|e| e.to_string());
    let answer = match (operation,cleanup) {
        (Ok(answer),None) => answer,
        (Err(error),None) => return Err(error),
        (Ok(_),Some(error)) => return Err(format!("review node shutdown failed: {error}")),
        (Err(error),Some(cleanup)) => return Err(format!("{error}; node shutdown also failed: {cleanup}")),
    };
    let scope = scope_fields(&options.scope);
    let Some(page) = answer else {
        emit(&mut std::io::stdout().lock(), &format!("{{\"type\":\"pull_request_reviews\",{scope},\"found\":false,\"node_closed\":true}}"))?;
        return Ok(4);
    };
    if page.pull_request != options.scope.number || options.head.is_some_and(|head| head != page.source_head)
        || page.reviews.len() > usize::from(options.limit)
        || page.reviews.windows(2).any(|p| p[0].event.reviewer >= p[1].event.reviewer)
        || page.reviews.iter().any(|v| options.after.is_some_and(|a| v.event.reviewer <= a)
            || v.event.subject.pull_request != options.scope.number
            || v.event.subject.source_tip.algorithm() != options.format)
        || (page.next_after.is_some() && (page.reviews.len() != usize::from(options.limit)
            || page.next_after != page.reviews.last().map(|v| v.event.reviewer)))
    { return Err("review page binding/order mismatch".into()); }
    let rows = page.reviews.iter().map(|view| {
        format!("{{{},\"review_version\":{},\"freshness\":{},\"reviewer_is_opener\":{}}}",
            review_fields(&view.event), view.version.get(), quote(&format!("{:?}",view.freshness)),
            view.reviewer_is_opener.map_or_else(|| "null".into(), |v| v.to_string()))
    }).collect::<Vec<_>>().join(",");
    let text = format!(concat!("{{\"type\":\"pull_request_reviews\",\"schema_version\":1,{},\"found\":true,",
        "\"page_complete\":true,\"complete\":{},\"node_closed\":true,\"published_to_repository\":false,",
        "\"source_head\":{},\"snapshot_token\":{},\"pull_request_version\":{},\"policy_epoch\":{},",
        "\"next_after\":{},\"approvals_satisfy_policy\":null,\"reviews\":[{}]}}"),
        scope, page.next_after.is_none(), quote(&page.source_head.to_string()), quote(&head_token(page.source_head)),
        page.pull_request_version.get(), page.policy_epoch.get(),
        page.next_after.map_or_else(|| "null".into(), |id| quote(&id.to_string())),rows);
    emit(&mut std::io::stdout().lock(), &text)?; Ok(0)
}
fn scope_fields(scope: &Scope) -> String {
    format!("\"tenant_id\":{},\"repository_id\":{},\"pull_request\":{}", quote(&scope.tenant.to_string()),
        quote(&scope.repository.to_string()), scope.number.get())
}
fn subject_fields(subject: &ReviewSubject, candidate: Option<CandidateBinding>) -> String {
    format!(concat!("\"pull_request_version\":{},\"source_reference_hex\":{},\"target_reference_hex\":{},",
        "\"source_tip\":{},\"target_tip\":{},\"policy_epoch\":{},\"candidate_commit\":{},\"merge_base\":{}"),
        subject.pull_request_version.get(), quote(&hex(subject.source_ref.as_bytes())), quote(&hex(subject.target_ref.as_bytes())),
        quote(&subject.source_tip.to_string()), quote(&subject.target_tip.to_string()),subject.policy_epoch.get(),
        candidate.map_or_else(|| "null".into(), |c| quote(&c.commit.to_string())),
        candidate.map_or_else(|| "null".into(), |c| quote(&c.merge_base.to_string())))
}
fn decision_name(decision: ReviewDecision) -> &'static str {
    match decision { ReviewDecision::Approve => "approve", ReviewDecision::RequestChanges => "request-changes", ReviewDecision::Withdraw => "withdraw" }
}
fn review_fields(review: &NativeReviewEvent) -> String {
    format!("{},\"reviewer\":{},\"decision\":{},\"reason\":{},\"profile\":{}",
        subject_fields(&review.subject,review.candidate), quote(&review.reviewer.to_string()), quote(decision_name(review.decision)),
        quote(&review.reason), quote(if review.candidate.is_some() { CANDIDATE_REVIEW_PROFILE } else { REVIEW_PROFILE }))
}
fn render_terminal(options: &Mutation, mode: Mode, tx: TxId, terminal: &TerminalOutcome, cleanup: Option<&str>) -> String {
    let (status,published,rcr,code,refused) = match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => ("committed",true,quote(&repository_commit_id.to_string()),"null".into(),"null".into()),
        DecisionOutcome::Refused { code,refusal_record_id } => ("refused",false,"null".into(),quote(&format!("{code:?}")),quote(&refusal_record_id.to_string())),
    };
    let version = match options.command.review.expected_version { ExpectedVersion::NewStream => 0, ExpectedVersion::Exactly(v) => v.get() };
    format!(concat!("{{\"schema_version\":1,\"type\":{},\"profile\":{}, {}, {},\"principal\":{},",
        "\"decision\":{},\"expected_review_version\":{},\"required_reviewers\":[{}],",
        "\"outcome\":{},\"published_to_repository\":{},\"git_refs_changed\":{},",
        "\"tx_id\":{},\"decision_sequence\":{},\"repository_commit_id\":{},",
        "\"refusal_code\":{},\"refusal_record_id\":{},\"node_closed\":{},\"cleanup_error\":{},",
        "\"delivery_acknowledged\":null,\"repository_wide_branch_protection\":false}}"),
        quote(if mode == Mode::Review { "candidate_review" } else { "reviewed_merge_publication" }),
        quote(if mode == Mode::Review { CANDIDATE_REVIEW_PROFILE } else { "named-candidate-reviewers-v1" }),
        scope_fields(&options.scope), subject_fields(&options.command.review.subject,Some(options.command.candidate)),
        quote(&options.principal.to_string()),
        if mode == Mode::Review { quote(decision_name(options.command.review.decision)) } else { "null".into() },
        if mode == Mode::Review { version.to_string() } else { "null".into() },
        options.reviewers.iter().map(|id| quote(&id.to_string())).collect::<Vec<_>>().join(","),
        quote(status),published,published && mode == Mode::Apply,quote(&tx.to_string()),terminal.decision_sequence.get(),
        rcr,code,refused,cleanup.is_none(),cleanup.map_or_else(|| "null".into(),quote))
}
fn emit(output: &mut impl Write, text: &str) -> Result<(),String> {
    if text.len() > MAX_JSON { return Err("review JSON exceeds the bounded response profile".into()); }
    writeln!(output,"{text}").and_then(|()| output.flush()).map_err(|e| format!("review output incomplete: {e}"))
}
fn decimal(text: &str) -> Result<u64,String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) || (text.len()>1 && text.starts_with('0')) {
        return Err("expected canonical unsigned decimal".into());
    }
    text.parse().map_err(|_| "integer overflow".into())
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn head_token(head: RepositoryAuthorityHeadId) -> String {
    let id = head.as_internal_object_id(); format!("alg:{}:{}",id.algorithm().code_point(),hex(id.digest().as_bytes()))
}
fn parse_head(text: &str) -> Result<RepositoryAuthorityHeadId,String> {
    let (algorithm,digest) = text.strip_prefix("head:").unwrap_or(text).strip_prefix("alg:")
        .and_then(|s| s.split_once(':')).ok_or("expected algorithm-qualified snapshot token")?;
    let algorithm = DigestAlgorithmId::try_new(u16::try_from(decimal(algorithm)?).map_err(|_| "algorithm overflow")?).map_err(|_| "invalid algorithm")?;
    if digest.is_empty() || digest.len()>128 || digest.len()%2!=0 || !digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("invalid bounded lowercase head digest".into());
    }
    let digit = |b| if b<=b'9' { b-b'0' } else { b-b'a'+10 };
    let bytes:Vec<_> = digest.as_bytes().chunks_exact(2).map(|p| digit(p[0])*16+digit(p[1])).collect();
    let digest = DigestBytes::try_new(&bytes).map_err(|_| "invalid digest width")?;
    Ok(RepositoryAuthorityHeadId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(width:usize,mode:Mode) -> Vec<String> {
        let mut args = vec!["node".into(),"11".repeat(16),"22".repeat(16),"17".into(),"--trusted-local".into(),
            "--principal".into(),"33".repeat(16),"--idempotency-key".into(),"private-key".into(),
            "--expected-version".into(),"1".into(),"--source-ref".into(),"refs/heads/topic".into(),
            "--target-ref".into(),"refs/heads/main".into(),"--source-tip".into(),"a".repeat(width),
            "--target-tip".into(),"b".repeat(width),"--merge-base".into(),"c".repeat(width),
            "--candidate".into(),"d".repeat(width),"--policy-epoch".into(),"1".into(),"--bundle".into(),"candidate.bundle".into()];
        if mode == Mode::Review { args.extend(["--review-version".into(),"0".into(),"--decision".into(),"approve".into()]); }
        else { args.extend(["--require-reviewer".into(),"44".repeat(16)]); } args
    }
    fn change(args:&mut [String],flag:&str,value:&str) {
        let at = args.iter().position(|a| a==flag).unwrap(); args[at+1]=value.into();
    }
    #[test]
    fn every_candidate_coordinate_is_explicit_and_both_hash_formats_are_supported() {
        for mode in [Mode::Review,Mode::Apply] { for width in [40,64] {
            let good=args(width,mode); assert_eq!(parse_mutation(&good,mode).unwrap().command.candidate.commit.to_string(),"d".repeat(width));
            for flag in ["--principal","--idempotency-key","--expected-version","--source-ref","--target-ref",
                "--source-tip","--target-tip","--merge-base","--candidate","--policy-epoch","--bundle"] {
                let mut bad=good.clone(); let at=bad.iter().position(|a|a==flag).unwrap(); bad.drain(at..at+2); assert!(parse_mutation(&bad,mode).is_err(),"{flag}");
                let mut bad=good.clone(); let at=bad.iter().position(|a|a==flag).unwrap(); bad.extend([flag.into(),bad[at+1].clone()]); assert!(parse_mutation(&bad,mode).is_err());
            }
            let mut bad=good.clone(); change(&mut bad,"--source-tip",&"a".repeat(if width==40 {64}else{40})); assert!(parse_mutation(&bad,mode).is_err());
            let mut bad=good.clone(); bad.retain(|a|a!="--trusted-local"); assert!(parse_mutation(&bad,mode).is_err());
        } }
    }
    #[test]
    fn withdrawal_and_named_reviewers_have_no_implicit_fallback() {
        let mut withdraw=args(40,Mode::Review); change(&mut withdraw,"--decision","withdraw"); change(&mut withdraw,"--review-version","1");
        withdraw.extend(["--reason".into(),"retract exact candidate".into()]);
        assert!(parse_mutation(&withdraw,Mode::Review).is_err());
        let at=withdraw.iter().position(|a|a=="--bundle").unwrap(); withdraw.drain(at..at+2);
        assert!(parse_mutation(&withdraw,Mode::Review).is_ok());
        change(&mut withdraw,"--review-version","0"); assert!(parse_mutation(&withdraw,Mode::Review).is_err());
        let mut apply=args(40,Mode::Apply); apply.extend(["--require-reviewer".into(),"44".repeat(16)]); assert!(parse_mutation(&apply,Mode::Apply).is_err());
        let mut apply=args(40,Mode::Apply); change(&mut apply,"--require-reviewer",&"33".repeat(16)); assert!(parse_mutation(&apply,Mode::Apply).is_err());
        let mut apply=args(40,Mode::Apply); apply.truncate(apply.len()-2); assert!(parse_mutation(&apply,Mode::Apply).is_err());
    }
    #[test]
    fn continuations_require_the_original_head_and_tokens_roundtrip() {
        let mut read=vec!["node".into(),"11".repeat(16),"22".repeat(16),"17".into(),"--trusted-local".into()];
        assert!(parse_read(&read).is_ok()); read.extend(["--after".into(),"44".repeat(16)]); assert!(parse_read(&read).is_err());
        let head=RepositoryAuthorityHeadId::from_digest(DigestAlgorithmId::try_new(2).unwrap(),CANONICAL_CODEC_VERSION,DigestBytes::try_new(&[7;32]).unwrap());
        assert_eq!(parse_head(&head_token(head)).unwrap(),head);
        read.extend(["--expected-head".into(),head_token(head)]); assert_eq!(parse_read(&read).unwrap().head,Some(head));
        read.extend(["--limit".into(),"0".into()]); assert!(parse_read(&read).is_err());
    }
    #[test]
    fn terminal_receipts_keep_commits_and_cleanup_failures_without_leaking_retry_keys() {
        use fgit_types::{DecisionSequence,RepositoryCommitId};
        let algorithm=DigestAlgorithmId::try_new(2).unwrap(); let digest=DigestBytes::try_new(&[7;32]).unwrap();
        let tx=TxId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest);
        let terminal=TerminalOutcome {decision_sequence:DecisionSequence::try_new(3).unwrap(),outcome:DecisionOutcome::Committed {
            repository_commit_id:RepositoryCommitId::from_digest(algorithm,CANONICAL_CODEC_VERSION,digest)}};
        let options=parse_mutation(&args(40,Mode::Apply),Mode::Apply).unwrap();
        let text=render_terminal(&options,Mode::Apply,tx,&terminal,Some("close\nfailed"));
        assert!(text.contains("\"outcome\":\"committed\"")); assert!(text.contains("\"git_refs_changed\":true"));
        assert!(text.contains("\"node_closed\":false")); assert!(text.contains("close\\u000afailed")); assert!(!text.contains("private-key"));
        assert!(text.contains("\"repository_wide_branch_protection\":false"));
        struct Fail; impl Write for Fail {
            fn write(&mut self,_:&[u8])->std::io::Result<usize>{Err(std::io::Error::other("write failed"))}
            fn flush(&mut self)->std::io::Result<()>{Ok(())}
        }
        let error=write_terminal_receipt(&mut Fail,&text,tx,&terminal).unwrap_err(); assert!(error.contains("committed"));
        assert!(emit(&mut Fail,"read page").is_err());
    }
}
