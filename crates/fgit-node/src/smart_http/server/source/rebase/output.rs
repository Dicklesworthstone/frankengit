//! Complete bounded rebase reports. Provisional step IDs at a stop are
//! explanations only: no intermediate pack or publishable candidate escapes.

use std::collections::BTreeSet;
use fgit_admission::AdmissionResult;
use fgit_forge::preparation::{ConflictKind, MergeConflict, MergeEntry};
use fgit_forge::preparation::rebase::{EmptyCommitPolicy, RebasePreparation, RebaseStep, RebaseStepKind, RebaseStop};
use fgit_types::{DecisionOutcome, GitHashAlgorithm, GitOid, PrincipalId, RepositoryAuthorityHeadId};
use crate::OneNode;
use super::request::{Apply, Prepare};
use super::super::artifact::{Bundle, PreparedReply, append, checkpoint, hex};
use super::super::super::{Status, issues::{ApiError, Reply, quote, ref_fields}};

fn valid(format: GitHashAlgorithm, oid: GitOid) -> bool { !oid.is_zero() && oid.algorithm() == format }
fn scope(node: &OneNode) -> String {
    format!("\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"object_format\":{}",
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()))
}

pub(super) fn build(node: &OneNode, command: &Prepare, head: RepositoryAuthorityHeadId,
    outcome: &RebasePreparation, bundle: Option<Vec<u8>>, counts: (usize, usize),
    maximum: usize, live: &mut impl FnMut() -> bool,
) -> Result<PreparedReply, ApiError> {
    checkpoint(live)?;
    if command.expected_head.is_some_and(|expected| expected != head) { return Err(ApiError::unavailable()); }
    let (request, steps) = match outcome {
        RebasePreparation::Clean(plan) => (&plan.request, plan.steps.as_slice()),
        RebasePreparation::Stopped { request, completed, .. } => (request, completed.as_slice()),
    };
    if *request != command.inputs || counts.1 > counts.0 || counts.0 > command.limits.max_objects {
        return Err(ApiError::unavailable());
    }
    let frontier = validate_steps(command, steps)?;
    let id = head.as_internal_object_id();
    let token = format!("alg:{}:{}", id.algorithm().code_point(), hex(id.digest().as_bytes()));
    let empty = match request.empty { EmptyCommitPolicy::Stop => "stop", EmptyCommitPolicy::Drop => "drop", EmptyCommitPolicy::Keep => "keep" };
    let mut body = format!(concat!("{{\"type\":\"rebase_preparation\",{},\"source_head\":{},\"snapshot_token\":{},",
        "\"profile\":\"linear-v1\",{},{},\"expected_source\":{},\"upstream\":{},\"onto\":{},\"empty\":{},",
        "\"committer\":{},\"timestamp\":{},\"read_only\":true,\"objects_staged\":false,",
        "\"transaction_created\":false,\"published\":false,\"publication_authorized\":false,",
        "\"original_authors_preserved\":true,\"original_messages_preserved\":true,",
        "\"original_signatures_copied\":false,\"author_identity_verified\":false,"),
        scope(node), quote(&head.to_string()), quote(&token), ref_fields("source_ref", &command.source),
        ref_fields("onto_ref", &command.onto_ref), quote(&request.source_tip.to_string()),
        quote(&request.upstream.to_string()), quote(&request.onto.to_string()), quote(empty),
        quote(&command.committer.identity), command.committer.timestamp);
    let (status, bundle) = match outcome {
        RebasePreparation::Clean(plan) => {
            if !valid(node.object_format, plan.commit) || !valid(node.object_format, plan.tree)
                || frontier != plan.commit || plan.objects.len() > command.limits.max_objects
                || steps.last().is_some_and(|step| step.original != request.source_tip || step.tree != plan.tree)
                || (steps.is_empty() && request.source_tip != request.upstream)
            { return Err(ApiError::unavailable()); }
            let bundle = Bundle::new(bundle.ok_or_else(ApiError::unavailable)?, live)?;
            if bundle.len() > command.limits.max_output_bytes { return Err(ApiError::too_large()); }
            append(&mut body, &format!(concat!("\"state\":\"clean\",\"series_complete\":true,\"provisional_steps\":false,",
                "\"candidate_commit\":{},\"root_tree\":{},\"generated_objects\":{},\"pack_objects\":{},",
                "\"borrowed_objects\":{},\"bundle\":{{\"bytes\":{},\"sha256\":{}}},",
                "\"stopped_commit\":null,\"conflicts\":[],"), quote(&plan.commit.to_string()),
                quote(&plan.tree.to_string()), plan.objects.len(), counts.0, counts.1, bundle.len(), quote(&bundle.digest_hex())))?;
            (Status::Success, Some(bundle))
        }
        RebasePreparation::Stopped { original, reason, .. } => {
            if bundle.is_some() || counts != (0, 0) || !valid(node.object_format, *original)
                || *original == request.upstream || steps.iter().any(|step| step.original == *original)
            { return Err(ApiError::unavailable()); }
            let state = match reason { RebaseStop::Conflicted(_) => "conflicted", RebaseStop::BecameEmpty => "became_empty" };
            append(&mut body, &format!(concat!("\"state\":{},\"series_complete\":false,\"provisional_steps\":true,",
                "\"candidate_commit\":null,\"root_tree\":null,\"bundle\":null,\"stopped_commit\":{},\"conflicts\":["),
                quote(state), quote(&original.to_string())))?;
            if let RebaseStop::Conflicted(conflicts) = reason {
                if conflicts.is_empty() || conflicts.len() > command.limits.max_conflicts
                    || conflicts.windows(2).any(|pair| pair[0].path >= pair[1].path)
                { return Err(ApiError::unavailable()); }
                for (index, conflict) in conflicts.iter().enumerate() {
                    checkpoint(live)?;
                    if index != 0 { append(&mut body, ",")?; }
                    append_conflict(&mut body, conflict, command)?;
                }
            }
            append(&mut body, "],")?;
            (Status::Conflict, None)
        }
    };
    append(&mut body, &format!("\"step_count\":{},\"steps\":[", steps.len()))?;
    for (index, step) in steps.iter().enumerate() {
        checkpoint(live)?;
        let kind = match step.kind { RebaseStepKind::Replayed => "replayed", RebaseStepKind::PreservedEmpty => "preserved_empty", RebaseStepKind::DroppedEmpty => "dropped_empty" };
        append(&mut body, &format!("{}{{\"original\":{},\"rewritten\":{},\"tree\":{},\"kind\":{}}}",
            if index == 0 { "" } else { "," }, quote(&step.original.to_string()),
            quote(&step.rewritten.to_string()), quote(&step.tree.to_string()), quote(kind)))?;
    }
    append(&mut body, "]}")?;
    PreparedReply::build(body, bundle, status, maximum, live)
}
fn validate_steps(command: &Prepare, steps: &[RebaseStep]) -> Result<GitOid, ApiError> {
    if steps.len() > command.limits.max_commits { return Err(ApiError::unavailable()); }
    let format = command.inputs.source_tip.algorithm();
    let mut seen = BTreeSet::new();
    let mut parent = command.inputs.onto;
    let mut tree = None;
    for step in steps {
        if [step.original, step.rewritten, step.tree].iter().any(|id| !valid(format, *id))
            || step.original == command.inputs.upstream || !seen.insert(step.original)
        { return Err(ApiError::unavailable()); }
        if step.kind == RebaseStepKind::DroppedEmpty {
            if command.inputs.empty != EmptyCommitPolicy::Drop || step.rewritten != parent
                || tree.is_some_and(|previous| previous != step.tree)
            { return Err(ApiError::unavailable()); }
        } else if step.rewritten == parent { return Err(ApiError::unavailable()); }
        parent = step.rewritten;
        tree = Some(step.tree);
    }
    Ok(parent)
}
pub(super) fn entry(value: Option<&MergeEntry>, format: GitHashAlgorithm) -> Result<String, ApiError> {
    value.map_or_else(|| Ok("null".into()), |e| {
        if !valid(format, e.oid) || !matches!(e.mode, 0o040000 | 0o100644 | 0o100755 | 0o120000 | 0o160000) {
            return Err(ApiError::unavailable());
        }
        Ok(format!("{{\"mode\":{},\"oid\":{}}}", e.mode, quote(&e.oid.to_string())))
    })
}
pub(super) fn append_conflict(out: &mut String, conflict: &MergeConflict, command: &Prepare) -> Result<(), ApiError> {
    let path = &conflict.path;
    if path.is_empty() || path.len() > command.limits.max_path_bytes || path.contains(&0)
        || path.split(|b| *b == b'/').any(|p| p.is_empty() || p == b"." || p == b"..")
    { return Err(ApiError::unavailable()); }
    let kind = match conflict.kind { ConflictKind::Content => "content", ConflictKind::Binary => "binary",
        ConflictKind::ModifyDelete => "modify_delete", ConflictKind::TypeChange => "type_change",
        ConflictKind::Mode => "mode", ConflictKind::Opaque => "opaque", ConflictKind::AttributesRequireDriver => "attributes_require_driver" };
    let format = command.inputs.source_tip.algorithm();
    append(out, &format!("{{\"path_hex\":{},\"kind\":{},\"base\":{},\"ours\":{},\"theirs\":{}}}",
        quote(&hex(path)), quote(kind), entry(conflict.base.as_ref(), format)?,
        entry(conflict.ours.as_ref(), format)?, entry(conflict.theirs.as_ref(), format)?))
}

pub(super) fn publication(node: &OneNode, principal: PrincipalId, command: &Apply,
    result: AdmissionResult, maximum: usize,
) -> Result<Reply, ApiError> {
    let [row] = result.commands.as_slice() else { return Err(ApiError::unknown()); };
    if !result.session.atomic || result.session.tx_ids.as_slice() != [row.tx_id] { return Err(ApiError::unknown()); }
    let (status, outcome, record, code) = match row.terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => (Status::Success, "committed", quote(&repository_commit_id.to_string()), "null".to_owned()),
        DecisionOutcome::Refused { code, refusal_record_id } => (Status::Conflict, "refused", quote(&refusal_record_id.to_string()), quote(&format!("{code:?}"))),
    };
    let body = format!(concat!("{{\"type\":\"rebase_publication\",{},\"principal_id\":{},{},",
        "\"expected_source\":{},\"onto\":{},\"candidate_commit\":{},\"tx_id\":{},\"outcome\":{},",
        "\"decision_sequence\":{},\"decision_record\":{},\"refusal_code\":{},\"delivery_acknowledged\":null}}"),
        scope(node), quote(&principal.to_string()), ref_fields("ref", &command.reference),
        quote(&command.expected_source.to_string()), quote(&command.onto.to_string()), quote(&command.candidate.to_string()),
        quote(&row.tx_id.to_string()), quote(outcome), row.terminal.decision_sequence.get(), record, code);
    if body.len() > maximum {
        eprintln!("Rebase reply limit after canonical transaction {}; recover the original key", row.tx_id);
        return Err(ApiError::unknown());
    }
    Ok(Reply { status, body, terminal: Some((row.tx_id, row.terminal)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_forge::preparation::{PreparationLimits};
    use fgit_forge::preparation::rebase::{RebaseCommitter, RebaseRequest};
    use fgit_types::RefName;
    fn id(n: u8) -> GitOid { GitOid::from_hex(GitHashAlgorithm::Sha1, &format!("{n:02x}").repeat(20)).unwrap() }
    fn command() -> Prepare {
        Prepare { source: RefName::try_new(b"refs/heads/topic").unwrap(), onto_ref: RefName::try_new(b"refs/heads/main").unwrap(),
            inputs: RebaseRequest { source_tip: id(1), upstream: id(2), onto: id(3), empty: EmptyCommitPolicy::Drop },
            expected_head: None, committer: RebaseCommitter { identity: "Bot <b@example.invalid>".into(), timestamp: 1 }, limits: PreparationLimits::default() }
    }
    #[test]
    fn dropped_steps_cannot_invent_new_tips_or_duplicate_originals() {
        let command = command();
        let dropped = RebaseStep { original: id(1), rewritten: id(3), tree: id(4), kind: RebaseStepKind::DroppedEmpty };
        assert_eq!(validate_steps(&command, &[dropped.clone()]).unwrap(), id(3));
        let mut bad = dropped.clone(); bad.rewritten = id(5);
        assert!(validate_steps(&command, &[bad]).is_err());
        assert!(validate_steps(&command, &[dropped.clone(), dropped]).is_err());
        assert_eq!(validate_steps(&command, &[]).unwrap(), id(3));
    }
    #[test]
    fn conflict_disclosure_preserves_raw_paths_and_refuses_invalid_side_domains() {
        let command = command();
        let mut conflict = MergeConflict { path: b"file\xff".to_vec(), kind: ConflictKind::ModifyDelete,
            base: None, ours: Some(MergeEntry { name: b"file\xff".to_vec(), mode: 0o100644, oid: id(4) }), theirs: None };
        let mut out = String::new(); append_conflict(&mut out, &conflict, &command).unwrap();
        assert!(out.contains("66696c65ff") && out.contains("\"theirs\":null"));
        conflict.ours.as_mut().unwrap().oid = GitOid::from_hex(GitHashAlgorithm::Sha256, &"a".repeat(64)).unwrap();
        assert!(append_conflict(&mut String::new(), &conflict, &command).is_err());
    }
}
