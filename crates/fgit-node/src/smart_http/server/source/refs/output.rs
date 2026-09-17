//! Fully constructed reference responses. A rename has two effects but one
//! authenticated terminal decision. Ref-list tokens are current-head pins,
//! never credentials or permission to read an arbitrary native object.

use fgit_admission::AdmissionResult;
use fgit_authority::{ExpectedOld, ProposedNew, RefCommand, TerminalOutcome};
use fgit_types::{DecisionOutcome, GitOid, PrincipalId, RefName, RepositoryAuthorityHeadId, TxId};

use crate::OneNode;
use super::request::{Operation, Page};
use super::super::super::issues::{ApiError, Reply, quote};
use super::super::super::Status;

pub(super) const MAX_REPLY_BYTES: usize = 1024 * 1024;

fn append(out: &mut String, text: &str, maximum: usize) -> Result<(), ApiError> {
    let end = out.len().checked_add(text.len()).filter(|size| *size <= maximum.min(MAX_REPLY_BYTES))
        .ok_or_else(ApiError::too_large)?;
    if end > out.capacity() {
        out.try_reserve_exact(end - out.len()).map_err(|_| ApiError::unavailable())?;
    }
    out.push_str(text);
    Ok(())
}
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() { Ok(()) } else { Err(ApiError::from_status(Status::Timeout, false)) }
}
fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn optional_ref(reference: Option<&RefName>) -> String {
    reference.map_or_else(|| "null".into(), |reference| quote(reference.as_str()))
}
fn metadata(node: &OneNode) -> String {
    format!(concat!("\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
        "\"repository_incarnation\":{},\"object_format\":{}"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(node.object_format.as_str()))
}

pub(super) fn page(node: &OneNode, query: &Page, head: RepositoryAuthorityHeadId,
    rows: &[(RefName, GitOid)], next: Option<&RefName>, maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, ApiError> {
    checkpoint(live)?;
    if query.expected_head.is_some_and(|expected| expected != head)
        || rows.len() > usize::from(query.limit)
        || rows.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || rows.iter().any(|(name, oid)| name.as_bytes().len() > 4096
            || !name.as_bytes().starts_with(query.namespace.prefix())
            || query.after.as_ref().is_some_and(|after| name <= after)
            || oid.is_zero() || oid.algorithm() != node.object_format)
        || next.is_some_and(|next| rows.len() != usize::from(query.limit)
            || rows.last().map(|(name, _)| name) != Some(next))
    { return Err(ApiError::unavailable()); }
    let internal = head.as_internal_object_id();
    let token = format!("alg:{}:{}", internal.algorithm().code_point(), hex(internal.digest().as_bytes()));
    let mut out = String::new();
    append(&mut out, &format!(concat!("{{\"type\":\"source_refs\",{},\"namespace\":{},",
        "\"source_head\":{},\"snapshot_token\":{},\"after\":{},\"limit\":{},\"next_after\":{},",
        "\"read_only\":true,\"transaction_created\":false,\"published\":false,",
        "\"direct_refs_only\":true,\"refs\":["), metadata(node), quote(query.namespace.as_str()),
        quote(&head.to_string()), quote(&token), optional_ref(query.after.as_ref()), query.limit,
        optional_ref(next)), maximum)?;
    for (index, (name, oid)) in rows.iter().enumerate() {
        checkpoint(live)?;
        append(&mut out, &format!("{}{{\"ref\":{},\"ref_hex\":{},\"object_id\":{}}}",
            if index == 0 { "" } else { "," }, quote(name.as_str()), quote(&hex(name.as_bytes())),
            quote(&oid.to_string())), maximum)?;
    }
    append(&mut out, "]}", maximum)?;
    checkpoint(live)?;
    Ok(out)
}

/// Validate the entire receipt before representing an atomic operation as
/// complete. Two rename commands must not carry different transactions or
/// different outcomes, even if both happen to have committed.
fn atomic_terminal(result: &AdmissionResult, command_count: usize)
    -> Result<(TxId, TerminalOutcome), ApiError>
{
    let [tx] = result.session.tx_ids.as_slice() else { return Err(ApiError::unknown()); };
    let Some(first) = result.commands.first() else { return Err(ApiError::unknown()); };
    if !result.session.atomic || result.commands.len() != command_count || command_count == 0
        || first.tx_id != *tx || result.commands.iter().any(|command| command != first)
    { return Err(ApiError::unknown()); }
    Ok((*tx, first.terminal))
}

pub(super) fn publication(node: &OneNode, principal: PrincipalId, operation: Operation,
    commands: &[RefCommand], result: &AdmissionResult, maximum: usize,
) -> Result<Reply, ApiError> {
    let (tx, terminal) = atomic_terminal(result, commands.len())?;
    let build = || -> Result<String, ApiError> {
        let decision = match terminal.outcome {
            DecisionOutcome::Committed { repository_commit_id } => format!(
                "\"outcome\":\"committed\",\"repository_commit_id\":{}", quote(&repository_commit_id.to_string())),
            DecisionOutcome::Refused { code, refusal_record_id } => format!(
                "\"outcome\":\"refused\",\"code\":{},\"code_point\":{},\"refusal_record_id\":{}",
                quote(&format!("{code:?}")), code.code_point(), quote(&refusal_record_id.to_string())),
        };
        let mut out = String::new();
        append(&mut out, &format!(concat!("{{\"type\":\"branch_publication\",{},\"principal_id\":{},",
            "\"operation\":{},\"atomic\":true,\"terminal\":true,\"tx_id\":{},\"decision_sequence\":{},",
            "{},\"forge_transition\":false,\"updates\":["), metadata(node), quote(&principal.to_string()),
            quote(operation.as_str()), quote(&tx.to_string()), terminal.decision_sequence.get(), decision), maximum)?;
        for (index, command) in commands.iter().enumerate() {
            let old = match command.expected_old {
                ExpectedOld::Absent => "null".into(),
                ExpectedOld::Exactly(oid) => quote(&oid.to_string()),
                ExpectedOld::Unspecified => return Err(ApiError::unknown()),
            };
            let new = match command.proposed_new {
                ProposedNew::Delete => "null".into(), ProposedNew::Update(oid) => quote(&oid.to_string()),
            };
            append(&mut out, &format!("{}{{\"ref\":{},\"expected_commit\":{},\"new_commit\":{},\"force\":false}}",
                if index == 0 { "" } else { "," }, quote(command.name.as_str()), old, new), maximum)?;
        }
        append(&mut out, "]}", maximum)?;
        Ok(out)
    };
    // Publication already has a canonical result. A serialization limit or
    // allocation failure is a LOST RECEIPT, never an admission refusal.
    let body = build().map_err(|_| {
        eprintln!("Branch HTTP receipt unavailable after canonical transaction {tx}; recover the original key");
        ApiError::unknown()
    })?;
    Ok(Reply { status: match terminal.outcome {
        DecisionOutcome::Committed { .. } => Status::Success,
        DecisionOutcome::Refused { .. } => Status::Conflict,
    }, body, terminal: Some((tx, terminal)) })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn size_refusal_does_not_leave_a_successfully_truncated_response() {
        let mut out = "abc".to_owned();
        assert!(append(&mut out, "de", 4).is_err());
        assert_eq!(out, "abc");
        append(&mut out, "d", 4).unwrap();
        assert_eq!(out, "abcd");
        assert!(checkpoint(&mut || false).is_err());
        assert_eq!(hex(b"refs/heads/topic"), "726566732f68656164732f746f706963");
    }
    #[test]
    fn an_empty_or_non_atomic_result_is_never_a_completed_branch_transaction() {
        let result = AdmissionResult {
            session: fgit_admission::SessionMapping { atomic: false, tx_ids: Vec::new() },
            commands: Vec::new(),
        };
        assert!(atomic_terminal(&result, 1).unwrap_err().outcome_unknown);
    }
}
