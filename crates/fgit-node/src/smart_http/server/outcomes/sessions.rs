//! Whole non-atomic session lookup, reusing the one-command receipt vocabulary.

use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_authority::key_recovery::RequestRecovery;
use fgit_types::PrincipalId;

use super::super::issues::ref_fields;
use super::{ApiError, Reply, Status, drive_request_while, quote, render};
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

const MAX_SESSION_REPLY_BYTES: usize = 1024 * 1024;

pub(super) fn execute(
    node: &OneNode,
    session: &LoopbackReceiveSession,
    maximum_response: u64,
) -> Result<Reply, ApiError> {
    let principal = session
        .authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?
        .principal_id();
    let deadline = GitDaemonSessionDeadline::new(
        node.git_daemon_session_timeout,
        GitDaemonSessionWorkScaling::FLAT,
    );
    let context = node.session_request_context(&deadline);
    let report = drive_request_while(
        node,
        &context,
        node.recover_receive_session_in(&context, session),
        &mut || !deadline.expired(),
    )
    .map_err(|_| ApiError::from_status(Status::Unavailable))?;
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(MAX_SESSION_REPLY_BYTES);
    let body = render_session(node, principal, &report, maximum)?;
    let terminal_tx = match &report {
        SessionRecovery::NotObserved => None,
        SessionRecovery::Recovered(session) => {
            session
                .commands()
                .iter()
                .find_map(|command| match command.recovery() {
                    RequestRecovery::Recovered(known)
                        if command.recovery().terminal().is_some() =>
                    {
                        Some(known.tx_id())
                    }
                    _ => None,
                })
        }
    };
    Ok(Reply { body, terminal_tx })
}

fn render_session(
    node: &OneNode,
    principal: PrincipalId,
    report: &SessionRecovery,
    maximum: usize,
) -> Result<String, ApiError> {
    let session = match report {
        SessionRecovery::NotObserved => None,
        SessionRecovery::Recovered(session) => Some(session.as_ref()),
    };
    let all_terminal = session.is_some_and(|session| session.all_terminal());
    let state = if session.is_none() {
        "session_not_observed"
    } else if all_terminal {
        "complete"
    } else {
        "partial"
    };
    let header = format!(
        concat!(
            "{{\"type\":\"receive_session_outcome\",\"schema_version\":1,",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"principal_id\":{},",
            "\"selector\":\"receive_session\",\"state\":{},\"session_identity\":{},",
            "\"session_identity_is_transaction\":false,\"command_count\":{},\"command_count_verified\":{},",
            "\"all_terminal\":{},\"session_completeness_established\":{},\"single_snapshot\":false,",
            "\"read_only\":true,\"request_reexecuted\":false,\"absence_proves_non_commit\":false,\"commands\":["
        ),
        quote(&node.tenant_id.to_string()),
        quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()),
        quote(&principal.to_string()),
        quote(state),
        session.map_or_else(
            || "null".into(),
            |session| quote(&session.identity().to_string())
        ),
        session.map_or_else(
            || "null".into(),
            |session| session.commands().len().to_string()
        ),
        session.is_some(),
        if session.is_some() {
            all_terminal.to_string()
        } else {
            "null".into()
        },
        all_terminal
    );
    let mut out = String::new();
    append(&mut out, &header, maximum)?;
    if let Some(session) = session {
        for command in session.commands() {
            let row = format!(
                "{}{{\"command_index\":{},{},\"observation\":{}}}",
                if command.index() == 0 { "" } else { "," },
                command.index(),
                ref_fields("ref_name", command.reference()),
                render(node, principal, Some(command.index()), command.recovery())
            );
            append(&mut out, &row, maximum)?;
        }
    }
    // Every append reserved this closing space before retaining another row.
    out.push_str("]}");
    Ok(out)
}

fn append(out: &mut String, part: &str, maximum: usize) -> Result<(), ApiError> {
    let next = out
        .len()
        .checked_add(part.len())
        .and_then(|length| length.checked_add(2))
        .ok_or_else(|| ApiError::from_status(Status::TooLarge))?;
    if next > maximum {
        return Err(ApiError::from_status(Status::TooLarge));
    }
    out.try_reserve(part.len())
        .map_err(|_| ApiError::from_status(Status::Unavailable))?;
    out.push_str(part);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_ceiling_accounts_for_closing_bytes_and_refuses_without_partial_append() {
        let mut out = String::new();
        append(&mut out, "abc", 5).unwrap();
        assert_eq!(out, "abc");
        assert!(append(&mut out, "x", 5).is_err());
        assert_eq!(out, "abc");
        assert!(append(&mut String::new(), "", 1).is_err());
    }
}
