//! Whole non-atomic session lookup, reusing the one-command receipt vocabulary.

use fgit_admission::policy_bridge::receive_session::recovery::SessionRecovery;
use fgit_authority::key_recovery::RequestRecovery;
use fgit_types::{PrincipalId, RefName};

use super::super::issues::ref_fields;
use super::{ApiError, Reply, Status, drive_request_while, quote, render};
use crate::{
    GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode,
};

// A session can carry thousands of commands, each with its own scoped
// observation and terminal identity. Keep a finite response budget that can
// carry that admitted count; the caller may still select a tighter envelope.
const MAX_SESSION_REPLY_BYTES: usize = 16 * 1024 * 1024;

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
            let row = render_command(
                node,
                principal,
                command.index(),
                command.reference(),
                command.recovery(),
            );
            append(&mut out, &row, maximum)?;
        }
    }
    // Every append reserved this closing space before retaining another row.
    out.push_str("]}");
    Ok(out)
}

fn render_command(
    node: &OneNode,
    principal: PrincipalId,
    index: usize,
    reference: &RefName,
    recovery: &RequestRecovery,
) -> String {
    format!(
        "{}{{\"command_index\":{index},{},\"observation\":{}}}",
        if index == 0 { "" } else { "," },
        ref_fields("ref_name", reference),
        render(node, principal, Some(index), recovery)
    )
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
    use crate::NodeConfig;
    use fgit_authority::MAX_REF_COMMANDS;
    use fgit_types::{RepositoryId, TenantId};
    use std::path::PathBuf;

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reply_profile_fits_all_admitted_command_observations_and_honors_tighter_limits() {
        let root = Scratch(
            std::env::temp_dir().join(format!("fg-session-response-limit-{}", std::process::id())),
        );
        let (node, _) = OneNode::init(NodeConfig::new(
            root.0.clone(),
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
        ))
        .unwrap();
        let principal = PrincipalId::from_bytes([0xb3; 16]);
        let mut response = String::new();
        let mut narrowed = String::new();
        let tight_limit = 1024 * 1024;
        append(&mut response, "{\"commands\":[", MAX_SESSION_REPLY_BYTES).unwrap();
        append(&mut narrowed, "{\"commands\":[", tight_limit).unwrap();
        let mut narrowed_refused = false;
        for index in 0..MAX_REF_COMMANDS {
            let reference = RefName::try_new(format!("refs/tags/{index:04}").as_bytes()).unwrap();
            // This exercises the real response serializer and its resource
            // envelope. No canonical decision or completed session is invented.
            let row = render_command(
                &node,
                principal,
                index,
                &reference,
                &RequestRecovery::SealNotObserved,
            );
            append(&mut response, &row, MAX_SESSION_REPLY_BYTES).unwrap();
            if !narrowed_refused {
                let before = narrowed.len();
                if let Err(error) = append(&mut narrowed, &row, tight_limit) {
                    assert_eq!(error.status, Status::TooLarge);
                    assert_eq!(narrowed.len(), before, "never retain a partial command");
                    narrowed_refused = true;
                }
            }
        }
        response.push_str("]}");
        assert!(response.len() > tight_limit);
        assert!(response.len() <= MAX_SESSION_REPLY_BYTES);
        assert!(
            narrowed_refused,
            "an explicitly smaller envelope still refuses"
        );
        assert_eq!(response.matches("\"ref_name\":").count(), MAX_REF_COMMANDS);
        assert!(response.contains(&format!(
            "\"command_index\":{},\"ref_name\":\"refs/tags/{:04}\"",
            MAX_REF_COMMANDS - 1,
            MAX_REF_COMMANDS - 1,
        )));
        assert_eq!(
            response
                .matches("\"absence_proves_non_commit\":false")
                .count(),
            MAX_REF_COMMANDS
        );
        node.shutdown().unwrap();
    }

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
