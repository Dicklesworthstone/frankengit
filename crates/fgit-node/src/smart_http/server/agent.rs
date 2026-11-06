//! A canonical agent grant is authenticated anew for each request. Existing
//! route parsers and service switches then attenuate the one-request grant.

use super::{Profile, Status, credentials, discussions, issues, pulls, retry_key, source};
use crate::agent_credentials::{AgentRequest, MAX_REQUEST_BYTES, TOKEN_PREFIX};
use crate::smart_http::drive_request_while;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionTimeout, GitDaemonSessionWorkScaling};
use fgit_authority::IdempotencyKey;
use fgit_identity::agent::{
    DISCUSSIONS_READ, DISCUSSIONS_WRITE, ISSUES_WRITE, OUTCOMES_READ, PULLS_WRITE,
};
use fgit_wire::smart_http::head::Envelope;
use std::time::Duration;

fn operation(envelope: &Envelope<'_>) -> Result<u16, Status> {
    if let Some(request) = pulls::Request::parse(envelope).map_err(|error| error.status)? {
        return request.agent_operation().ok_or(Status::Forbidden);
    }
    if discussions::is_route(envelope.target) {
        let request = discussions::Request::parse(envelope).map_err(|error| error.status)?;
        return Ok(if request.is_mutation() {
            DISCUSSIONS_WRITE
        } else {
            DISCUSSIONS_READ
        });
    }
    if let Some(request) = issues::Request::parse(envelope).map_err(|error| error.status)? {
        return request.agent_operation().ok_or(Status::Forbidden);
    }
    if envelope.target.contains("/api/v1/source/") {
        return source::Request::parse(envelope)
            .map_err(|error| error.status)?
            .agent_operation()
            .ok_or(Status::Forbidden);
    }
    // Only single metadata-transaction recovery. Receive/session recovery and
    // Git, review, workflow, merge and administration routes stay closed.
    if envelope.method == "POST" && envelope.target.ends_with("/api/v1/outcomes") {
        return Ok(OUTCOMES_READ);
    }
    Err(Status::Forbidden)
}

pub(super) fn authenticate(
    profile: &Profile,
    envelope: &Envelope<'_>,
    raw_head: &[u8],
) -> Result<Option<(Profile, AgentRequest)>, Status> {
    let Some((scheme, token)) = envelope
        .authorization()
        .and_then(|value| value.split_once(' '))
    else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("bearer") || !token.starts_with(TOKEN_PREFIX) {
        return Ok(None);
    }
    if !crate::agent_credentials::valid_agent_credential_token(token.as_bytes()) {
        return Err(Status::Unauthorized);
    }
    let operation = operation(envelope)?;
    let mutation = operation & (ISSUES_WRITE | PULLS_WRITE | DISCUSSIONS_WRITE) != 0;
    let retry = retry_key(raw_head).map_err(|_| Status::BadRequest)?;
    let key = if mutation || operation == OUTCOMES_READ {
        retry.ok_or(Status::BadRequest)?
    } else {
        b"agent-metadata-read-no-publication".as_slice()
    };
    let key = IdempotencyKey::new(key.to_vec()).map_err(|_| Status::BadRequest)?;
    let mut selected = profile.clone();
    // These are the actual parser/response envelopes reserved by IntentRun.
    selected.http.max_body_bytes = selected
        .http
        .max_body_bytes
        .min(issues::MAX_FORM_BYTES as u64);
    selected.http.max_body_wire_bytes = selected
        .http
        .max_body_wire_bytes
        .min(selected.http.max_body_bytes + 64 * 1024);
    selected.maximum_response_bytes = selected
        .maximum_response_bytes
        .min(MAX_REQUEST_BYTES - 16 * 1024);
    let input_limit = selected.http.max_head_bytes as u64 + selected.http.max_body_wire_bytes;
    let output_limit = selected.maximum_response_bytes + 16 * 1024;
    let timeout = GitDaemonSessionTimeout::try_new(profile.timeout.duration().min(
        Duration::from_secs(crate::agent_credentials::MAX_REQUEST_SECONDS),
    ))
    .map_err(|_| Status::Unavailable)?;
    let deadline = GitDaemonSessionDeadline::new(timeout, GitDaemonSessionWorkScaling::FLAT);
    let node = profile.nodes.lease().ok_or(Status::Unavailable)?;
    let context = node.session_request_context(&deadline);
    let authenticated = drive_request_while(
        &node,
        &context,
        node.authenticate_agent_request_in(
            &context,
            token.as_bytes(),
            &key,
            operation,
            fgit_crypto::sha256_digest(raw_head),
            input_limit,
            output_limit,
        ),
        &mut || !deadline.expired(),
    );
    // A lane is an owned node, not an RAII lease. Close failed work and restore
    // successful work after its authority future completes; authentication
    // must not leak a SQLite connection/runtime on each request.
    drop(context);
    let cleanup = if authenticated.is_ok() {
        profile.nodes.restore(node)
    } else {
        node.shutdown()
    };
    if let Err(error) = cleanup {
        super::log_cleanup(&error);
        return Err(Status::Unavailable);
    }
    let request = authenticated.map_err(|error| match error {
        crate::NodeReceiveTransportRefusal::Unauthenticated => Status::Unauthorized,
        crate::NodeReceiveTransportRefusal::Admission(error) => match *error {
            fgit_admission::AdmissionError::AsyncProjectionUnavailable(
                fgit_types::RefusalCode::CapabilityScopeViolation,
            ) => Status::Forbidden,
            _ => Status::Unavailable,
        },
        _ => Status::Unavailable,
    })?;
    selected.credentials = credentials::CredentialSource::AgentRequest {
        digest: fgit_crypto::sha256_digest(token.as_bytes()),
        grant: credentials::Grant::agent(&request),
    };
    Ok(Some((selected, request)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn agent_routes_are_a_closed_metadata_and_recovery_set() {
        for (method, path, allowed) in [
            ("GET", "/repo/api/v1/issues", true),
            ("GET", "/repo/api/v1/pulls", true),
            ("POST", "/repo/api/v1/outcomes", true),
            ("POST", "/repo/api/v1/outcomes/receive", false),
            ("POST", "/repo/git-receive-pack", false),
            ("GET", "/repo/api/v1/source", false),
            ("GET", "/repo/api/v1/protection", false),
            ("GET", "/repo/api/v1/milestones", false),
        ] {
            let raw =
                format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
            let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(operation(&envelope).is_ok(), allowed, "{path}");
        }
    }

    #[test]
    fn sponsored_source_read_uses_a_closed_read_only_route_set() {
        use fgit_identity::agent::SOURCE_READ;

        for action in [
            "tree",
            "blob",
            "search",
            "search-batch",
            "search-regex",
            "search-index",
            "search-symbols",
            "search-symbols-index",
            "search-initial",
            "context-initial",
            "agent-context",
            "refs",
            "tags/inspect",
        ] {
            let raw = format!(
                "POST /repo/api/v1/source/{action} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(operation(&envelope).unwrap(), SOURCE_READ, "{action}");
        }
        for action in ["log", "blame", "historical-tree", "historical-blob", "diff"] {
            let raw = format!(
                "POST /repo/api/v1/source/{action} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                operation(&envelope).unwrap(),
                fgit_identity::agent::SOURCE_HISTORY_READ,
                "{action}"
            );
        }
        for action in [
            "prepare",
            "apply",
            "initial",
            "history",
            "verified-blob",
            "branches/create",
            "branches/update",
            "branches/delete",
            "branches/rename",
            "branches/transaction",
            "tags/lightweight",
            "tags/annotated",
            "tags/delete",
            "bundle/export",
            "bundle/import",
            "bundle/fetch",
            "cherry-pick/prepare",
            "cherry-pick/resolve",
            "revert/prepare",
            "revert/resolve",
            "rebase/prepare",
            "rebase/resolve",
            "rebase/inspect",
            "rebase/apply",
            "unknown-read",
        ] {
            let raw = format!(
                "POST /repo/api/v1/source/{action} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n\r\n"
            );
            let envelope = head::parse(raw.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(operation(&envelope).is_err(), "{action}");
        }
    }
}
