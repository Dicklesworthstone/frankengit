//! Lost-response recovery without a command body, pack, re-seal, or publication.
//!
//! The independently granted caller can inspect only its own principal's key
//! scope. The authority's existing key/seal verifier and outcome resolver own
//! every reported fact. In particular, absence is never an abort certificate.

use std::io::{self, Write};

use fgit_admission::policy_bridge::receive_session::non_atomic_command_key;
use fgit_authority::key_recovery::RequestRecovery;
use fgit_authority::{IdempotencyKey, OutcomeLookup};
use fgit_types::{DecisionOutcome, PrincipalId};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};

use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession, OneNode};
use super::{Profile, Status, retry_key};
use super::super::drive_request_while;

const MAX_REPLY_BYTES: usize = 16 * 1024;
const ROUTE: &str = "/api/v1/outcomes";

/// An original key is carried in Idempotency-Key, never in a URL or response.
/// POST is a read-only query here; its envelope must have no body.
struct Request<'a> {
    repository_route: &'a str,
    command_index: Option<usize>,
}
impl<'a> Request<'a> {
    fn parse(envelope: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let Some((repository_route, suffix)) = envelope.target.rsplit_once(ROUTE) else {
            return Ok(None);
        };
        if envelope.method != "POST" {
            return Err(ApiError::new(Status::Method, "method_not_allowed"));
        }
        let command_index = if suffix.is_empty() {
            None
        } else {
            let number = suffix.strip_prefix("/receive/")
                .ok_or_else(|| ApiError::new(Status::NotFound, "not_found"))?;
            if number.is_empty() || number.len() > 2
                || !number.bytes().all(|byte| byte.is_ascii_digit())
                || (number.len() > 1 && number.starts_with('0'))
            {
                return Err(ApiError::bad("invalid_command_index"));
            }
            let index: usize = number.parse().map_err(|_| ApiError::bad("invalid_command_index"))?;
            if index >= fgit_admission::AdmissionLimits::default().max_commands {
                return Err(ApiError::bad("invalid_command_index"));
            }
            Some(index)
        };
        if !matches!(envelope.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
            || envelope.expect_continue
        {
            return Err(ApiError::bad("body_not_allowed"));
        }
        if envelope.git_protocol.is_some() {
            return Err(ApiError::bad("git_protocol_not_applicable"));
        }
        Ok(Some(Self { repository_route, command_index }))
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct ApiError {
    pub(super) status: Status,
    code: &'static str,
}
impl ApiError {
    fn new(status: Status, code: &'static str) -> Self { Self { status, code } }
    fn bad(code: &'static str) -> Self { Self::new(Status::BadRequest, code) }
    pub(super) fn from_status(status: Status) -> Self {
        let code = match status {
            Status::Unauthorized => "unauthorized",
            Status::Forbidden => "forbidden",
            Status::NotFound => "not_found",
            Status::RateLimited => "rate_limited",
            Status::Timeout => "request_timeout",
            Status::TooLarge | Status::HeaderTooLarge => "resource_limit",
            Status::Unavailable => "recovery_unavailable",
            _ => "invalid_request",
        };
        Self::new(status, code)
    }
    pub(super) fn send(self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let retryable = matches!(self.status, Status::Unavailable | Status::Timeout | Status::RateLimited);
        let remediation = match self.status {
            Status::Unauthorized => "authenticate_as_original_principal",
            Status::Forbidden => "request_outcomes_read_grant",
            _ if retryable => "retry_same_lookup",
            _ => "correct_lookup_parameters",
        };
        let body = format!(concat!(
            "{{\"type\":\"outcome_error\",\"schema_version\":1,\"code\":{},",
            "\"retryable\":{},\"remediation\":{},\"outcome_unknown\":true,",
            "\"read_only\":true,\"request_reexecuted\":false,\"absence_proves_non_commit\":false}}"
        ), quote(self.code), retryable, quote(remediation));
        send_json(writer, version, self.status, &body)
    }
}

fn authenticate(
    request: &Request<'_>, envelope: &Envelope<'_>, raw_head: &[u8], profile: &Profile,
) -> Result<LoopbackReceiveSession, ApiError> {
    let grant = profile.credentials.authenticate(envelope.authorization())
        .map_err(|error| ApiError::from_status(Status::from(error)))?;
    if request.repository_route.as_bytes() != profile.route {
        return Err(ApiError::new(Status::NotFound, "not_found"));
    }
    if !profile.allow_outcomes || !grant.permits_outcomes() {
        return Err(ApiError::new(Status::Forbidden, "forbidden"));
    }
    let original = retry_key(raw_head).map_err(|_| ApiError::bad("invalid_original_key"))?
        .ok_or_else(|| ApiError::bad("original_key_required"))?;
    let original = IdempotencyKey::new(original.to_vec()).map_err(|_| ApiError::bad("invalid_original_key"))?;
    let key = match request.command_index {
        None => original,
        Some(index) => non_atomic_command_key(&original, index)
            .map_err(|_| ApiError::bad("invalid_command_index"))?,
    };
    Ok(LoopbackReceiveSession::authenticated(grant.principal, key))
}

/// Own one bounded lookup child, including explicit close on every result.
/// This path never reads a transaction body or brings the child into Serving.
/// Recovery has its own quota so an exhausted write quota cannot hide a result.
pub(super) fn serve(
    profile: &Profile, envelope: &Envelope<'_>, raw_head: &[u8],
    read_ahead: &[u8], writer: &mut impl Write,
) -> Result<(), ApiError> {
    let request = Request::parse(envelope)?
        .ok_or_else(|| ApiError::new(Status::NotFound, "not_found"))?;
    let session = authenticate(&request, envelope, raw_head, profile)?;
    if !read_ahead.is_empty() { return Err(ApiError::bad("body_not_allowed")); }
    let principal = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?.principal_id();
    profile.outcome_quota.evaluate(&principal)
        .map_err(|_| ApiError::from_status(Status::RateLimited))?;
    let node = OneNode::open_existing(profile.config.clone())
        .map_err(|_| ApiError::from_status(Status::Unavailable))?;
    let result = execute(&node, &request, &session, profile.maximum_response_bytes)
        .and_then(|reply| reply.send(writer, envelope.version)
            .map_err(|_| ApiError::from_status(Status::Unavailable)));
    let cleanup = node.shutdown();
    if let Err(error) = cleanup {
        super::log_cleanup(&error);
        return Err(ApiError::from_status(Status::Unavailable));
    }
    result
}

struct Reply {
    body: String,
    terminal_tx: Option<fgit_types::TxId>,
}
impl Reply {
    fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let result = send_json(writer, version, Status::Success, &self.body);
        if result.is_err() {
            if let Some(tx) = self.terminal_tx {
                eprintln!("Outcome HTTP reply lost after resolving canonical transaction {tx}; repeat the read-only lookup");
            }
        }
        result
    }
}

fn execute(
    node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession, maximum_response: u64,
) -> Result<Reply, ApiError> {
    let principal = session.authenticated_session()
        .ok_or_else(|| ApiError::new(Status::Unauthorized, "unauthorized"))?.principal_id();
    let context = node.request_context();
    let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
    // The resolver preserves a terminal result even if cancellation arrives
    // after that decision was authenticated. No seal or binding is written.
    let report = drive_request_while(node, &context,
        node.recover_transaction_in(&context, session), &mut || !deadline.expired())
        .map_err(|_| ApiError::from_status(Status::Unavailable))?;
    let body = render(node, principal, request.command_index, &report);
    let maximum = usize::try_from(maximum_response).unwrap_or(usize::MAX).min(MAX_REPLY_BYTES);
    if body.len() > maximum {
        return Err(ApiError::from_status(Status::TooLarge));
    }
    let terminal_tx = match &report {
        RequestRecovery::Recovered(recovered) if report.terminal().is_some() => Some(recovered.tx_id()),
        _ => None,
    };
    Ok(Reply { body, terminal_tx })
}

fn render(node: &OneNode, principal: PrincipalId, command_index: Option<usize>, report: &RequestRecovery) -> String {
    let (state, recovered, terminal) = match report {
        RequestRecovery::KeyNotObserved => ("key_not_observed", None, None),
        RequestRecovery::SealNotObserved => ("seal_not_observed", None, None),
        RequestRecovery::Recovered(recovered) => match recovered.outcome() {
            OutcomeLookup::Undecided => ("undecided", Some(recovered.as_ref()), None),
            OutcomeLookup::Decided(terminal) => (
                match terminal.outcome { DecisionOutcome::Committed { .. } => "committed", DecisionOutcome::Refused { .. } => "refused" },
                Some(recovered.as_ref()), Some(terminal),
            ),
        },
    };
    let transaction = recovered.map_or_else(|| "null".to_owned(), |recovered| {
        let digest = recovered.seal().canonical_request_digest;
        let hex: String = digest.bytes().as_bytes().iter().map(|byte| format!("{byte:02x}")).collect();
        format!(concat!("{{\"tx_id\":{},\"seal_id\":{},\"request_schema\":{},",
            "\"canonical_request_digest\":{{\"algorithm\":{},\"hex\":{}}}}}"),
            quote(&recovered.tx_id().to_string()), quote(&recovered.seal_id().to_string()),
            quote(&recovered.seal().request_schema.to_string()), digest.algorithm().code_point(), quote(&hex))
    });
    let decision = terminal.map_or_else(|| "null".to_owned(), |terminal| match terminal.outcome {
        DecisionOutcome::Committed { repository_commit_id } => format!(
            "{{\"kind\":\"committed\",\"decision_sequence\":{},\"repository_commit_id\":{}}}",
            terminal.decision_sequence.get(), quote(&repository_commit_id.to_string())),
        DecisionOutcome::Refused { code, refusal_record_id } => format!(
            "{{\"kind\":\"refused\",\"decision_sequence\":{},\"code\":{},\"code_point\":{},\"refusal_record_id\":{}}}",
            terminal.decision_sequence.get(), quote(&format!("{code:?}")), code.code_point(), quote(&refusal_record_id.to_string())),
    });
    format!(concat!("{{\"type\":\"transaction_outcome\",\"schema_version\":1,",
        "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation\":{},\"principal_id\":{},",
        "\"selector\":{},\"command_index\":{},\"state\":{},\"terminal\":{},",
        "\"transaction\":{},\"decision\":{},\"read_only\":true,\"request_reexecuted\":false,",
        "\"absence_proves_non_commit\":false,\"session_completeness_established\":false}}"),
        quote(&node.tenant_id.to_string()), quote(&node.repository_id.to_string()),
        quote(&node.repository_incarnation_id().to_string()), quote(&principal.to_string()),
        quote(if command_index.is_some() { "receive_command" } else { "transaction" }),
        command_index.map_or_else(|| "null".to_owned(), |index| index.to_string()),
        quote(state), terminal.is_some(), transaction, decision)
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
fn send_json(writer: &mut impl Write, version: HttpVersion, status: Status, body: &str) -> io::Result<()> {
    let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
    let extra = match status {
        Status::Unauthorized => "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: POST\r\n",
        _ => "",
    };
    write!(writer, "{version} {}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nVary: Authorization, Idempotency-Key\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n{extra}\r\n{body}", status.line(), body.len())?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn selectors_are_bodyless_queries_with_explicit_original_wire_indices() {
        for suffix in ["", "/receive/0", "/receive/63"] {
            let bytes = format!("POST /repo.git/api/v1/outcomes{suffix} HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            let request = Request::parse(&envelope).unwrap().unwrap();
            assert_eq!(request.repository_route, "/repo.git");
            assert_eq!(request.command_index, if suffix.is_empty() { None } else if suffix.ends_with("/0") { Some(0) } else { Some(63) });
        }
    }

    #[test]
    fn recovery_never_accepts_mutation_bodies_query_keys_or_ambiguous_indices() {
        for (suffix, headers) in [
            ("?key=secret", ""), ("/receive/64", ""), ("/receive/00", ""),
            ("/receive/-1", ""), ("/receive/1/extra", ""), ("/receive/%30", ""),
            ("", "Content-Length: 1\r\n"), ("", "Transfer-Encoding: chunked\r\n"),
            ("", "Expect: 100-continue\r\n"), ("", "Git-Protocol: version=2\r\n"),
        ] {
            let bytes = format!("POST /repo.git/api/v1/outcomes{suffix} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&envelope).is_err(), "{suffix} {headers}");
        }
    }

    #[test]
    fn errors_are_self_delimited_and_never_infer_a_previous_mutations_outcome() {
        let mut output = Vec::new();
        ApiError::from_status(Status::Unavailable).send(&mut output, HttpVersion::Http11).unwrap();
        let text = String::from_utf8(output).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("HTTP/1.1 503"));
        assert!(head.contains(&format!("Content-Length: {}", body.len())));
        assert!(body.contains("\"outcome_unknown\":true"));
        assert!(body.contains("\"remediation\":\"retry_same_lookup\""));
        assert!(body.contains("\"absence_proves_non_commit\":false"));
        assert!(!body.contains("\"state\":\"refused\""));
    }
}
