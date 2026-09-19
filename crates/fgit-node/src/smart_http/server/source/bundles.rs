//! Portable repository transfers through the existing native bundle engine.
//! The source gateway authenticates and assigns read/write quotas. Bundle bytes
//! never select a host path, mint a grant, or constitute forge-state recovery.

mod intake;

use std::io::{self, Read, Write};

use fgit_crypto::sha256_digest;
use fgit_pack::full_bundle::{FullBundle, FullBundleError, FullBundleLimits};
use fgit_types::{GitHashAlgorithm, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, HttpLimits, HttpVersion, head::Envelope};
use fgit_wire::visibility::RefVisibility;

use crate::smart_http::drive_request_while;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling, LoopbackReceiveSession,
    NodeWorkspaceRefusal, OneNode};
use super::{Reply, read_error};
use super::super::{Status, issues::{ApiError, MAX_FORM_BYTES, parse_form, parse_snapshot, read_form}};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation { Export, Import, Fetch }

#[derive(Debug)]
pub(super) struct Request<'a> {
    pub(super) repository_route: &'a str,
    operation: Operation,
    boundary: Option<&'a str>,
}
impl<'a> Request<'a> {
    pub(super) fn parse(head: &Envelope<'a>) -> Result<Option<Self>, ApiError> {
        let Some((repository_route, action)) = head.target.split_once("/api/v1/source/bundle/") else {
            return Ok(None);
        };
        if repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte)))
        { return Err(ApiError::not_found()); }
        let operation = match action {
            "export" => Operation::Export,
            "import" => Operation::Import,
            "fetch" => Operation::Fetch,
            _ => return Err(ApiError::not_found()),
        };
        if head.method != "POST" { return Err(ApiError::method()); }
        if head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_bundle_envelope"));
        }
        let (boundary, maximum) = match operation {
            Operation::Export => {
                if !head.content_type.is_some_and(|media| media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
                    || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8"))
                { return Err(ApiError::media()); }
                (None, MAX_FORM_BYTES)
            }
            Operation::Import | Operation::Fetch => {
                use super::super::pulls::{SourceUploadKind, source_upload_boundary};
                let boundary = source_upload_boundary(head.content_type.ok_or_else(ApiError::media)?)?;
                (Some(boundary), SourceUploadKind::Bundle.maximum())
            }
        };
        if head.body == BodyFraming::ContentLength(0) { return Err(ApiError::bad("empty_bundle_request")); }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > maximum as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Some(Self { repository_route, operation, boundary }))
    }

    pub(super) const fn is_mutation(&self) -> bool {
        match self.operation { Operation::Export => false, Operation::Import | Operation::Fetch => true }
    }
}

fn export_command(bytes: &[u8], format: GitHashAlgorithm)
    -> Result<Option<RepositoryAuthorityHeadId>, ApiError>
{
    let (mut object_format, mut expected_head) = (None, None);
    for (name, value) in parse_form(bytes, 2)? {
        match name.as_str() {
            "object_format" if object_format.is_none() => object_format = Some(value),
            "expected_head" if expected_head.is_none() => expected_head = Some(parse_snapshot(&value)?),
            _ => return Err(ApiError::bad("unknown_or_duplicate_bundle_field")),
        }
    }
    if object_format.as_deref() != Some(format.as_str()) {
        return Err(ApiError::bad("object_format_mismatch"));
    }
    Ok(expected_head)
}

pub(super) fn execute(node: &OneNode, request: &Request<'_>, session: &LoopbackReceiveSession,
    framing: BodyFraming, reader: &mut impl Read, http: HttpLimits, maximum_response: u64,
) -> Result<Reply, ApiError> {
    if session.authenticated_session().is_none() {
        return Err(ApiError::new(Status::Unauthorized, "unauthorized"));
    }
    match request.operation {
        Operation::Import | Operation::Fetch => intake::execute(node, request, session, framing, reader, http, maximum_response),
        Operation::Export => {
            // Resolve format and the snapshot precondition before object work.
            // Complete framing precedes even this read-only native operation.
            let expected = export_command(&read_form(reader, framing, http)?, node.object_format)?;
            let context = node.request_context();
            let deadline = GitDaemonSessionDeadline::new(node.git_daemon_session_timeout, GitDaemonSessionWorkScaling::FLAT);
            let mut live = || !deadline.expired();
            let (head, bundle) = drive_request_while(node, &context,
                node.export_full_git_bundle_in(&context, &RefVisibility::new(), expected), &mut live)
                .map_err(export_error)?;
            let reply = Export::new(node, head, bundle, maximum_response, &mut live)?;
            Ok(Reply::bundle_export(reply))
        }
    }
}

fn export_error(error: NodeWorkspaceRefusal) -> ApiError {
    match error {
        NodeWorkspaceRefusal::FullBundle(error) => match *error {
            FullBundleError::Invalid("export snapshot moved") =>
                ApiError::new(Status::Conflict, "source_snapshot_moved"),
            FullBundleError::Limit(_) => ApiError::too_large(),
            _ => ApiError::unavailable(),
        },
        error => read_error(error),
    }
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|byte| format!("{byte:02x}")).collect() }
fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() { Ok(()) } else { Err(ApiError::from_status(Status::Timeout, false)) }
}

/// Fully constructed native bytes; no successful HTTP header escapes before
/// pack/closure validation, response bounds and the transport digest complete.
/// This is a transport receipt, not a signed repository capsule or backup root.
pub(super) struct Export {
    headers: String,
    body: Vec<u8>,
}
impl Export {
    fn new(node: &OneNode, head: RepositoryAuthorityHeadId, bundle: FullBundle,
        maximum: u64, live: &mut impl FnMut() -> bool,
    ) -> Result<Self, ApiError> {
        checkpoint(live)?;
        if bundle.bytes().len() as u64 > maximum
            || bundle.bytes().len() > FullBundleLimits::default().max_bundle_bytes
        { return Err(ApiError::too_large()); }
        let digest = hex(&sha256_digest(bundle.bytes()));
        checkpoint(live)?;
        let internal = head.as_internal_object_id();
        let snapshot = format!("alg:{}:{}", internal.algorithm().code_point(), hex(internal.digest().as_bytes()));
        let headers = format!(concat!(
            "Content-Type: application/x-git-bundle\r\n",
            "Content-Disposition: attachment; filename=\"repository.bundle\"\r\n",
            "Content-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\n",
            "Vary: Authorization\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n",
            "X-Fgit-Bundle-Profile: full-v1\r\nX-Fgit-Object-Format: {}\r\n",
            "X-Fgit-Tenant: {}\r\nX-Fgit-Repository: {}\r\nX-Fgit-Repository-Incarnation: {}\r\n",
            "X-Fgit-Source-Head: {}\r\nX-Fgit-Snapshot: {}\r\n",
            "X-Fgit-Artifact-Sha256: {}\r\nX-Fgit-Read-Only: true\r\n\r\n"),
            bundle.bytes().len(), node.object_format.as_str(), node.tenant_id, node.repository_id,
            node.repository_incarnation_id(), head, snapshot, digest);
        Ok(Self { headers, body: bundle.into_bytes() })
    }

    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let version = match version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
        write!(writer, "{version} 200 OK\r\n{}", self.headers)?;
        // The owner supplies its deadline-bound stream and drains the session.
        // Stop at the first failed write; never append a success terminator.
        for chunk in self.body.chunks(64 * 1024) { writer.write_all(chunk)?; }
        writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::head;

    fn envelope(method: &str, target: &str, extra: &str) -> Vec<u8> {
        format!("{method} {target} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n").into_bytes()
    }
    #[test]
    fn export_is_an_explicit_read_only_route_not_an_object_or_filesystem_selector() {
        let bytes = envelope("POST", "/r.git/api/v1/source/bundle/export", "");
        let head = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
        let request = Request::parse(&head).unwrap().unwrap();
        assert_eq!(request.repository_route, "/r.git");
        assert!(!request.is_mutation());
        for (method, path, extra) in [
            ("GET", "/r.git/api/v1/source/bundle/export", ""),
            ("POST", "/r.git/api/v1/source/bundle/export?ref=secret", ""),
            ("POST", "/r.git/api/v1/source/bundle/../export", ""),
            ("POST", "/../r.git/api/v1/source/bundle/export", ""),
            ("POST", "/r.git/api/v1/source/bundle/export", "Git-Protocol: version=2\r\n"),
        ] {
            let bytes = envelope(method, path, extra);
            let head = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&head).is_err());
        }
    }
    #[test]
    fn import_and_fetch_are_mutations_with_multipart_envelopes_only() {
        for action in ["import", "fetch"] {
            let bytes = format!("POST /r.git/api/v1/source/bundle/{action} HTTP/1.1\r\nHost: local\r\nContent-Type: multipart/form-data; boundary=x\r\nContent-Length: 1\r\n\r\n");
            let head = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            let request = Request::parse(&head).unwrap().unwrap();
            assert!(request.is_mutation());
            assert_eq!(request.boundary, Some("x"));
            let bytes = envelope("POST", &format!("/r.git/api/v1/source/bundle/{action}"), "");
            let head = head::parse(&bytes, HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&head).is_err());
        }
    }
    #[test]
    fn export_form_requires_format_and_rejects_authority_or_path_overrides() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let valid = format!("object_format={}", format.as_str());
            assert!(export_command(valid.as_bytes(), format).unwrap().is_none());
            for tail in ["&ref=refs/heads/hidden", "&path=/tmp/output", "&principal=admin",
                "&expected_head=invalid", "&object_format=sha1", "&force=true"]
            { assert!(export_command((valid.clone() + tail).as_bytes(), format).is_err()); }
        }
        assert!(export_command(b"", GitHashAlgorithm::Sha1).is_err());
        assert!(export_command(b"object_format=sha256", GitHashAlgorithm::Sha1).is_err());
    }
    #[test]
    fn export_failure_never_reports_a_repository_mutation() {
        for error in [NodeWorkspaceRefusal::FullBundle(Box::new(FullBundleError::Invalid("export snapshot moved"))),
            NodeWorkspaceRefusal::FullBundle(Box::new(FullBundleError::Limit("bundle bytes"))),
            NodeWorkspaceRefusal::RefUnavailable, NodeWorkspaceRefusal::Cancelled { exhaustion: None }]
        { assert!(!export_error(error).outcome_unknown); }
        assert!(checkpoint(&mut || false).is_err());
    }
    #[test]
    fn binary_response_preserves_bytes_and_writer_failure_stops_delivery() {
        let reply = Export { headers: "Content-Length: 4\r\n\r\n".into(), body: vec![0, 255, 13, 10] };
        for version in [HttpVersion::Http10, HttpVersion::Http11] {
            let mut out = Vec::new(); reply.send(&mut out, version).unwrap();
            assert!(out.ends_with(&[0, 255, 13, 10]));
        }
        struct Failed { calls: usize }
        impl Write for Failed {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.calls += 1; Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
            }
            fn flush(&mut self) -> io::Result<()> { panic!("must not flush after failed write") }
        }
        let mut writer = Failed { calls: 0 };
        assert!(reply.send(&mut writer, HttpVersion::Http11).is_err());
        assert_eq!(writer.calls, 1);
    }
}
