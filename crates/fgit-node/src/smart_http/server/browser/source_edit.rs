//! A source-enabled static authoring shell. These assets contain no repository
//! state, credentials or authority; every operation uses native source APIs.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/source/" => Some(("text/html; charset=utf-8", include_str!("source-edit.html"))),
        b"/ui/source/source-edit.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("source-edit.mjs"),
        )),
        b"/ui/source/source-edit-patch.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("source-edit-patch.mjs"),
        )),
        b"/ui/source/source-edit-protocol.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("source-edit-protocol.mjs"),
        )),
        b"/ui/source/source-edit-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("source-edit-view.mjs"),
        )),
        // Byte-identical helpers, not an implicit PR enablement or permission.
        b"/ui/source/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        b"/ui/source/pulls-candidate.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-candidate.mjs"),
        )),
        b"/ui/source/pulls-actions.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-actions.mjs"),
        )),
        _ => None,
    }
}
fn checked_asset(
    route: &[u8],
    enabled: bool,
    maximum: u64,
    request: &Envelope<'_>,
    trailing: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else {
        return Ok(None);
    };
    if !enabled {
        return Err(Status::NotFound);
    }
    if request.method != "GET" {
        return Err(Status::Method);
    }
    if request.target.contains('?')
        || request.git_protocol.is_some()
        || request.expect_continue
        || trailing
        || !matches!(
            request.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        )
    {
        return Err(Status::BadRequest);
    }
    if body.len() as u64 > maximum {
        return Err(Status::TooLarge);
    }
    Ok(Some(found))
}
pub(super) fn serve(
    profile: &Profile,
    request: &Envelope<'_>,
    trailing: &[u8],
    writer: &mut impl Write,
) -> Result<bool, Status> {
    let Some((media, body)) = checked_asset(
        &profile.route,
        profile.allow_source,
        profile.maximum_response_bytes,
        request,
        !trailing.is_empty(),
    )?
    else {
        return Ok(false);
    };
    let version = match request.version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    write!(
        writer,
        "{version} 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{SECURITY}Connection: close\r\n\r\n",
        body.len()
    )?;
    writer.write_all(body.as_bytes())?;
    writer.flush()?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};
    #[test]
    fn authoring_and_shared_helpers_require_exact_source_routes_and_source_enablement() {
        for suffix in [
            "",
            "source-edit.mjs",
            "source-edit-patch.mjs",
            "source-edit-protocol.mjs",
            "source-edit-view.mjs",
            "pulls-core.mjs",
            "pulls-candidate.mjs",
            "pulls-actions.mjs",
        ] {
            let target = format!("/repo.git/ui/source/{suffix}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(
                checked_asset(b"/repo.git", true, u64::MAX, &request, false)
                    .unwrap()
                    .is_some()
            );
            assert!(checked_asset(b"/repo.git", false, u64::MAX, &request, false).is_err());
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in [
            "/repo.git-more/ui/source/",
            "/repo.git/ui/source/../private",
            "/repo.git/ui/source/%2e%2e",
            "/repo.git/api/v1/source/apply",
            "/repo.git/ui/pulls/",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }
    #[test]
    fn static_authoring_does_not_accept_request_bodies_queries_or_oversized_responses() {
        for (method, query, headers, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX),
            ("GET", "?token=secret", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Transfer-Encoding: chunked\r\n", false, u64::MAX),
            ("GET", "", "Expect: 100-continue\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX),
            ("GET", "", "", false, 1),
        ] {
            let bytes = format!(
                "{method} /repo.git/ui/source/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }
    #[test]
    fn authoring_shell_and_scripts_keep_repository_text_inert_and_tokens_ephemeral() {
        assert!(!include_str!("source-edit.html").contains("<script>"));
        for script in [
            include_str!("source-edit.mjs"),
            include_str!("source-edit-view.mjs"),
        ] {
            for forbidden in [
                "innerHTML",
                "localStorage",
                "sessionStorage",
                "document.write",
            ] {
                assert!(!script.contains(forbidden));
            }
        }
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(SECURITY.contains("form-action 'none'"));
    }
}
