//! Source-gated rebase shell. Static bytes have no repository data or authority.
use std::io::Write;
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use super::{Profile, SECURITY, Status};
fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/rebase/" => Some(("text/html; charset=utf-8", include_str!("rebase.html"))),
        b"/ui/rebase/rebase.mjs" => Some(("text/javascript; charset=utf-8", include_str!("rebase.mjs"))),
        b"/ui/rebase/rebase-data.mjs" => Some(("text/javascript; charset=utf-8", include_str!("rebase-data.mjs"))),
        b"/ui/rebase/rebase-inspection.mjs" => Some(("text/javascript; charset=utf-8", include_str!("rebase-inspection.mjs"))),
        b"/ui/rebase/rebase-view.mjs" => Some(("text/javascript; charset=utf-8", include_str!("rebase-view.mjs"))),
        b"/ui/rebase/pulls-core.mjs" => Some(("text/javascript; charset=utf-8", include_str!("pulls-core.mjs"))),
        b"/ui/rebase/pulls-candidate.mjs" => Some(("text/javascript; charset=utf-8", include_str!("pulls-candidate.mjs"))),
        b"/ui/rebase/pulls-actions.mjs" => Some(("text/javascript; charset=utf-8", include_str!("pulls-actions.mjs"))),
        b"/ui/rebase/source-edit-protocol.mjs" => Some(("text/javascript; charset=utf-8", include_str!("source-edit-protocol.mjs"))),
        b"/ui/rebase/source-edit-patch.mjs" => Some(("text/javascript; charset=utf-8", include_str!("source-edit-patch.mjs"))),
        _ => None,
    }
}
fn checked_asset(route: &[u8], enabled: bool, maximum: u64, request: &Envelope<'_>, trailing: bool)
    -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else { return Ok(None); };
    if !enabled { return Err(Status::NotFound); }
    if request.method != "GET" { return Err(Status::Method); }
    if request.target.contains('?') || request.git_protocol.is_some() || request.expect_continue
        || trailing || !matches!(request.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
    { return Err(Status::BadRequest); }
    if body.len() as u64 > maximum { return Err(Status::TooLarge); }
    Ok(Some(found))
}
pub(super) fn serve(profile: &Profile, request: &Envelope<'_>, trailing: &[u8], writer: &mut impl Write)
    -> Result<bool, Status> {
    let Some((media, body)) = checked_asset(&profile.route, profile.allow_source,
        profile.maximum_response_bytes, request, !trailing.is_empty())? else { return Ok(false); };
    let version = match request.version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
    write!(writer, "{version} 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{SECURITY}Connection: close\r\n\r\n", body.len())?;
    writer.write_all(body.as_bytes())?; writer.flush()?; Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};
    #[test]
    fn every_asset_is_source_gated_and_exactly_repository_scoped() {
        for name in ["", "rebase.mjs", "rebase-data.mjs", "rebase-inspection.mjs", "rebase-view.mjs", "pulls-core.mjs", "pulls-candidate.mjs", "pulls-actions.mjs", "source-edit-protocol.mjs", "source-edit-patch.mjs"] {
            let target = format!("/r.git/ui/rebase/{name}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked_asset(b"/r.git", true, u64::MAX, &request, false).unwrap().is_some());
            assert!(checked_asset(b"/r.git", false, u64::MAX, &request, false).is_err());
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in ["/r.git-more/ui/rebase/", "/r.git/ui/rebase/../private", "/r.git/api/v1/source/rebase/apply"] {
            assert!(asset(b"/r.git", target).is_none());
        }
    }
    #[test]
    fn shell_refuses_bodies_queries_protocol_options_and_response_overflow() {
        for (method, query, headers, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX), ("GET", "?token=secret", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Transfer-Encoding: chunked\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "Expect: 100-continue\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX), ("GET", "", "", false, 1),
        ] {
            let bytes = format!("{method} /r.git/ui/rebase/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked_asset(b"/r.git", true, maximum, &request, trailing).is_err());
        }
    }
    #[test]
    fn shell_has_no_inline_code_or_credential_persistence() {
        assert!(!include_str!("rebase.html").contains("<script>"));
        for script in [include_str!("rebase.mjs"), include_str!("rebase-data.mjs"), include_str!("rebase-inspection.mjs"), include_str!("rebase-view.mjs")] {
            for forbidden in ["innerHTML", "localStorage", "sessionStorage", "document.write"] { assert!(!script.contains(forbidden)); }
        }
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(include_str!("rebase.html").contains("id=\"confirm-send\""));
    }
}
