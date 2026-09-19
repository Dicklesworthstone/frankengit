//! Static branch management over the existing authenticated source API.
//! Public shell bytes contain no repository state. No profile grants expand.
use std::io::Write;
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use super::{Profile, SECURITY, Status};

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/branches/" => Some(("text/html; charset=utf-8", include_str!("branches.html"))),
        b"/ui/branches/branches.mjs" => Some(("text/javascript; charset=utf-8", include_str!("branches.mjs"))),
        b"/ui/branches/branches-view.mjs" => Some(("text/javascript; charset=utf-8", include_str!("branches-view.mjs"))),
        // Same bounded transport/outcome helpers, not an implicit PR grant.
        b"/ui/branches/pulls-core.mjs" => Some(("text/javascript; charset=utf-8", include_str!("pulls-core.mjs"))),
        b"/ui/branches/pulls-actions.mjs" => Some(("text/javascript; charset=utf-8", include_str!("pulls-actions.mjs"))),
        b"/ui/branches/pulls-candidate.mjs" => Some(("text/javascript; charset=utf-8", include_str!("pulls-candidate.mjs"))),
        _ => None,
    }
}
fn checked_asset(route: &[u8], enabled: bool, maximum: u64,
    request: &Envelope<'_>, trailing: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else { return Ok(None); };
    if !enabled { return Err(Status::NotFound); }
    if request.method != "GET" { return Err(Status::Method); }
    if request.target.contains('?') || request.git_protocol.is_some() || request.expect_continue
        || trailing || !matches!(request.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
    { return Err(Status::BadRequest); }
    if body.len() as u64 > maximum { return Err(Status::TooLarge); }
    Ok(Some(found))
}
pub(super) fn serve(profile: &Profile, request: &Envelope<'_>, trailing: &[u8],
    writer: &mut impl Write,
) -> Result<bool, Status> {
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
    fn every_branch_asset_and_import_is_exactly_source_scoped() {
        for suffix in ["", "branches.mjs", "branches-view.mjs", "pulls-core.mjs", "pulls-actions.mjs", "pulls-candidate.mjs"] {
            let target = format!("/repo.git/ui/branches/{suffix}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked_asset(b"/repo.git", true, u64::MAX, &request, false).unwrap().is_some());
            assert!(matches!(checked_asset(b"/repo.git", false, u64::MAX, &request, false), Err(Status::NotFound)));
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in ["/repo.git-more/ui/branches/", "/repo.git/ui/branches/../private", "/repo.git/ui/branches/%2e%2e",
            "/repo.git/api/v1/source/branches/delete", "/repo.git/ui/source/", "/repo.git/ui/pulls/"] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }
    #[test]
    fn static_routes_never_accept_mutation_framing_queries_or_oversized_responses() {
        for (method, query, headers, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX), ("GET", "?token=secret", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Transfer-Encoding: chunked\r\n", false, u64::MAX),
            ("GET", "", "Expect: 100-continue\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX), ("GET", "", "", false, 1),
        ] {
            let bytes = format!("{method} /repo.git/ui/branches/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }
    #[test]
    fn branch_shell_keeps_ref_text_inert_and_credentials_ephemeral() {
        assert!(!include_str!("branches.html").contains("<script>"));
        for script in [include_str!("branches.mjs"), include_str!("branches-view.mjs")] {
            for forbidden in ["innerHTML", "localStorage", "sessionStorage", "document.write"] {
                assert!(!script.contains(forbidden));
            }
        }
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(SECURITY.contains("form-action 'none'"));
    }
}
