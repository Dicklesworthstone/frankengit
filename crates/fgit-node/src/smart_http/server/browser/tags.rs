//! Public static shell only. Native source/tag/outcome endpoints keep their
//! independent grants; loading a helper never enables its other API profile.
use std::io::Write;
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use super::{Profile, Status, SECURITY};

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    let suffix = target.split('?').next()?.as_bytes().strip_prefix(route)?;
    let script = match suffix {
        b"/ui/tags/" => return Some(("text/html; charset=utf-8", include_str!("tags.html"))),
        b"/ui/tags/tags-view.mjs" => include_str!("tags-view.mjs"),
        b"/ui/tags/tags.mjs" => include_str!("tags.mjs"),
        b"/ui/tags/tags-protocol.mjs" => include_str!("tags-protocol.mjs"),
        b"/ui/tags/pulls-core.mjs" => include_str!("pulls-core.mjs"),
        b"/ui/tags/pulls-actions.mjs" => include_str!("pulls-actions.mjs"),
        b"/ui/tags/pulls-candidate.mjs" => include_str!("pulls-candidate.mjs"),
        _ => return None,
    };
    Some(("text/javascript; charset=utf-8", script))
}
fn checked(route: &[u8], enabled: bool, maximum: u64, request: &Envelope<'_>, trailing: bool)
    -> Result<Option<(&'static str, &'static str)>, Status>
{
    let Some(found @ (_, body)) = asset(route, request.target) else { return Ok(None); };
    if !enabled { return Err(Status::NotFound); }
    if request.method != "GET" { return Err(Status::Method); }
    if request.target.contains('?') || request.git_protocol.is_some() || request.expect_continue || trailing
        || !matches!(request.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
    { return Err(Status::BadRequest); }
    if body.len() as u64 > maximum { return Err(Status::TooLarge); }
    Ok(Some(found))
}
pub(super) fn serve(profile: &Profile, request: &Envelope<'_>, trailing: &[u8], writer: &mut impl Write)
    -> Result<bool, Status>
{
    let Some((media, body)) = checked(&profile.route, profile.allow_source,
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
    fn shell_and_every_helper_require_exact_source_enabled_routes() {
        for name in ["", "tags.mjs", "tags-view.mjs", "tags-protocol.mjs", "pulls-core.mjs", "pulls-actions.mjs", "pulls-candidate.mjs"] {
            let target = format!("/repo.git/ui/tags/{name}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked(b"/repo.git", true, u64::MAX, &request, false).unwrap().is_some());
            assert!(checked(b"/repo.git", false, u64::MAX, &request, false).is_err());
            assert!(asset(b"/other.git", &target).is_none());
        }
        for path in ["/repo.git-more/ui/tags/", "/repo.git/ui/tags/../private", "/repo.git/ui/tags/%2e%2e", "/repo.git/api/v1/source/tags/delete"] {
            assert!(asset(b"/repo.git", path).is_none());
        }
    }
    #[test]
    fn tag_static_shell_never_relaxes_http_framing_or_resource_limits() {
        for (method, suffix, extra, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX), ("GET", "?token=x", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Transfer-Encoding: chunked\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "Expect: 100-continue\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX), ("GET", "", "", false, 1),
        ] {
            let bytes = format!("{method} /repo.git/ui/tags/{suffix} HTTP/1.1\r\nHost: local\r\n{extra}\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }
    #[test]
    fn native_metadata_is_not_html_and_credentials_are_not_persisted() {
        assert!(!include_str!("tags.html").contains("<script>"));
        for script in [include_str!("tags.mjs"), include_str!("tags-view.mjs")] {
            for forbidden in ["innerHTML", "localStorage", "sessionStorage", "document.write"] { assert!(!script.contains(forbidden)); }
        }
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(SECURITY.contains("form-action 'none'"));
    }
}
