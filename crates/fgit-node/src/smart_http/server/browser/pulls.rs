//! PR browser assets are public inert shells, not repository read grants.
//! The PR profile enables them independently of source and issue browsing;
//! every data, candidate, review, merge and recovery call keeps native auth.

use std::io::Write;

use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};

use super::super::{Profile, Status};
use super::SECURITY;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    let suffix = target.split('?').next()?.as_bytes().strip_prefix(route)?;
    let script = "text/javascript; charset=utf-8";
    match suffix {
        b"/ui/pulls/" => Some(("text/html; charset=utf-8", include_str!("pulls.html"))),
        b"/ui/pulls.css" => Some(("text/css; charset=utf-8", include_str!("pulls.css"))),
        b"/ui/pulls-view.mjs" => Some((script, include_str!("pulls-view.mjs"))),
        b"/ui/pulls.mjs" => Some((script, include_str!("pulls.mjs"))),
        b"/ui/pulls-core.mjs" => Some((script, include_str!("pulls-core.mjs"))),
        b"/ui/pulls-candidate.mjs" => Some((script, include_str!("pulls-candidate.mjs"))),
        b"/ui/pulls-resolution.mjs" => Some((script, include_str!("pulls-resolution.mjs"))),
        b"/ui/pulls-resolution-view.mjs" => Some((script, include_str!("pulls-resolution-view.mjs"))),
        b"/ui/pulls-actions.mjs" => Some((script, include_str!("pulls-actions.mjs"))),
        _ => None,
    }
}

fn checked_asset(
    route: &[u8], enabled: bool, maximum: u64, request: &Envelope<'_>, trailing: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else { return Ok(None); };
    if !enabled { return Err(Status::NotFound); }
    if request.method != "GET" { return Err(Status::Method); }
    if request.target.contains('?') || request.git_protocol.is_some()
        || request.expect_continue || trailing
        || !matches!(request.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
    { return Err(Status::BadRequest); }
    if body.len() as u64 > maximum { return Err(Status::TooLarge); }
    Ok(Some(found))
}

pub(super) fn serve(
    profile: &Profile, request: &Envelope<'_>, trailing: &[u8], writer: &mut impl Write,
) -> Result<bool, Status> {
    let Some((media, body)) = checked_asset(
        &profile.route, profile.allow_pulls, profile.maximum_response_bytes,
        request, !trailing.is_empty(),
    )? else { return Ok(false); };
    let version = match request.version { HttpVersion::Http10 => "HTTP/1.0", HttpVersion::Http11 => "HTTP/1.1" };
    write!(writer, "{version} 200 OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{SECURITY}Connection: close\r\n\r\n", body.len())?;
    writer.write_all(body.as_bytes())?;
    writer.flush()?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};

    #[test]
    fn exact_pr_assets_do_not_widen_other_browser_or_repository_routes() {
        for suffix in ["/ui/pulls/", "/ui/pulls.css", "/ui/pulls-view.mjs", "/ui/pulls.mjs",
            "/ui/pulls-core.mjs", "/ui/pulls-candidate.mjs", "/ui/pulls-actions.mjs",
            "/ui/pulls-resolution.mjs", "/ui/pulls-resolution-view.mjs"] {
            assert!(asset(b"/r.git", &format!("/r.git{suffix}")).is_some());
            assert!(asset(b"/r.git", &format!("/r.git-other{suffix}")).is_none());
            assert!(asset(b"/r.git", &format!("/other.git{suffix}")).is_none());
        }
        for target in ["/r.git/ui/", "/r.git/ui/issues/", "/r.git/ui/pulls/../secret",
            "/r.git/ui/%70ulls/", "/r.git/api/v1/pulls", "/r.git/ui/pulls"] {
            assert!(asset(b"/r.git", target).is_none());
        }
    }

    #[test]
    fn pr_enablement_and_framing_are_checked_before_static_success() {
        for (method, suffix, extra, enabled, trailing, maximum, allowed) in [
            ("GET", "/ui/pulls/", "", true, false, u64::MAX, true),
            ("GET", "/ui/pulls.mjs", "Content-Length: 0\r\n", true, false, u64::MAX, true),
            ("GET", "/ui/pulls/", "", false, false, u64::MAX, false),
            ("POST", "/ui/pulls/", "", true, false, u64::MAX, false),
            ("GET", "/ui/pulls/?token=x", "", true, false, u64::MAX, false),
            ("GET", "/ui/pulls/", "Content-Length: 1\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/pulls/", "Transfer-Encoding: chunked\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/pulls/", "Git-Protocol: version=2\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/pulls/", "Expect: 100-continue\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/pulls/", "", true, true, u64::MAX, false),
            ("GET", "/ui/pulls/", "", true, false, 1, false),
        ] {
            let text = format!("{method} /r.git{suffix} HTTP/1.1\r\nHost: local\r\n{extra}\r\n");
            let envelope = head::parse(text.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert_eq!(checked_asset(b"/r.git", enabled, maximum, &envelope, trailing).is_ok(), allowed);
        }
    }

    #[test]
    fn pr_shell_reuses_strict_security_and_has_no_inline_execution() {
        let html = include_str!("pulls.html");
        assert!(!html.contains("<script>"));
        assert!(html.contains("../pulls-view.mjs"));
        assert!(SECURITY.contains("form-action 'none'"));
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(!SECURITY.contains("unsafe-inline"));
        for script in [include_str!("pulls-view.mjs"), include_str!("pulls.mjs"),
            include_str!("pulls-core.mjs"), include_str!("pulls-candidate.mjs"), include_str!("pulls-actions.mjs"),
            include_str!("pulls-resolution.mjs"), include_str!("pulls-resolution-view.mjs")] {
            assert!(!script.contains("innerHTML"));
            assert!(!script.contains("localStorage"));
            assert!(!script.contains("sessionStorage"));
        }
    }
}
