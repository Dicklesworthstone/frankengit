//! Static read-only source browser. This shell holds no repository data or
//! authority. Its same-origin API calls authenticate through existing grants.
//! It is exposed only by the explicitly source-enabled gateway profile.

use std::io::Write;
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use super::{Profile, Status};

const HTML: &str = include_str!("browser/index.html");
const SCRIPT: &str = include_str!("browser/browser.mjs");
const STYLE: &str = include_str!("browser/browser.css");
const SECURITY: &str = concat!(
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; ",
    "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n",
);

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/" => Some(("text/html; charset=utf-8", HTML)),
        b"/ui/browser.mjs" => Some(("text/javascript; charset=utf-8", SCRIPT)),
        b"/ui/browser.css" => Some(("text/css; charset=utf-8", STYLE)),
        _ => None,
    }
}

fn checked_asset(
    route: &[u8],
    enabled: bool,
    maximum: u64,
    request: &Envelope<'_>,
    has_trailing_bytes: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else { return Ok(None); };
    if !enabled { return Err(Status::NotFound); }
    if request.method != "GET" { return Err(Status::Method); }
    if request.target.contains('?') || request.git_protocol.is_some()
        || request.expect_continue || has_trailing_bytes
        || !matches!(request.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
    { return Err(Status::BadRequest); }
    if body.len() as u64 > maximum { return Err(Status::TooLarge); }
    Ok(Some(found))
}

pub(super) fn serve(
    profile: &Profile,
    request: &Envelope<'_>,
    trailing: &[u8],
    writer: &mut impl Write,
) -> Result<bool, Status> {
    let Some((media, body)) = checked_asset(
        &profile.route, profile.allow_source, profile.maximum_response_bytes,
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
    #[test]
    fn static_assets_are_exactly_repository_scoped() {
        for suffix in ["/ui/", "/ui/browser.mjs", "/ui/browser.css"] {
            assert!(asset(b"/repo.git", &format!("/repo.git{suffix}")).is_some());
            assert!(asset(b"/repo.git", &format!("/other.git{suffix}")).is_none());
            assert!(asset(b"/repo.git", &format!("/repo.git-more{suffix}")).is_none());
        }
        for target in ["/repo.git/ui/../source.rs", "/repo.git/ui/%2e%2e", "/repo.git/ui/private", "/repo.git/api/v1/source/tree"] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }
    #[test]
    fn shell_has_no_inline_scripts_or_permissive_csp() {
        assert!(!HTML.contains("<script>"));
        assert!(!SECURITY.contains("unsafe-inline"));
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(SECURITY.contains("Cache-Control: no-store"));
        assert!(!SCRIPT.contains("innerHTML"));
        assert!(!SCRIPT.contains("localStorage"));
        assert!(!SCRIPT.contains("sessionStorage"));
    }
    #[test]
    fn shell_never_relaxes_endpoint_framing_or_source_enablement() {
        use fgit_wire::smart_http::{HttpLimits, head};
        for (method, suffix, extra, enabled, trailing, maximum, allowed) in [
            ("GET", "/ui/", "", true, false, u64::MAX, true),
            ("GET", "/ui/browser.mjs", "Content-Length: 0\r\n", true, false, u64::MAX, true),
            ("POST", "/ui/", "Content-Length: 0\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/?token=secret", "", true, false, u64::MAX, false),
            ("GET", "/ui/", "Content-Length: 1\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/", "Transfer-Encoding: chunked\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/", "Git-Protocol: version=2\r\n", true, false, u64::MAX, false),
            ("GET", "/ui/", "", false, false, u64::MAX, false),
            ("GET", "/ui/", "", true, true, u64::MAX, false),
            ("GET", "/ui/", "", true, false, 1, false),
        ] {
            let bytes = format!("{method} /repo.git{suffix} HTTP/1.1\r\nHost: local\r\n{extra}\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert_eq!(checked_asset(b"/repo.git", enabled, maximum, &request, trailing).is_ok(), allowed);
        }
    }

}
