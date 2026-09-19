//! Static source, issue and PR shells hold no repository data or authority.
//! Same-origin API calls authenticate through existing grants. Each shell is
//! independently enabled by its existing gateway profile.

mod pulls;

mod source_edit;
mod initial;
mod history;
mod branches;
mod search;
mod transfers;
mod export_verify;
mod tags;
mod replay;

use std::io::Write;
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use super::{Profile, Status};

const HTML: &str = include_str!("browser/index.html");
const SCRIPT: &str = include_str!("browser/browser.mjs");
const STYLE: &str = include_str!("browser/browser.css");
const ISSUES_HTML: &str = include_str!("browser/issues.html");
const ISSUES_CLIENT: &str = include_str!("browser/issues.mjs");
const ISSUES_VIEW: &str = include_str!("browser/issues-view.mjs");

#[derive(Clone, Copy)]
enum AssetScope { Source, Issues, Shared }
const SECURITY: &str = concat!(
    "Cache-Control: no-store\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; ",
    "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n",
);

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str, AssetScope)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/" => Some(("text/html; charset=utf-8", HTML, AssetScope::Source)),
        b"/ui/browser.mjs" => Some(("text/javascript; charset=utf-8", SCRIPT, AssetScope::Source)),
        b"/ui/browser.css" => Some(("text/css; charset=utf-8", STYLE, AssetScope::Shared)),
        b"/ui/issues/" => Some(("text/html; charset=utf-8", ISSUES_HTML, AssetScope::Issues)),
        b"/ui/issues.mjs" => Some(("text/javascript; charset=utf-8", ISSUES_CLIENT, AssetScope::Issues)),
        b"/ui/issues-view.mjs" => Some(("text/javascript; charset=utf-8", ISSUES_VIEW, AssetScope::Issues)),
        _ => None,
    }
}

fn checked_asset(
    route: &[u8],
    source_enabled: bool,
    issues_enabled: bool,
    maximum: u64,
    request: &Envelope<'_>,
    has_trailing_bytes: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some((media, body, scope)) = asset(route, request.target) else { return Ok(None); };
    let enabled = match scope {
        AssetScope::Source => source_enabled,
        AssetScope::Issues => issues_enabled,
        AssetScope::Shared => source_enabled || issues_enabled,
    };
    if !enabled { return Err(Status::NotFound); }
    if request.method != "GET" { return Err(Status::Method); }
    if request.target.contains('?') || request.git_protocol.is_some()
        || request.expect_continue || has_trailing_bytes
        || !matches!(request.body, BodyFraming::Empty | BodyFraming::ContentLength(0))
    { return Err(Status::BadRequest); }
    if body.len() as u64 > maximum { return Err(Status::TooLarge); }
    Ok(Some((media, body)))
}

pub(super) fn serve(
    profile: &Profile,
    request: &Envelope<'_>,
    trailing: &[u8],
    writer: &mut impl Write,
) -> Result<bool, Status> {
    if replay::serve(profile, request, trailing, writer)? { return Ok(true); }
    if tags::serve(profile, request, trailing, writer)? { return Ok(true); }
    if export_verify::serve(profile, request, trailing, writer)? { return Ok(true); }
    if transfers::serve(profile, request, trailing, writer)? { return Ok(true); }
    if search::serve(profile, request, trailing, writer)? { return Ok(true); }
    if branches::serve(profile, request, trailing, writer)? { return Ok(true); }
    if history::serve(profile, request, trailing, writer)? { return Ok(true); }
    if initial::serve(profile, request, trailing, writer)? { return Ok(true); }
    if source_edit::serve(profile, request, trailing, writer)? { return Ok(true); }
    if pulls::serve(profile, request, trailing, writer)? { return Ok(true); }
    let Some((media, body)) = checked_asset(
        &profile.route, profile.allow_source, profile.allow_issues, profile.maximum_response_bytes,
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
        for suffix in ["/ui/", "/ui/browser.mjs", "/ui/browser.css", "/ui/issues/", "/ui/issues.mjs", "/ui/issues-view.mjs"] {
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
        for script in [ISSUES_CLIENT, ISSUES_VIEW] {
            assert!(!script.contains("innerHTML"));
            assert!(!script.contains("localStorage"));
            assert!(!script.contains("sessionStorage"));
        }
        assert!(!ISSUES_HTML.contains("<script>"));
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
            assert_eq!(checked_asset(b"/repo.git", enabled, false, maximum, &request, trailing).is_ok(), allowed);
        }
    }

    #[test]
    fn issue_and_source_shells_keep_independent_profile_ceilings() {
        use fgit_wire::smart_http::{HttpLimits, head};
        for source in [false, true] {
            for issues in [false, true] {
                for (suffix, allowed) in [
                    ("/ui/", source), ("/ui/browser.mjs", source),
                    ("/ui/issues/", issues), ("/ui/issues.mjs", issues),
                    ("/ui/issues-view.mjs", issues), ("/ui/browser.css", source || issues),
                ] {
                    let bytes = format!("GET /repo.git{suffix} HTTP/1.1\r\nHost: local\r\n\r\n");
                    let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
                    assert_eq!(checked_asset(b"/repo.git", source, issues, u64::MAX, &envelope, false).is_ok(), allowed);
                }
            }
        }
    }

    #[test]
    fn issue_shell_cannot_smuggle_bodies_queries_or_native_mutations() {
        use fgit_wire::smart_http::{HttpLimits, head};
        for (method, suffix, header, trailing, maximum) in [
            ("POST", "/ui/issues/", "", false, u64::MAX),
            ("GET", "/ui/issues/?token=secret", "", false, u64::MAX),
            ("GET", "/ui/issues/", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "/ui/issues.mjs", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "/ui/issues-view.mjs", "", true, u64::MAX),
            ("GET", "/ui/issues/", "", false, 1),
        ] {
            let bytes = format!("{method} /repo.git{suffix} HTTP/1.1\r\nHost: local\r\n{header}\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(checked_asset(b"/repo.git", false, true, maximum, &envelope, trailing).is_err());
        }
        assert!(asset(b"/repo.git", "/repo.git/api/v1/issues/1/open").is_none());
    }

}
