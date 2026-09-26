//! Source-enabled code-search shell. Static bytes never confer source or write
//! authority; every API request passes through the existing source read gate.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/search/" => Some(("text/html; charset=utf-8", include_str!("search.html"))),
        b"/ui/search/search.mjs" => {
            Some(("text/javascript; charset=utf-8", include_str!("search.mjs")))
        }
        b"/ui/search/search-index.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("search-index.mjs"),
        )),
        b"/ui/search/search-current.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("search-current.mjs"),
        )),
        b"/ui/search/search-data.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("search-data.mjs"),
        )),
        b"/ui/search/search-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("search-view.mjs"),
        )),
        b"/ui/search/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        b"/ui/search/search.css" => Some(("text/css; charset=utf-8", include_str!("search.css"))),
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
    fn search_assets_require_exact_source_routes_and_source_enablement() {
        for suffix in [
            "",
            "search.mjs",
            "search-data.mjs",
            "search-index.mjs",
            "search-current.mjs",
            "search-view.mjs",
            "pulls-core.mjs",
            "search.css",
        ] {
            let target = format!("/repo.git/ui/search/{suffix}");
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
            "/repo.git-more/ui/search/",
            "/repo.git/ui/search/../private",
            "/repo.git/ui/search/%2e%2e",
            "/repo.git/api/v1/source/search",
            "/repo.git/ui/pulls/",
            "/repo.git/ui/search/unknown.mjs",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }
    #[test]
    fn search_assets_refuse_bodies_queries_protocol_options_and_response_overflow() {
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
                "{method} /repo.git/ui/search/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }
    #[test]
    fn search_keeps_repository_text_inert_and_credentials_ephemeral() {
        assert!(!include_str!("search.html").contains("<script>"));
        for script in [
            include_str!("search.mjs"),
            include_str!("search-data.mjs"),
            include_str!("search-index.mjs"),
            include_str!("search-current.mjs"),
            include_str!("search-view.mjs"),
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
        assert!(
            include_str!("search.html").contains("id=\"submit-search\" type=\"submit\" disabled")
        );
    }
}
