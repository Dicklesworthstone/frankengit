//! Static protection administration over the existing independently granted API.
//! Public assets contain no policy state and never expand credential permissions.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/protection/" => Some(("text/html; charset=utf-8", include_str!("protection.html"))),
        b"/ui/protection/protection-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("protection-view.mjs"),
        )),
        b"/ui/protection/pulls-actions.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-actions.mjs"),
        )),
        b"/ui/protection/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        b"/ui/protection/pulls-candidate.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-candidate.mjs"),
        )),
        b"/ui/protection/browser.css" => {
            Some(("text/css; charset=utf-8", include_str!("browser.css")))
        }
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
        profile.config.http_protection_admin_enabled(),
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
    fn protection_assets_use_exact_routes_and_the_independent_profile() {
        for suffix in [
            "",
            "protection-view.mjs",
            "pulls-actions.mjs",
            "pulls-core.mjs",
            "pulls-candidate.mjs",
            "browser.css",
        ] {
            let target = format!("/repo.git/ui/protection/{suffix}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(
                checked_asset(b"/repo.git", true, u64::MAX, &request, false)
                    .unwrap()
                    .is_some()
            );
            assert!(matches!(
                checked_asset(b"/repo.git", false, u64::MAX, &request, false),
                Err(Status::NotFound)
            ));
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in [
            "/repo.git-more/ui/protection/",
            "/repo.git/ui/protection/../private",
            "/repo.git/ui/protection/%2e%2e",
            "/repo.git/api/v1/protection",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }

    #[test]
    fn protection_shell_rejects_mutation_framing_and_has_no_embedded_authority() {
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
                "{method} /repo.git/ui/protection/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
        assert!(!include_str!("protection.html").contains("<script>"));
        let script = include_str!("protection-view.mjs");
        for forbidden in ["innerHTML", "localStorage", "sessionStorage", "document.write"] {
            assert!(!script.contains(forbidden));
        }
        assert!(SECURITY.contains("frame-ancestors 'none'"));
    }
}
