//! Static merge-queue workflow over the independently granted native APIs.
//! Local helper aliases permit queue-only deployments without enabling PR views.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/queues/" => Some(("text/html; charset=utf-8", include_str!("queues.html"))),
        b"/ui/queues/queues.mjs" => {
            Some(("text/javascript; charset=utf-8", include_str!("queues.mjs")))
        }
        b"/ui/queues/queues-protocol.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("queues-protocol.mjs"),
        )),
        b"/ui/queues/queues-candidate.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("queues-candidate.mjs"),
        )),
        b"/ui/queues/queues-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("queues-view.mjs"),
        )),
        b"/ui/queues/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        b"/ui/queues/pulls-actions.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-actions.mjs"),
        )),
        // The immutable recovery helper imports these modules relatively.
        b"/ui/queues/pulls-candidate.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-candidate.mjs"),
        )),
        b"/ui/queues/pulls-comments.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-comments.mjs"),
        )),
        b"/ui/queues/browser.css" => Some(("text/css; charset=utf-8", include_str!("browser.css"))),
        _ => None,
    }
}

fn checked_asset(
    route: &[u8],
    management_enabled: bool,
    landings_enabled: bool,
    maximum: u64,
    request: &Envelope<'_>,
    trailing: bool,
) -> Result<Option<(&'static str, &'static str)>, Status> {
    let Some(found @ (_, body)) = asset(route, request.target) else {
        return Ok(None);
    };
    if !management_enabled && !landings_enabled {
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
        profile.config.http_queue_management_enabled(),
        profile.config.http_queue_landings_enabled(),
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
    fn queue_assets_and_all_imports_work_under_either_independent_queue_profile() {
        for suffix in [
            "",
            "queues.mjs",
            "queues-protocol.mjs",
            "queues-candidate.mjs",
            "queues-view.mjs",
            "pulls-core.mjs",
            "pulls-actions.mjs",
            "pulls-candidate.mjs",
            "pulls-comments.mjs",
            "browser.css",
        ] {
            let target = format!("/repo.git/ui/queues/{suffix}");
            let bytes =
                format!("GET {target} HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let found @ (media, body) = asset(b"/repo.git", &target).unwrap();
            assert!(!body.is_empty());
            assert_eq!(
                media,
                if suffix.is_empty() {
                    "text/html; charset=utf-8"
                } else if suffix.ends_with(".css") {
                    "text/css; charset=utf-8"
                } else {
                    "text/javascript; charset=utf-8"
                }
            );
            for management in [false, true] {
                for landings in [false, true] {
                    let result = checked_asset(
                        b"/repo.git",
                        management,
                        landings,
                        body.len() as u64,
                        &request,
                        false,
                    );
                    assert_eq!(
                        result,
                        if management || landings {
                            Ok(Some(found))
                        } else {
                            Err(Status::NotFound)
                        },
                        "{suffix}: management={management}, landings={landings}"
                    );
                }
            }
            assert_eq!(
                checked_asset(
                    b"/repo.git",
                    true,
                    false,
                    body.len() as u64 - 1,
                    &request,
                    false,
                ),
                Err(Status::TooLarge)
            );
            assert!(asset(b"/other.git", &target).is_none());
        }
    }

    #[test]
    fn queue_aliases_never_match_other_browser_surfaces_or_api_routes() {
        for target in [
            "/repo.git-more/ui/queues/",
            "/repo.git/ui/queues",
            "/repo.git/ui/queues/../private",
            "/repo.git/ui/queues/%2e%2e",
            "/repo.git/ui/queues/%71ueues.mjs",
            "/repo.git/ui/queues/unknown.mjs",
            "/repo.git/ui/queues.html",
            "/repo.git/ui/queues.mjs",
            "/repo.git/ui/",
            "/repo.git/ui/browser.css",
            "/repo.git/ui/pulls/",
            "/repo.git/ui/pulls-core.mjs",
            "/repo.git/ui/protection/",
            "/repo.git/api/v1/queues",
            "/repo.git/api/v1/queues/1/land",
        ] {
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                checked_asset(b"/repo.git", true, true, u64::MAX, &request, false),
                Ok(None),
                "{target}"
            );
        }
    }

    #[test]
    fn queue_shell_keeps_exact_get_framing_and_shared_security_policy() {
        for (method, query, headers, trailing, expected) in [
            ("POST", "", "", false, Status::Method),
            ("HEAD", "", "", false, Status::Method),
            ("GET", "?token=secret", "", false, Status::BadRequest),
            (
                "GET",
                "",
                "Content-Length: 1\r\n",
                false,
                Status::BadRequest,
            ),
            (
                "GET",
                "",
                "Transfer-Encoding: chunked\r\n",
                false,
                Status::BadRequest,
            ),
            (
                "GET",
                "",
                "Expect: 100-continue\r\n",
                false,
                Status::BadRequest,
            ),
            (
                "GET",
                "",
                "Git-Protocol: version=2\r\n",
                false,
                Status::BadRequest,
            ),
            ("GET", "", "", true, Status::BadRequest),
        ] {
            let bytes = format!(
                "{method} /repo.git/ui/queues/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert_eq!(
                checked_asset(b"/repo.git", false, true, u64::MAX, &request, trailing),
                Err(expected)
            );
        }
        let html = include_str!("queues.html");
        assert!(!html.contains("<script>"));
        assert!(html.contains("href=\"./browser.css\""));
        assert!(html.contains("src=\"./queues-view.mjs\""));
        assert!(!SECURITY.contains("unsafe-inline"));
        assert!(SECURITY.contains("connect-src 'self'"));
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(SECURITY.contains("form-action 'none'"));
        assert!(SECURITY.contains("Cache-Control: no-store"));
    }
}
