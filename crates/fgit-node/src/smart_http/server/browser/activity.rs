//! Static activity assets contain no repository data or authority. The native
//! event endpoint independently authenticates issue and pull-request read grants.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/activity/" => Some(("text/html; charset=utf-8", include_str!("activity.html"))),
        b"/ui/activity/activity.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("activity.mjs"),
        )),
        b"/ui/activity/activity-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("activity-view.mjs"),
        )),
        // Serve the existing stylesheet within this independently enabled shell.
        b"/ui/activity/browser.css" => Some((
            "text/css; charset=utf-8",
            include_str!("browser.css"),
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
        profile.allow_issues || profile.allow_pulls,
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
    fn activity_assets_require_exact_repository_routes_and_a_forge_profile() {
        for suffix in ["", "activity.mjs", "activity-view.mjs", "browser.css"] {
            let target = format!("/repo.git/ui/activity/{suffix}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            for issues in [false, true] {
                for pulls in [false, true] {
                    let result = checked_asset(
                        b"/repo.git",
                        issues || pulls,
                        u64::MAX,
                        &request,
                        false,
                    );
                    if issues || pulls {
                        assert!(result.unwrap().is_some());
                    } else {
                        assert!(result.is_err());
                    }
                }
            }
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in [
            "/repo.git-more/ui/activity/",
            "/repo.git/ui/activity/../private",
            "/repo.git/ui/activity/%2e%2e",
            "/repo.git/api/v1/events",
            "/repo.git/ui/activity/unknown.mjs",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }

    #[test]
    fn activity_assets_refuse_body_query_protocol_and_budget_smuggling() {
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
                "{method} /repo.git/ui/activity/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }

    #[test]
    fn activity_keeps_the_existing_csp_and_ephemeral_credentials() {
        assert!(!include_str!("activity.html").contains("<script>"));
        for script in [include_str!("activity.mjs"), include_str!("activity-view.mjs")] {
            for forbidden in ["innerHTML", "localStorage", "sessionStorage", "document.write"] {
                assert!(!script.contains(forbidden));
            }
        }
        assert!(SECURITY.contains("frame-ancestors 'none'"));
        assert!(SECURITY.contains("form-action 'none'"));
        assert!(SECURITY.contains("Cache-Control: no-store"));
    }
}
