//! Default-branch administration shell; all authority stays in native APIs.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/default-branch/" => Some((
            "text/html; charset=utf-8",
            include_str!("default-branch.html"),
        )),
        b"/ui/default-branch/default-branch.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("default-branch.mjs"),
        )),
        b"/ui/default-branch/default-branch-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("default-branch-view.mjs"),
        )),
        b"/ui/default-branch/branches.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("branches.mjs"),
        )),
        b"/ui/default-branch/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        b"/ui/default-branch/pulls-actions.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-actions.mjs"),
        )),
        b"/ui/default-branch/pulls-comments.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-comments.mjs"),
        )),
        b"/ui/default-branch/pulls-candidate.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-candidate.mjs"),
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
        profile.allow_source(),
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
    fn every_default_branch_asset_and_import_is_source_scoped() {
        for suffix in [
            "",
            "default-branch.mjs",
            "default-branch-view.mjs",
            "branches.mjs",
            "pulls-core.mjs",
            "pulls-actions.mjs",
            "pulls-comments.mjs",
            "pulls-candidate.mjs",
        ] {
            let target = format!("/repo.git/ui/default-branch/{suffix}");
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
            "/repo.git-more/ui/default-branch/",
            "/repo.git/ui/default-branch/../private",
            "/repo.git/ui/default-branch/%2e%2e",
            "/repo.git/api/v1/default-branch",
            "/repo.git/ui/branches/",
            "/repo.git/ui/pulls/",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }

    #[test]
    fn static_shell_rejects_mutation_framing_queries_and_excess_response_size() {
        for (method, query, headers, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX),
            ("GET", "?token=secret", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX),
            ("GET", "", "", false, 1),
        ] {
            let bytes = format!(
                "{method} /repo.git/ui/default-branch/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &request, trailing).is_err());
        }
    }

    #[test]
    fn shell_exposes_exact_expectations_without_persistent_credentials() {
        assert!(!include_str!("default-branch.html").contains("<script>"));
        for source in [
            include_str!("default-branch.mjs"),
            include_str!("default-branch-view.mjs"),
        ] {
            for forbidden in [
                "innerHTML",
                "localStorage",
                "sessionStorage",
                "document.write",
            ] {
                assert!(!source.contains(forbidden));
            }
        }
        let shell = include_str!("default-branch.html");
        assert!(shell.contains("default-branch-write"));
        assert!(shell.contains("Original") || shell.contains("original"));
        assert!(shell.contains("unborn"));
        assert!(shell.contains("confirm-send"));
    }
}
