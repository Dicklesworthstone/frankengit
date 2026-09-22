//! Source-gated portable transfer shell. Assets contain no private repository
//! data, grants or authority; API requests still authenticate independently.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/transfers/" => Some(("text/html; charset=utf-8", include_str!("transfers.html"))),
        b"/ui/transfers/transfers.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("transfers.mjs"),
        )),
        b"/ui/transfers/transfers-protocol.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("transfers-protocol.mjs"),
        )),
        b"/ui/transfers/transfers-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("transfers-view.mjs"),
        )),
        b"/ui/transfers/transfers.css" => {
            Some(("text/css; charset=utf-8", include_str!("transfers.css")))
        }
        // Shared bytes confer no PR/source-edit/initial/branch permission.
        b"/ui/transfers/pulls-core.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-core.mjs"),
        )),
        b"/ui/transfers/pulls-candidate.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-candidate.mjs"),
        )),
        b"/ui/transfers/pulls-actions.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("pulls-actions.mjs"),
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
    fn transfer_assets_are_exactly_source_scoped_without_enabling_other_operations() {
        for suffix in [
            "",
            "transfers.mjs",
            "transfers-protocol.mjs",
            "transfers-view.mjs",
            "transfers.css",
            "pulls-core.mjs",
            "pulls-candidate.mjs",
            "pulls-actions.mjs",
        ] {
            let target = format!("/repo.git/ui/transfers/{suffix}");
            let bytes = format!("GET {target} HTTP/1.1\r\nHost: local\r\n\r\n");
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(
                checked_asset(b"/repo.git", true, u64::MAX, &envelope, false)
                    .unwrap()
                    .is_some()
            );
            assert!(checked_asset(b"/repo.git", false, u64::MAX, &envelope, false).is_err());
            assert!(asset(b"/other.git", &target).is_none());
        }
        for target in [
            "/repo.git-more/ui/transfers/",
            "/repo.git/ui/transfers/../private",
            "/repo.git/ui/transfers/%2e%2e",
            "/repo.git/ui/pulls/",
            "/repo.git/api/v1/source/bundle/import",
        ] {
            assert!(asset(b"/repo.git", target).is_none());
        }
    }
    #[test]
    fn static_transfer_assets_refuse_bodies_protocol_parameters_queries_and_byte_overruns() {
        for (method, query, headers, trailing, maximum) in [
            ("POST", "", "", false, u64::MAX),
            ("GET", "?token=private", "", false, u64::MAX),
            ("GET", "", "Content-Length: 1\r\n", false, u64::MAX),
            ("GET", "", "Transfer-Encoding: chunked\r\n", false, u64::MAX),
            ("GET", "", "Expect: 100-continue\r\n", false, u64::MAX),
            ("GET", "", "Git-Protocol: version=2\r\n", false, u64::MAX),
            ("GET", "", "", true, u64::MAX),
            ("GET", "", "", false, 1),
        ] {
            let bytes = format!(
                "{method} /repo.git/ui/transfers/{query} HTTP/1.1\r\nHost: local\r\n{headers}\r\n"
            );
            let envelope = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            assert!(checked_asset(b"/repo.git", true, maximum, &envelope, trailing).is_err());
        }
    }
    #[test]
    fn transfer_ui_keeps_native_text_inert_and_reuses_the_strict_security_policy() {
        assert!(!include_str!("transfers.html").contains("<script>"));
        for script in [
            include_str!("transfers.mjs"),
            include_str!("transfers-protocol.mjs"),
            include_str!("transfers-view.mjs"),
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
    }
}
