//! Discussion assets are enabled independently of source, issue and PR APIs.
//! Local helper aliases provide the shared transport without enabling issue reads.
use super::{Profile, SECURITY, Status};
use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};
use std::io::Write;

fn asset(route: &[u8], target: &str) -> Option<(&'static str, &'static str)> {
    match target.split('?').next()?.as_bytes().strip_prefix(route)? {
        b"/ui/discussion-notifications/" => Some((
            "text/html; charset=utf-8",
            include_str!("discussion-notifications.html"),
        )),
        b"/ui/discussion-notifications/notifications.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("notifications.mjs"),
        )),
        b"/ui/discussion-notifications/notifications-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("notifications-view.mjs"),
        )),
        b"/ui/discussion-notifications/issues.mjs" => {
            Some(("text/javascript; charset=utf-8", include_str!("issues.mjs")))
        }
        b"/ui/discussion-notifications/browser.css" => {
            Some(("text/css; charset=utf-8", include_str!("browser.css")))
        }
        b"/ui/discussions/" => Some(("text/html; charset=utf-8", include_str!("discussions.html"))),
        b"/ui/discussions/discussions.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("discussions.mjs"),
        )),
        b"/ui/discussions/discussions-view.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("discussions-view.mjs"),
        )),
        b"/ui/discussions/issues.mjs" => {
            Some(("text/javascript; charset=utf-8", include_str!("issues.mjs")))
        }
        b"/ui/discussions/markdown.mjs" => Some((
            "text/javascript; charset=utf-8",
            include_str!("markdown.mjs"),
        )),
        b"/ui/discussions/browser.css" => {
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
        profile.config.http_discussions_enabled(),
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
    fn every_discussion_asset_requires_its_independent_profile_and_bounded_get() {
        for suffix in [
            "discussions/",
            "discussions/discussions.mjs",
            "discussions/discussions-view.mjs",
            "discussions/issues.mjs",
            "discussions/markdown.mjs",
            "discussions/browser.css",
            "discussion-notifications/",
            "discussion-notifications/notifications.mjs",
            "discussion-notifications/notifications-view.mjs",
            "discussion-notifications/issues.mjs",
            "discussion-notifications/browser.css",
        ] {
            let target = format!("/repo.git/ui/{suffix}");
            let bytes =
                format!("GET {target} HTTP/1.1\r\nHost: local\r\nContent-Length: 0\r\n\r\n");
            let request = head::parse(bytes.as_bytes(), HttpLimits::default())
                .unwrap()
                .unwrap();
            let found @ (_, body) = asset(b"/repo.git", &target).unwrap();
            assert!(!body.is_empty());
            assert_eq!(
                checked_asset(b"/repo.git", true, body.len() as u64, &request, false),
                Ok(Some(found))
            );
            assert_eq!(
                checked_asset(b"/repo.git", false, body.len() as u64, &request, false),
                Err(Status::NotFound)
            );
            assert_eq!(
                checked_asset(b"/repo.git", true, body.len() as u64 - 1, &request, false),
                Err(Status::TooLarge)
            );
            assert_eq!(
                checked_asset(b"/repo.git", true, body.len() as u64, &request, true),
                Err(Status::BadRequest)
            );
            assert!(asset(b"/other.git", &target).is_none());
        }
    }
}
