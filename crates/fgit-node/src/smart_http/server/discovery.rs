//! Credential-filtered discovery of the fixed HTTP deployment catalog.
//!
//! These are routing hints, not a canonical repository registry or an authority
//! snapshot. Every row requires a fresh, independently bound read grant. The
//! complete catalog is checked before any successful response is written; a
//! broken credential source cannot silently turn into an incomplete listing.

use std::io::{self, Write};

use fgit_wire::smart_http::{BodyFraming, HttpVersion, head::Envelope};

use super::credentials::{CredentialFailure, CredentialSource};
use super::routing::{MAX_HTTP_REPOSITORY_ROUTES, Profiles};
use super::{Profile, Status, bearer_only, issues};
use crate::GitDaemonSessionDeadline;

#[cfg(test)]
mod tests;

const API: &str = "/api/v1/repositories";
const HOME: &str = "/ui/";
const SCRIPT_PATH: &str = "/ui/repositories.mjs";
const STYLE_PATH: &str = "/ui/repositories.css";
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_PATH_BYTES: usize = 512;
const HTML: &str = include_str!("discovery/index.html");
const SCRIPT: &str = include_str!("discovery/repositories.mjs");
const STYLE: &str = include_str!("discovery/repositories.css");
const SECURITY: &str = concat!(
    "Cache-Control: no-store\r\n",
    "Vary: Authorization\r\n",
    "X-Content-Type-Options: nosniff\r\n",
    "Referrer-Policy: no-referrer\r\n",
    "Cross-Origin-Opener-Policy: same-origin\r\n",
    "Cross-Origin-Resource-Policy: same-origin\r\n",
    "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; ",
    "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'\r\n",
);

pub(super) fn is_route(target: &str) -> bool {
    matches!(
        target.split('?').next(),
        Some(API | HOME | SCRIPT_PATH | STYLE_PATH)
    )
}

/// Called after the listener-wide cross-site check and before selecting a
/// repository. The caller retains the original deadline on its response writer.
pub(super) fn serve(
    ingress: &Profile,
    routes: Option<&Profiles>,
    request: &Envelope<'_>,
    trailing: &[u8],
    writer: &mut impl Write,
    deadline: &GitDaemonSessionDeadline,
) -> Result<(), Status> {
    let maximum = usize::try_from(ingress.maximum_response_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_RESPONSE_BYTES);
    let result = (|| {
        validate_request(request, trailing)?;
        if deadline.expired() {
            return Err(Status::Timeout);
        }
        if request.target == API {
            let body = collect(
                ingress,
                routes,
                request.authorization(),
                maximum,
                &mut || !deadline.expired(),
            )?;
            return Ok((
                "application/json; charset=utf-8",
                std::borrow::Cow::Owned(body),
            ));
        }
        let (media, body) = match request.target {
            HOME => ("text/html; charset=utf-8", HTML),
            SCRIPT_PATH => ("text/javascript; charset=utf-8", SCRIPT),
            STYLE_PATH => ("text/css; charset=utf-8", STYLE),
            _ => return Err(Status::NotFound),
        };
        if body.len() > maximum {
            return Err(Status::TooLarge);
        }
        Ok((media, std::borrow::Cow::Borrowed(body)))
    })();
    let result = result.and_then(|reply| {
        if deadline.expired() {
            Err(Status::Timeout)
        } else {
            Ok(reply)
        }
    });
    match result {
        Ok((media, body)) => send(writer, request.version, Status::Success, media, &body)
            .map_err(|_| Status::Unavailable),
        Err(status) => {
            let body = format!(
                "{{\"type\":\"repository_discovery_error\",\"schema_version\":1,\"code\":{},\"outcome_unknown\":false}}",
                issues::quote(error_code(status)),
            );
            send(
                writer,
                request.version,
                status,
                "application/json; charset=utf-8",
                &body,
            )
            .map_err(|_| Status::Unavailable)?;
            Err(status)
        }
    }
}

fn validate_request(request: &Envelope<'_>, trailing: &[u8]) -> Result<(), Status> {
    if request.method != "GET" {
        return Err(Status::Method);
    }
    if !is_route(request.target)
        || request.target.contains('?')
        || request.git_protocol.is_some()
        || request.expect_continue
        || !trailing.is_empty()
        || !matches!(
            request.body,
            BodyFraming::Empty | BodyFraming::ContentLength(0)
        )
    {
        return Err(Status::BadRequest);
    }
    Ok(())
}

fn collect(
    ingress: &Profile,
    routes: Option<&Profiles>,
    authorization: Option<&str>,
    maximum: usize,
    live: &mut impl FnMut() -> bool,
) -> Result<String, Status> {
    // Root discovery cannot select a repository in which to validate a sponsored
    // credential. Never downgrade one to a static token or probe other issuers.
    let authorization = bearer_only(authorization).ok_or(Status::Unauthorized)?;
    let (_, token) = authorization.split_once(' ').ok_or(Status::Unauthorized)?;
    if token.len() != 64
        || !token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Status::Unauthorized);
    }
    let mut profiles = Vec::new();
    profiles
        .try_reserve_exact(MAX_HTTP_REPOSITORY_ROUTES)
        .map_err(|_| Status::Unavailable)?;
    match routes {
        Some(Profiles::Routed { routes, .. }) => {
            if routes.is_empty() || routes.len() > MAX_HTTP_REPOSITORY_ROUTES {
                return Err(Status::Unavailable);
            }
            for (path, profile) in routes {
                if path.as_bytes() != profile.route {
                    return Err(Status::Unavailable);
                }
                profiles.push(profile);
            }
        }
        Some(Profiles::Single(profile)) => profiles.push(profile),
        None => profiles.push(ingress),
    }
    let mut matched = false;
    let mut visible = Vec::new();
    visible
        .try_reserve_exact(profiles.len())
        .map_err(|_| Status::Unavailable)?;
    for profile in profiles {
        if !live() {
            return Err(Status::Timeout);
        }
        // Only startup-owned sources can participate in the deployment catalog.
        // A per-request canonical agent grant must never escape its bound route.
        if matches!(profile.credentials, CredentialSource::AgentRequest { .. }) {
            return Err(Status::Unavailable);
        }
        let grant = match profile.credentials.authenticate(Some(authorization)) {
            Ok(grant) => grant,
            Err(CredentialFailure::UnknownCredential) => continue,
            Err(error) => return Err(Status::from(error)),
        };
        if !live() {
            return Err(Status::Timeout);
        }
        matched = true;
        if grant.permits_source_read() {
            let path = std::str::from_utf8(&profile.route).map_err(|_| Status::Unavailable)?;
            if !safe_path(path) {
                return Err(Status::Unavailable);
            }
            visible.push((path, profile, grant.principal));
        }
    }
    if !live() {
        return Err(Status::Timeout);
    }
    if visible.is_empty() {
        return Err(if matched {
            Status::Forbidden
        } else {
            Status::Unauthorized
        });
    }
    visible.sort_unstable_by(|left, right| left.0.cmp(right.0));
    let mut body = String::new();
    append(
        &mut body,
        "{\"type\":\"repository_catalog\",\"schema_version\":1,\"complete\":true,\"repositories\":[",
        maximum,
    )?;
    for (index, (path, profile, principal)) in visible.iter().enumerate() {
        if !live() {
            return Err(Status::Timeout);
        }
        profile
            .source_quota
            .evaluate(principal)
            .map_err(|_| Status::RateLimited)?;
        if index != 0 {
            append(&mut body, ",", maximum)?;
        }
        let source_url = if profile.allow_source() {
            issues::quote(&format!("{path}/ui/"))
        } else {
            "null".to_owned()
        };
        append(
            &mut body,
            &format!(
                "{{\"path\":{},\"source_url\":{source_url}}}",
                issues::quote(path)
            ),
            maximum,
        )?;
    }
    append(&mut body, "]}", maximum)?;
    if !live() {
        return Err(Status::Timeout);
    }
    Ok(body)
}

// Catalog routes already satisfy this. Single-repository listeners may have a
// broader Git-daemon lookup key; discovery refuses keys that cannot safely be
// used as literal same-origin HTTP links, rather than normalizing or aliasing.
fn safe_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && path.strip_prefix('/').is_some_and(|path| {
            path.split('/').all(|component| {
                !component.is_empty()
                    && component != "."
                    && component != ".."
                    && !component.starts_with('-')
                    && component
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
        })
}

fn append(body: &mut String, text: &str, maximum: usize) -> Result<(), Status> {
    if body
        .len()
        .checked_add(text.len())
        .is_none_or(|size| size > maximum.min(MAX_RESPONSE_BYTES))
    {
        return Err(Status::TooLarge);
    }
    body.try_reserve(text.len())
        .map_err(|_| Status::Unavailable)?;
    body.push_str(text);
    Ok(())
}

fn error_code(status: Status) -> &'static str {
    match status {
        Status::Unauthorized => "authentication_required",
        Status::Forbidden => "read_scope_required",
        Status::Method => "method_not_allowed",
        Status::Timeout => "request_timeout",
        Status::TooLarge => "response_too_large",
        Status::RateLimited => "rate_limited",
        Status::NotFound => "not_found",
        Status::Unavailable => "catalog_unavailable",
        _ => "invalid_request",
    }
}

fn send(
    writer: &mut impl Write,
    version: HttpVersion,
    status: Status,
    media: &str,
    body: &str,
) -> io::Result<()> {
    let version = match version {
        HttpVersion::Http10 => "HTTP/1.0",
        HttpVersion::Http11 => "HTTP/1.1",
    };
    let extra = match status {
        Status::Unauthorized => "WWW-Authenticate: Bearer realm=\"frankengit\"\r\n",
        Status::RateLimited => "Retry-After: 60\r\n",
        Status::Method => "Allow: GET\r\n",
        _ => "",
    };
    write!(
        writer,
        "{version} {}\r\nContent-Type: {media}\r\nContent-Length: {}\r\n{SECURITY}{extra}Connection: close\r\n\r\n{body}",
        status.line(),
        body.len()
    )?;
    writer.flush()
}
