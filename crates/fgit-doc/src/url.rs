//! Destination policy for links, images, and autolinks.
//!
//! The policy is applied at parse time and recorded in the tree, so every
//! surface makes the same decision about the same destination. A rejected
//! destination is never emitted as a navigable target by any renderer; the
//! construct degrades to its visible text.

use crate::ast::{UrlRejection, UrlVerdict};

/// Longest destination this crate will treat as navigable.
pub(crate) const MAX_URL_BYTES: usize = 4096;

/// Schemes that may appear in a rendered navigable target.
const NAVIGABLE_SCHEMES: [&str; 3] = ["http", "https", "mailto"];

/// Applies the destination policy to a raw source destination.
///
/// A destination with no scheme is a relative reference and is accepted. A
/// destination with a scheme is accepted only if the scheme is on the
/// navigable allowlist, compared case-insensitively.
pub(crate) fn classify(destination: &str) -> UrlVerdict {
    let trimmed = destination.trim_matches(is_url_trim);
    if trimmed.len() > MAX_URL_BYTES {
        return UrlVerdict::Rejected(UrlRejection::TooLong);
    }
    if trimmed.chars().any(is_url_forbidden) {
        return UrlVerdict::Rejected(UrlRejection::ControlCharacter);
    }
    match scheme_of(trimmed) {
        None => UrlVerdict::Allowed,
        Some(scheme) => {
            if NAVIGABLE_SCHEMES
                .iter()
                .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
            {
                UrlVerdict::Allowed
            } else {
                UrlVerdict::Rejected(UrlRejection::DisallowedScheme)
            }
        }
    }
}

/// Applies the destination policy to an autolink, which must be absolute.
pub(crate) fn classify_autolink(destination: &str) -> UrlVerdict {
    match classify(destination) {
        UrlVerdict::Rejected(reason) => UrlVerdict::Rejected(reason),
        UrlVerdict::Allowed => {
            if scheme_of(destination.trim_matches(is_url_trim)).is_some() {
                UrlVerdict::Allowed
            } else {
                UrlVerdict::Rejected(UrlRejection::DisallowedScheme)
            }
        }
    }
}

/// Whether a destination looks like a bare email address.
pub(crate) fn is_email_like(candidate: &str) -> bool {
    let mut parts = candidate.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    if local.is_empty() || domain.is_empty() || !domain.contains('.') {
        return false;
    }
    local
        .chars()
        .all(|value| value.is_ascii_alphanumeric() || ".!#$%&'*+/=?^_`{|}~-".contains(value))
        && domain
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || value == '.' || value == '-')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// Leading scheme of a destination, without its colon.
fn scheme_of(destination: &str) -> Option<&str> {
    let colon = destination.find(':')?;
    let scheme = destination.get(..colon)?;
    let mut characters = scheme.chars();
    let first = characters.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if characters.all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '.' | '-')) {
        Some(scheme)
    } else {
        None
    }
}

/// Characters trimmed from both ends before the policy is applied.
fn is_url_trim(value: char) -> bool {
    value.is_ascii_whitespace() || value.is_control()
}

/// Characters that make a destination unusable as a navigable target.
///
/// Control characters and raw whitespace are the classic scheme-smuggling
/// vehicle, so they are rejected rather than stripped.
fn is_url_forbidden(value: char) -> bool {
    value.is_control() || value.is_whitespace()
}
