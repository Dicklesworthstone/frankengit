//! Closed read-only source requests. References select authority-owned commits;
//! expected OIDs are comparisons, never an arbitrary-object lookup capability.

use std::collections::BTreeMap;
use fgit_forge::source_browse::{SourceBrowseAction, SourceBrowseQuery};
use fgit_forge::source_search::{SearchCase, SearchLimits, SourceQuery};
use fgit_types::{GitHashAlgorithm, GitOid, RefName, RepositoryAuthorityHeadId};
use fgit_wire::smart_http::{BodyFraming, head::Envelope};
use super::super::issues::{ApiError, MAX_FORM_BYTES, parse_decimal, parse_form, parse_snapshot};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation { Tree, Blob, Search }
#[derive(Debug)]
pub(crate) struct Request<'a> {
    pub repository_route: &'a str,
    pub operation: Operation,
}
impl<'a> Request<'a> {
    pub(crate) fn parse(head: &Envelope<'a>) -> Result<Self, ApiError> {
        let (path, query) = head.target.split_once('?').map_or((head.target, None), |(p, q)| (p, Some(q)));
        let (repository_route, action) = path.split_once("/api/v1/source/").ok_or_else(ApiError::not_found)?;
        if repository_route.len() < 2 || !repository_route.starts_with('/')
            || repository_route[1..].split('/').any(|part| part.is_empty() || matches!(part, "." | "..")
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b)))
        { return Err(ApiError::not_found()); }
        let operation = match action { "tree" => Operation::Tree, "blob" => Operation::Blob,
            "search" => Operation::Search, _ => return Err(ApiError::not_found()) };
        if head.method != "POST" { return Err(ApiError::method()); }
        if query.is_some() || head.body == BodyFraming::Empty || head.git_protocol.is_some() {
            return Err(ApiError::bad("invalid_source_envelope"));
        }
        if !head.content_type.is_some_and(|media| media.eq_ignore_ascii_case("application/x-www-form-urlencoded")
            || media.eq_ignore_ascii_case("application/x-www-form-urlencoded; charset=utf-8"))
        { return Err(ApiError::media()); }
        if matches!(head.body, BodyFraming::ContentLength(n) if n > MAX_FORM_BYTES as u64) {
            return Err(ApiError::too_large());
        }
        Ok(Self { repository_route, operation })
    }

    pub(super) fn command(&self, bytes: &[u8], format: GitHashAlgorithm) -> Result<Command, ApiError> {
        let mut fields = BTreeMap::new();
        let mut prefixes = Vec::new();
        for (name, value) in parse_form(bytes, 140)? {
            if name == "path_prefix_hex" && self.operation == Operation::Search {
                if prefixes.len() == 128 { return Err(ApiError::too_large()); }
                prefixes.push(unhex(&value, 4096)?);
                continue;
            }
            let common = matches!(name.as_str(), "ref" | "object_format" | "expected_head" | "expected_commit");
            let applicable = match self.operation {
                Operation::Tree => matches!(name.as_str(), "path_hex" | "after_hex" | "limit"),
                Operation::Blob => matches!(name.as_str(), "path_hex" | "offset" | "limit"),
                Operation::Search => matches!(name.as_str(), "needle_hex" | "case" | "max_matches" | "max_bytes" | "max_file_bytes"),
            };
            if !common && !applicable { return Err(ApiError::bad("unknown_or_inapplicable_field")); }
            if fields.insert(name, value).is_some() { return Err(ApiError::bad("duplicate_field")); }
        }
        if take(&mut fields, "object_format")? != format.as_str() { return Err(ApiError::bad("object_format_mismatch")); }
        let reference = RefName::try_new(take(&mut fields, "ref")?.as_bytes())
            .map_err(|_| ApiError::bad("invalid_ref"))?;
        // The existing tree readers require a commit-valued ref. Annotated-tag
        // peeling is not silently added as another object-selection algorithm.
        let expected_head = fields.remove("expected_head").map(|text| parse_snapshot(&text)).transpose()?;
        let expected_commit = fields.remove("expected_commit").map(|text| oid(&text, format)).transpose()?;
        let selection = Selection { reference, expected_head, expected_commit };
        if self.operation == Operation::Search {
            let needle = unhex(&take(&mut fields, "needle_hex")?, 256)?;
            let case = match fields.remove("case").as_deref().unwrap_or("exact") {
                "exact" => SearchCase::Exact, "ascii-insensitive" => SearchCase::AsciiInsensitive,
                _ => return Err(ApiError::bad("unsupported_search_case")),
            };
            let query = SourceQuery::new(&needle, case, &prefixes).map_err(|_| ApiError::bad("invalid_search_query"))?;
            let defaults = SearchLimits::default();
            let limits = SearchLimits {
                max_matches: positive(&mut fields, "max_matches", defaults.max_matches as u64, 4096)? as usize,
                max_total_bytes: positive(&mut fields, "max_bytes", defaults.max_total_bytes as u64, defaults.max_total_bytes as u64)? as usize,
                max_file_bytes: positive(&mut fields, "max_file_bytes", defaults.max_file_bytes as u64, defaults.max_file_bytes as u64)? as usize,
                ..defaults
            };
            limits.validate().map_err(|_| ApiError::bad("invalid_search_limits"))?;
            return Ok(Command::Search { selection, query, limits });
        }
        let path = fields.remove("path_hex").map(|text| unhex(&text, 4096)).transpose()?;
        let action = match self.operation {
            Operation::Tree => SourceBrowseAction::List {
                after: fields.remove("after_hex").map(|text| unhex(&text, 4096)).transpose()?,
                limit: positive(&mut fields, "limit", 100, 1000)? as u16,
            },
            Operation::Blob => SourceBrowseAction::Read {
                offset: fields.remove("offset").map(|text| parse_decimal(&text)).transpose()?.unwrap_or(0),
                limit: positive(&mut fields, "limit", 64 * 1024, 1024 * 1024)? as u32,
            },
            Operation::Search => return Err(ApiError::unavailable()),
        };
        let query = SourceBrowseQuery { path, expected_head, expected_commit, action };
        query.validate(format).map_err(|_| ApiError::bad("invalid_browse_query"))?;
        Ok(Command::Browse { selection, query })
    }
}

#[derive(Debug)]
pub(super) struct Selection {
    pub reference: RefName,
    pub expected_head: Option<RepositoryAuthorityHeadId>,
    pub expected_commit: Option<GitOid>,
}
#[derive(Debug)]
pub(super) enum Command {
    Browse { selection: Selection, query: SourceBrowseQuery },
    Search { selection: Selection, query: SourceQuery, limits: SearchLimits },
}
fn take(fields: &mut BTreeMap<String, String>, name: &str) -> Result<String, ApiError> {
    fields.remove(name).ok_or_else(|| ApiError::bad("missing_source_field"))
}
fn positive(fields: &mut BTreeMap<String, String>, name: &str, default: u64, maximum: u64) -> Result<u64, ApiError> {
    let n = fields.remove(name).map(|text| parse_decimal(&text)).transpose()?.unwrap_or(default);
    if n == 0 || n > maximum { return Err(ApiError::bad("invalid_source_limit")); }
    Ok(n)
}
fn oid(text: &str, format: GitHashAlgorithm) -> Result<GitOid, ApiError> {
    let bytes = unhex(text, format.digest_len())?;
    if bytes.len() != format.digest_len() { return Err(ApiError::bad("invalid_expected_commit")); }
    let id = GitOid::from_hex(format, text).map_err(|_| ApiError::bad("invalid_expected_commit"))?;
    if id.is_zero() { return Err(ApiError::bad("invalid_expected_commit")); }
    Ok(id)
}
fn unhex(text: &str, maximum: usize) -> Result<Vec<u8>, ApiError> {
    if text.is_empty() || text.len() % 2 != 0 || text.len() > maximum * 2
        || !text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    { return Err(ApiError::bad("invalid_hex_bytes")); }
    let digit = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
    Ok(text.as_bytes().chunks_exact(2).map(|pair| (digit(pair[0]) << 4) | digit(pair[1])).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_wire::smart_http::{HttpLimits, head};
    fn request(operation: Operation) -> Request<'static> { Request { repository_route: "/r.git", operation } }
    fn form(format: GitHashAlgorithm) -> String { format!("object_format={}&ref=refs%2Fheads%2Fmain", format.as_str()) }
    #[test]
    fn byte_paths_and_binary_needles_are_not_lossy_text() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let input = form(format);
            let Command::Browse { query, .. } = request(Operation::Blob).command(
                (input.clone() + "&path_hex=66696c65ff&limit=1").as_bytes(), format).unwrap() else { panic!("blob") };
            assert_eq!(query.path, Some(b"file\xff".to_vec()));
            let Command::Search { query, limits, .. } = request(Operation::Search).command(
                (input + "&needle_hex=00ff&case=ascii-insensitive&path_prefix_hex=66696c65ff&max_matches=1").as_bytes(), format).unwrap() else { panic!("search") };
            assert_eq!(query.needle(), &[0, 255]);
            assert_eq!(query.prefixes()[0].as_bytes(), b"file\xff");
            assert_eq!(limits.max_matches, 1);
        }
    }
    #[test]
    fn continuations_require_a_snapshot_and_unknown_fields_never_grant_authority() {
        let valid = form(GitHashAlgorithm::Sha1);
        for (operation, extra) in [
            (Operation::Tree, "&after_hex=61"), (Operation::Blob, "&path_hex=61&offset=1"),
            (Operation::Blob, "&path_hex=2e2e2f736563726574"), (Operation::Blob, "&path_hex=612f0062"),
            (Operation::Tree, "&object_id=aaaa"), (Operation::Tree, "&ref=refs/heads/other"),
            (Operation::Search, "&needle_hex=0a"), (Operation::Search, "&needle_hex=61&case=unicode"),
            (Operation::Search, "&needle_hex=61&principal=admin"), (Operation::Search, "&needle_hex=61&max_matches=4097"),
            (Operation::Tree, "&limit=0"), (Operation::Tree, "&path_hex=FF"),
        ] { assert!(request(operation).command((valid.clone() + extra).as_bytes(), GitHashAlgorithm::Sha1).is_err()); }
    }
    #[test]
    fn strict_ref_and_hash_selection_cannot_name_an_arbitrary_object() {
        let valid = form(GitHashAlgorithm::Sha256);
        for invalid in [valid.replace("sha256", "sha1"), valid.clone() + "&expected_commit=" + &"a".repeat(40),
            valid.clone() + "&expected_commit=" + &"0".repeat(64), valid.replace("refs%2Fheads%2Fmain", "../main")]
        { assert!(request(Operation::Tree).command(invalid.as_bytes(), GitHashAlgorithm::Sha256).is_err()); }
        assert!(request(Operation::Tree).command((valid + "&expected_commit=" + &"a".repeat(64)).as_bytes(), GitHashAlgorithm::Sha256).is_ok());
    }
    #[test]
    fn urls_cannot_smuggle_queries_or_alternative_operations() {
        for (method, suffix, extra) in [("GET", "tree", ""), ("POST", "search?needle=secret", ""),
            ("POST", "../blob", ""), ("POST", "blob/mutate", ""),
            ("POST", "tree", "Git-Protocol: version=2\r\n")]
        {
            let bytes = format!("{method} /r.git/api/v1/source/{suffix} HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\n{extra}\r\n");
            let head = head::parse(bytes.as_bytes(), HttpLimits::default()).unwrap().unwrap();
            assert!(Request::parse(&head).is_err());
        }
    }
}
