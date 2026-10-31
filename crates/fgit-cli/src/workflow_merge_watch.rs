//! Explicit operator policy for automatically preparing a PR's CI candidate.
//! Shared by the foreground watcher and the HTTP-owned controller; parsing
//! neither reads ambient Git identity nor grants a network request authority.

use std::collections::BTreeMap;

use fgit_forge::preparation::{MergeCommitStyle, MergeMetadata, MergeProfile};
use fgit_types::{PrincipalId, RefName};

#[derive(Clone, Debug)]
pub(crate) struct Options {
    pub(crate) reference: RefName,
    pub(crate) principal: PrincipalId,
    pub(crate) metadata: MergeMetadata,
    pub(crate) profile: MergeProfile,
    pub(crate) style: MergeCommitStyle,
}

pub(crate) fn is_option(name: &str) -> bool {
    matches!(
        name,
        "--merge-candidate-ref"
            | "--merge-candidate-ref-hex"
            | "--merge-principal"
            | "--merge-author"
            | "--merge-committer"
            | "--merge-timestamp"
            | "--merge-message"
            | "--merge-profile"
            | "--merge-method"
    )
}

pub(crate) fn server_option(name: &str) -> Option<&'static str> {
    Some(match name {
        "--workflow-merge-candidate-ref" => "--merge-candidate-ref",
        "--workflow-merge-candidate-ref-hex" => "--merge-candidate-ref-hex",
        "--workflow-merge-principal" => "--merge-principal",
        "--workflow-merge-author" => "--merge-author",
        "--workflow-merge-committer" => "--merge-committer",
        "--workflow-merge-timestamp" => "--merge-timestamp",
        "--workflow-merge-message" => "--merge-message",
        "--workflow-merge-profile" => "--merge-profile",
        "--workflow-merge-method" => "--merge-method",
        _ => return None,
    })
}

/// The map contains only normalized merge option names. Both callers consume
/// each option and its value together before calling this pure parser.
pub(crate) fn parse(fields: &BTreeMap<&str, &str>) -> Result<Option<Options>, String> {
    if fields.is_empty() {
        return Ok(None);
    }
    if fields.keys().any(|name| !is_option(name)) {
        return Err("unknown merge-candidate watch option".into());
    }
    let required = |name: &str| {
        fields
            .get(name)
            .copied()
            .ok_or_else(|| format!("merge-candidate watch requires {name}"))
    };
    let bytes = match (
        fields.get("--merge-candidate-ref"),
        fields.get("--merge-candidate-ref-hex"),
    ) {
        (Some(reference), None) => reference.as_bytes().to_vec(),
        (None, Some(encoded)) => decode_ref(encoded)?,
        _ => {
            return Err(
                "supply exactly one of --merge-candidate-ref and --merge-candidate-ref-hex".into(),
            );
        }
    };
    if !bytes.starts_with(b"refs/heads/") || bytes.len() > 1024 {
        return Err(
            "merge candidate requires a full branch reference of at most 1024 bytes".into(),
        );
    }
    let reference = RefName::try_new(&bytes).map_err(|_| "invalid merge candidate reference")?;
    let principal = PrincipalId::from_hex(required("--merge-principal")?)
        .map_err(|_| "invalid merge publication principal")?;
    let timestamp = required("--merge-timestamp")?;
    if timestamp.is_empty()
        || timestamp.starts_with('0')
        || !timestamp.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("--merge-timestamp requires a canonical positive Unix timestamp".into());
    }
    let metadata = MergeMetadata {
        author: required("--merge-author")?.to_owned(),
        committer: required("--merge-committer")?.to_owned(),
        timestamp: timestamp
            .parse()
            .map_err(|_| "--merge-timestamp is out of range")?,
        message: required("--merge-message")?.as_bytes().to_vec(),
    };
    metadata
        .validate()
        .map_err(|_| "invalid explicit merge author, committer, timestamp or message")?;
    let profile = match fields.get("--merge-profile").copied().unwrap_or("path") {
        "path" => MergeProfile::PathMergeV1,
        "exact-renames" => MergeProfile::ExactRenamesV1,
        _ => return Err("--merge-profile must be path or exact-renames".into()),
    };
    let style = match fields
        .get("--merge-method")
        .copied()
        .unwrap_or("merge-commit")
    {
        "merge-commit" => MergeCommitStyle::TwoParent,
        "squash" => MergeCommitStyle::Squash,
        _ => return Err("--merge-method must be merge-commit or squash".into()),
    };
    Ok(Some(Options {
        reference,
        principal,
        metadata,
        profile,
        style,
    }))
}

fn decode_ref(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty()
        || value.len() > 2048
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("merge candidate ref hex must be bounded lowercase complete bytes".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid ref hex")?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid ref hex".to_owned())
        })
        .collect()
}

impl Options {
    pub(crate) fn validate_queue_selection(
        &self,
        target: &RefName,
        incarnation_pinned: bool,
    ) -> Result<(), String> {
        if !incarnation_pinned {
            return Err("queue candidate publication requires --expected-incarnation".into());
        }
        if self.reference == *target {
            return Err("merge candidate ref must differ from the watched queue target ref".into());
        }
        if self.style != MergeCommitStyle::TwoParent {
            return Err("merge-queue watch requires --merge-method merge-commit".into());
        }
        Ok(())
    }

    pub(crate) fn validate_selection(
        &self,
        source: &RefName,
        pull_request: Option<u64>,
        incarnation_pinned: bool,
    ) -> Result<(), String> {
        if pull_request.is_none() {
            return Err("merge-candidate watch requires a native --pull-request selection".into());
        }
        if !incarnation_pinned {
            return Err("merge-candidate publication requires --expected-incarnation".into());
        }
        if self.reference == *source {
            return Err("merge candidate ref must differ from the watched PR source ref".into());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn node_config(
        &self,
    ) -> Result<fgit_node::workflow_watch::PullRequestMergeWatchConfig, String> {
        fgit_node::workflow_watch::PullRequestMergeWatchConfig::try_new(
            self.reference.clone(),
            self.principal,
            self.metadata.clone(),
            self.profile,
            self.style,
        )
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> BTreeMap<&'static str, &'static str> {
        BTreeMap::from([
            ("--merge-candidate-ref", "refs/heads/ci/pr-1"),
            ("--merge-principal", "33333333333333333333333333333333"),
            ("--merge-author", "CI <ci@example.test>"),
            ("--merge-committer", "CI <ci@example.test>"),
            ("--merge-timestamp", "1700000000"),
            ("--merge-message", "Test the exact candidate\n"),
        ])
    }

    #[test]
    fn identity_is_explicit_and_preserves_exact_message_and_method() {
        let parsed = parse(&fields()).unwrap().unwrap();
        assert_eq!(parsed.metadata.message, b"Test the exact candidate\n");
        assert_eq!(parsed.metadata.timestamp, 1_700_000_000);
        assert_eq!(parsed.profile, MergeProfile::PathMergeV1);
        assert_eq!(parsed.style, MergeCommitStyle::TwoParent);
        let mut selected = fields();
        selected.insert("--merge-profile", "exact-renames");
        selected.insert("--merge-method", "squash");
        let parsed = parse(&selected).unwrap().unwrap();
        assert_eq!(parsed.profile, MergeProfile::ExactRenamesV1);
        assert_eq!(parsed.style, MergeCommitStyle::Squash);
        selected.insert("--merge-message", "--merge-method");
        assert_eq!(
            parse(&selected).unwrap().unwrap().metadata.message,
            b"--merge-method"
        );
    }

    #[test]
    fn partial_or_invalid_authority_and_identity_never_gain_defaults() {
        assert!(parse(&BTreeMap::new()).unwrap().is_none());
        for key in fields().keys() {
            let mut missing = fields();
            missing.remove(key);
            assert!(parse(&missing).is_err(), "{key}");
        }
        for (key, value) in [
            ("--merge-candidate-ref", "refs/tags/ci"),
            ("--merge-candidate-ref", "refs/heads/../ci"),
            ("--merge-principal", "not-a-principal"),
            ("--merge-author", "CI"),
            ("--merge-committer", "CI <ci@example.test>\n"),
            ("--merge-timestamp", "0"),
            ("--merge-timestamp", "01700000000"),
            ("--merge-timestamp", "9223372036854775808"),
            ("--merge-timestamp", "1.5"),
            ("--merge-message", ""),
            ("--merge-message", "bad\0message"),
            ("--merge-method", "rebase"),
            ("--merge-profile", "guess"),
        ] {
            let mut bad = fields();
            bad.insert(key, value);
            assert!(parse(&bad).is_err(), "{key}={value:?}");
        }
    }

    #[test]
    fn byte_ref_is_exact_and_exclusive_with_text() {
        let mut selected = fields();
        selected.remove("--merge-candidate-ref");
        selected.insert(
            "--merge-candidate-ref-hex",
            "726566732f68656164732f63692fff",
        );
        assert_eq!(
            parse(&selected).unwrap().unwrap().reference.as_bytes(),
            b"refs/heads/ci/\xff"
        );
        selected.insert("--merge-candidate-ref", "refs/heads/ci/pr-1");
        assert!(parse(&selected).is_err());
        selected.remove("--merge-candidate-ref");
        for value in ["", "a", "726566732F", "zz"] {
            selected.insert("--merge-candidate-ref-hex", value);
            assert!(parse(&selected).is_err());
        }
    }

    #[test]
    fn publication_requires_native_pr_incarnation_and_separate_branch() {
        let parsed = parse(&fields()).unwrap().unwrap();
        let source = RefName::try_new(b"refs/heads/topic").unwrap();
        assert!(parsed.validate_selection(&source, Some(1), true).is_ok());
        assert!(parsed.validate_selection(&source, None, true).is_err());
        assert!(parsed.validate_selection(&source, Some(1), false).is_err());
        assert!(
            parsed
                .validate_selection(&parsed.reference, Some(1), true)
                .is_err()
        );
    }
}
