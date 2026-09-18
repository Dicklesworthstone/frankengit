//! Versioned issue commands and canonical events. Text is data, never authority.
//! Events retain explicit changes, so a retry never depends on a latest-state
//! lookup. Admission evaluates the exact expected predecessor before publication.
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};
use crate::aggregate::{AggregateId, AggregateVersion, ExpectedVersion, IssueNumber};
use super::{ForgeEvent, ForgeEventPayload, invalid_native};

pub const MAX_TITLE_BYTES: usize = 256;
pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_LABELS: usize = 32;
pub const MAX_LABEL_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueState { Open, Closed }

/// A replacement applies only to the explicitly supplied fields. Labels are a
/// bounded canonical set; None preserves them and Some(empty) clears them.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IssueEdit {
    pub title: Option<String>,
    pub body: Option<String>,
    pub labels: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssueAction {
    Open { title: String, body: String, labels: Vec<String> },
    Edit(IssueEdit),
    Close,
    Reopen,
    Comment { body: String },
}
impl IssueAction {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        match self {
            Self::Open { title, body, labels } => {
                validate_title(title)?; validate_body(body)?; validate_labels(labels)
            }
            Self::Edit(edit) => {
                if edit.title.is_none() && edit.body.is_none() && edit.labels.is_none() {
                    return Err(invalid_native("issue.empty_edit"));
                }
                if let Some(title) = &edit.title { validate_title(title)?; }
                if let Some(body) = &edit.body { validate_body(body)?; }
                if let Some(labels) = &edit.labels { validate_labels(labels)?; }
                Ok(())
            }
            Self::Comment { body } => {
                validate_body(body)?;
                if body.trim().is_empty() { return Err(invalid_native("issue.empty_comment")); }
                Ok(())
            }
            Self::Close | Self::Reopen => Ok(()),
        }
    }
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self { Self::Open { .. } => "open", Self::Edit(_) => "edit",
            Self::Close => "close", Self::Reopen => "reopen", Self::Comment { .. } => "comment" }
    }
    fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_scalar(match self { Self::Open { .. } => 1u32, Self::Edit(_) => 2,
            Self::Close => 3, Self::Reopen => 4, Self::Comment { .. } => 5 });
        match self {
            Self::Open { title, body, labels } => {
                out.write_bytes("issue.title", title.as_bytes())?;
                out.write_bytes("issue.body", body.as_bytes())?;
                write_labels(out, labels)?;
            }
            Self::Edit(edit) => {
                for (field, value) in [("issue.title", &edit.title), ("issue.body", &edit.body)] {
                    out.write_bool(value.is_some());
                    if let Some(text) = value { out.write_bytes(field, text.as_bytes())?; }
                }
                out.write_bool(edit.labels.is_some());
                if let Some(labels) = &edit.labels { write_labels(out, labels)?; }
            }
            Self::Comment { body } => out.write_bytes("issue.comment", body.as_bytes())?,
            Self::Close | Self::Reopen => {}
        }
        Ok(())
    }
    fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let offset = input.offset();
        let action = match input.read_scalar::<u32>("issue.action")? {
            1 => Self::Open { title: text(input, "issue.title", MAX_TITLE_BYTES)?,
                body: text(input, "issue.body", MAX_BODY_BYTES)?, labels: read_labels(input)? },
            2 => Self::Edit(IssueEdit {
                title: if input.read_bool("issue.has_title")? { Some(text(input, "issue.title", MAX_TITLE_BYTES)?) } else { None },
                body: if input.read_bool("issue.has_body")? { Some(text(input, "issue.body", MAX_BODY_BYTES)?) } else { None },
                labels: if input.read_bool("issue.has_labels")? { Some(read_labels(input)?) } else { None },
            }),
            3 => Self::Close,
            4 => Self::Reopen,
            5 => Self::Comment { body: text(input, "issue.comment", MAX_BODY_BYTES)? },
            observed => return Err(CodecRefusal::VariantUnknown { field: "issue.action", observed, offset }),
        };
        action.validate()?;
        Ok(action)
    }
}
fn validate_title(title: &str) -> Result<(), CodecRefusal> {
    if title.trim().is_empty() || title.len() > MAX_TITLE_BYTES || title.chars().any(char::is_control) {
        return Err(invalid_native("issue.title"));
    }
    Ok(())
}
fn validate_body(body: &str) -> Result<(), CodecRefusal> {
    if body.len() > MAX_BODY_BYTES || body.contains('\0') { return Err(invalid_native("issue.body")); }
    Ok(())
}
fn validate_labels(labels: &[String]) -> Result<(), CodecRefusal> {
    if labels.len() > MAX_LABELS || labels.windows(2).any(|pair| pair[0] >= pair[1])
        || labels.iter().any(|label| label.trim().is_empty() || label.len() > MAX_LABEL_BYTES
            || label.chars().any(char::is_control))
    { return Err(invalid_native("issue.labels")); }
    Ok(())
}
fn text(input: &mut Decoder<'_>, field: &'static str, limit: usize) -> Result<String, CodecRefusal> {
    let bytes = input.read_bytes(field)?;
    if bytes.len() > limit { return Err(invalid_native(field)); }
    let value = std::str::from_utf8(bytes).map_err(|_| invalid_native(field))?;
    Ok(value.to_owned())
}
fn write_labels(out: &mut Encoder, labels: &[String]) -> Result<(), CodecRefusal> {
    validate_labels(labels)?;
    out.write_sequence("issue.labels", labels, |out, label| out.write_bytes("issue.label", label.as_bytes()))
}
fn read_labels(input: &mut Decoder<'_>) -> Result<Vec<String>, CodecRefusal> {
    // The codec's sequence bound is checked before allocation; the issue bound
    // is applied as each element is read, before retaining another label.
    let mut count = 0usize;
    let labels = input.read_sequence("issue.labels", |input| {
        count = count.checked_add(1).ok_or_else(|| invalid_native("issue.labels"))?;
        if count > MAX_LABELS { return Err(invalid_native("issue.labels")); }
        text(input, "issue.label", MAX_LABEL_BYTES)
    })?;
    validate_labels(&labels)?;
    Ok(labels)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeIssueEvent { pub actor: PrincipalId, pub action: IssueAction }
impl NativeIssueEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        out.write_opaque_id(self.actor.as_bytes());
        self.action.write(out)
    }
    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        Ok(Self { actor: PrincipalId::from_bytes(input.read_opaque_id("issue.actor")?),
            action: IssueAction::read(input)? })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueCommand {
    pub number: IssueNumber,
    pub expected_version: ExpectedVersion,
    pub action: IssueAction,
}
impl IssueCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        self.action.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
        if matches!(self.action, IssueAction::Open { .. }) != (self.expected_version == ExpectedVersion::NewStream) {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(version) => version.next().map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent { aggregate: AggregateId::Issue(self.number), version,
            payload: ForgeEventPayload::IssueChangedNative(NativeIssueEvent { actor, action: self.action.clone() }) })
    }
}

/// Rebuildable state, not storage or authority. Comments remain in the exact
/// versioned event timeline; this small projection never duplicates their text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueSnapshot {
    pub number: IssueNumber,
    pub version: AggregateVersion,
    pub title: String,
    pub body: String,
    pub labels: Vec<String>,
    pub state: IssueState,
    pub opened_by: PrincipalId,
    pub last_actor: PrincipalId,
    pub comments: u64,
}

/// Replay one event against its exact predecessor. No latest-version refresh,
/// implicit reopening, duplicate creation or lost-update overwrite is possible.
pub fn apply_event(previous: Option<&IssueSnapshot>, event: &ForgeEvent) -> Result<IssueSnapshot, RefusalCode> {
    let (AggregateId::Issue(number), ForgeEventPayload::IssueChangedNative(change)) = (event.aggregate, &event.payload) else {
        return Err(RefusalCode::EvidenceInvalid);
    };
    change.action.validate().map_err(|_| RefusalCode::EvidenceInvalid)?;
    let Some(previous) = previous else {
        let IssueAction::Open { title, body, labels } = &change.action else { return Err(RefusalCode::EvidenceStale); };
        if event.version != AggregateVersion::FIRST { return Err(RefusalCode::EvidenceStale); }
        return Ok(IssueSnapshot { number, version: event.version, title: title.clone(), body: body.clone(),
            labels: labels.clone(), state: IssueState::Open, opened_by: change.actor,
            last_actor: change.actor, comments: 0 });
    };
    if previous.number != number || !previous.version.is_immediate_predecessor_of(event.version) {
        return Err(RefusalCode::EvidenceStale);
    }
    let mut next = previous.clone();
    match &change.action {
        IssueAction::Open { .. } => return Err(RefusalCode::ProtectedRefTransitionDenied),
        IssueAction::Edit(edit) => {
            if let Some(title) = &edit.title { next.title.clone_from(title); }
            if let Some(body) = &edit.body { next.body.clone_from(body); }
            if let Some(labels) = &edit.labels { next.labels.clone_from(labels); }
        }
        IssueAction::Close if previous.state == IssueState::Open => next.state = IssueState::Closed,
        IssueAction::Reopen if previous.state == IssueState::Closed => next.state = IssueState::Open,
        IssueAction::Close | IssueAction::Reopen => return Err(RefusalCode::ProtectedRefTransitionDenied),
        IssueAction::Comment { .. } => next.comments = next.comments.checked_add(1).ok_or(RefusalCode::ResourceBudgetExceeded)?,
    }
    next.version = event.version;
    next.last_actor = change.actor;
    Ok(next)
}

#[cfg(test)]
mod tests;

/// Maximum UTF-8 bytes in a literal title/body search. No regex, query language,
/// stemming or ambient locale affects matching.
pub const MAX_QUERY_BYTES: usize = 256;

/// A conjunction of filters over an authority-selected issue snapshot.
///
/// Labels are an exact, sorted, duplicate-free set and ALL must be present.
/// Text matches either title or body, never across their boundary. Comments
/// are intentionally excluded: their text lives in the versioned event stream.
/// Default text matching folds ASCII only; non-ASCII UTF-8 stays byte-exact.
/// This is a derived read predicate, not an authorization or publication grant.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IssueQuery {
    pub state: Option<IssueState>,
    pub opened_by: Option<PrincipalId>,
    pub labels: Vec<String>,
    pub text: Option<String>,
    pub case_sensitive: bool,
}

impl IssueQuery {
    /// Validate the bounded query and compile a linear-time literal matcher.
    ///
    /// # Errors
    /// Empty/oversized/NUL text and noncanonical label sets are refused before
    /// allocating the matcher. Absence of text means no text restriction.
    pub fn compile(self) -> Result<CompiledIssueQuery, CodecRefusal> {
        validate_labels(&self.labels)?;
        if self.text.as_ref().is_some_and(|text|
            text.is_empty() || text.len() > MAX_QUERY_BYTES || text.contains('\0'))
        {
            return Err(invalid_native("issue.query"));
        }
        let needle: Vec<u8> = self.text.as_deref().unwrap_or_default().bytes()
            .map(|byte| if self.case_sensitive { byte } else { byte.to_ascii_lowercase() })
            .collect();
        let mut failure = vec![0; needle.len()];
        let mut matched = 0;
        for index in 1..needle.len() {
            while matched > 0 && needle[index] != needle[matched] {
                matched = failure[matched - 1];
            }
            if needle[index] == needle[matched] { matched += 1; }
            failure[index] = matched;
        }
        Ok(CompiledIssueQuery { query: self, needle, failure })
    }
}

/// A validated predicate reusable across bounded pages from ONE selected head.
/// The caller owns disclosure, snapshot pinning, scan limits and cancellation.
/// Matching allocates no per-issue text copy and takes linear text work even
/// for adversarial repeated-prefix needles.
#[derive(Clone, Debug)]
pub struct CompiledIssueQuery {
    query: IssueQuery,
    needle: Vec<u8>,
    failure: Vec<usize>,
}

impl CompiledIssueQuery {
    #[must_use]
    pub const fn query(&self) -> &IssueQuery { &self.query }

    /// Evaluate a validated snapshot; malformed state is never an empty result.
    ///
    /// # Errors
    /// Snapshot text, labels or comment counts violating the issue contract
    /// refuse, including snapshots that would fail an inexpensive filter.
    pub fn matches(&self, issue: &IssueSnapshot) -> Result<bool, CodecRefusal> {
        validate_title(&issue.title)?;
        validate_body(&issue.body)?;
        validate_labels(&issue.labels)?;
        if issue.comments >= issue.version.get() {
            return Err(invalid_native("issue.comments"));
        }
        if self.query.state.is_some_and(|state| state != issue.state)
            || self.query.opened_by.is_some_and(|actor| actor != issue.opened_by)
            || !self.query.labels.iter().all(|label| issue.labels.binary_search(label).is_ok())
        {
            return Ok(false);
        }
        Ok(self.contains(issue.title.as_bytes()) || self.contains(issue.body.as_bytes()))
    }

    fn contains(&self, bytes: &[u8]) -> bool {
        if self.needle.is_empty() { return true; }
        let mut matched = 0;
        for &byte in bytes {
            let byte = if self.query.case_sensitive { byte } else { byte.to_ascii_lowercase() };
            while matched > 0 && byte != self.needle[matched] {
                matched = self.failure[matched - 1];
            }
            if byte == self.needle[matched] { matched += 1; }
            if matched == self.needle.len() { return true; }
        }
        false
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;

    fn snapshot() -> IssueSnapshot {
        IssueSnapshot {
            number: IssueNumber::FIRST, version: AggregateVersion::FIRST,
            title: "Fix HTTP".into(), body: "café\nbody needle".into(),
            labels: vec!["bug".into(), "urgent".into()], state: IssueState::Open,
            opened_by: PrincipalId::from_bytes([1; 16]),
            last_actor: PrincipalId::from_bytes([2; 16]), comments: 0,
        }
    }

    #[test]
    fn query_filters_are_conjoined_and_author_is_not_last_actor() {
        let query = IssueQuery {
            state: Some(IssueState::Open), opened_by: Some(PrincipalId::from_bytes([1; 16])),
            labels: vec!["bug".into(), "urgent".into()], text: Some("http".into()),
            case_sensitive: false,
        };
        let compiled = query.clone().compile().unwrap();
        assert_eq!(compiled.query(), &query);
        assert!(compiled.matches(&snapshot()).unwrap());
        for changed in [
            IssueQuery { state: Some(IssueState::Closed), ..query.clone() },
            IssueQuery { opened_by: Some(PrincipalId::from_bytes([2; 16])), ..query.clone() },
            IssueQuery { labels: vec!["bug".into(), "missing".into()], ..query.clone() },
            IssueQuery { text: Some("absent".into()), ..query },
        ] {
            assert!(!changed.compile().unwrap().matches(&snapshot()).unwrap());
        }
        assert!(IssueQuery::default().compile().unwrap().matches(&snapshot()).unwrap());
    }

    #[test]
    fn literal_matching_is_ascii_only_and_does_not_join_fields() {
        for (text, case_sensitive, expected) in [
            ("http", false, true), ("http", true, false), ("HTTP", true, true),
            ("CAFé", false, true), ("CAFÉ", false, false), ("body needle", true, true),
            ("HTTPcafé", false, false), (".*", false, false), ("é\nbody", true, true),
        ] {
            let query = IssueQuery { text: Some(text.into()), case_sensitive, ..Default::default() };
            assert_eq!(query.compile().unwrap().matches(&snapshot()).unwrap(), expected, "{text}");
        }
    }

    #[test]
    fn query_bounds_and_canonical_labels_have_permitted_twins() {
        for text in [String::new(), "a".repeat(MAX_QUERY_BYTES + 1), "a\0b".into()] {
            assert!(IssueQuery { text: Some(text), ..Default::default() }.compile().is_err());
        }
        assert!(IssueQuery { text: Some("a".repeat(MAX_QUERY_BYTES)), ..Default::default() }.compile().is_ok());
        for labels in [vec!["b".into(), "a".into()], vec!["a".into(), "a".into()],
            vec![" ".into()], vec!["a".repeat(MAX_LABEL_BYTES + 1)], vec!["a\nb".into()]]
        {
            assert!(IssueQuery { labels, ..Default::default() }.compile().is_err());
        }
        let labels: Vec<_> = (0..MAX_LABELS).map(|n| format!("{n:02}")).collect();
        assert!(IssueQuery { labels: labels.clone(), ..Default::default() }.compile().is_ok());
        let mut oversized = labels;
        oversized.push("zz".into());
        assert!(IssueQuery { labels: oversized, ..Default::default() }.compile().is_err());
    }

    #[test]
    fn malformed_snapshots_refuse_before_filtering_or_text_work() {
        let query = IssueQuery { state: Some(IssueState::Closed), ..Default::default() }.compile().unwrap();
        let valid = snapshot();
        for invalid in [
            IssueSnapshot { body: "a".repeat(MAX_BODY_BYTES + 1), ..valid.clone() },
            IssueSnapshot { title: String::new(), ..valid.clone() },
            IssueSnapshot { labels: vec!["z".into(), "a".into()], ..valid.clone() },
            IssueSnapshot { comments: 1, ..valid },
        ] {
            assert!(query.matches(&invalid).is_err());
        }
    }

    #[test]
    fn linear_matcher_agrees_with_scalar_literal_oracle() {
        fn word(bits: u32, length: usize) -> Vec<u8> {
            (0..length).map(|n| if bits & (1 << n) == 0 { b'A' } else { b'b' }).collect()
        }
        for case_sensitive in [false, true] {
            for needle_len in 1..=4 {
                for needle_bits in 0..(1 << needle_len) {
                    let needle = word(needle_bits, needle_len);
                    let query = IssueQuery { text: Some(String::from_utf8(needle.clone()).unwrap()),
                        case_sensitive, ..Default::default() }.compile().unwrap();
                    for hay_len in 0..=7 {
                        for hay_bits in 0..(1 << hay_len) {
                            let hay = word(hay_bits, hay_len);
                            let expected = hay.windows(needle.len()).any(|window| if case_sensitive {
                                window == needle.as_slice()
                            } else { window.eq_ignore_ascii_case(&needle) });
                            assert_eq!(query.contains(&hay), expected, "{hay:?} / {needle:?}");
                        }
                    }
                }
            }
        }
    }
}
