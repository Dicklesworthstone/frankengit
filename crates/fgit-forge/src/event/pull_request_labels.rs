//! Exact replacement and additive intents in an independent PR aggregate. Labels never
//! advance the PR content version or change a review's compared subject.

use super::{ForgeEvent, ForgeEventPayload, invalid_native};
use crate::{AggregateId, AggregateVersion, ExpectedVersion, PullRequestNumber};
use fgit_codec::{CodecRefusal, Decoder, Encoder};
use fgit_types::{PrincipalId, RefusalCode};

pub const MAX_LABELS: usize = 32;
pub const MAX_LABEL_BYTES: usize = 64;

/// The exact complete desired set; an empty set explicitly clears all labels.
/// `expected_version` belongs to the label aggregate, not PR content or reviews.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestLabelsCommand {
    pub number: PullRequestNumber,
    pub expected_version: ExpectedVersion,
    pub labels: Vec<String>,
}

/// Add exactly this nonempty set without selecting a mutable label predecessor.
/// The actor and original additions stay sealed while admission derives the
/// complete after-set from the currently authenticated labels frontier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestLabelsIntent {
    pub number: PullRequestNumber,
    pub labels: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePullRequestLabelsEvent {
    pub actor: PrincipalId,
    pub labels: Vec<String>,
}

/// One additive intent and its independently validated full label after-set.
/// Keeping the full set preserves bounded frontier reads after many additions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePullRequestLabelsAddedEvent {
    pub actor: PrincipalId,
    pub additions: Vec<String>,
    pub labels: Vec<String>,
}

/// Shared write/query bounds. Sets are sorted by exact UTF-8 bytes, distinct,
/// and case-sensitive; no trimming or Unicode normalization changes identity.
pub fn validate_labels(labels: &[String]) -> Result<(), CodecRefusal> {
    if labels.len() > MAX_LABELS
        || labels.windows(2).any(|pair| pair[0] >= pair[1])
        || labels.iter().any(|label| {
            label.trim().is_empty()
                || label.len() > MAX_LABEL_BYTES
                || label.chars().any(char::is_control)
        })
    {
        return Err(invalid_native("pull_request_labels.labels"));
    }
    Ok(())
}

impl PullRequestLabelsCommand {
    pub fn proposed_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        validate_labels(&self.labels).map_err(|_| RefusalCode::EvidenceInvalid)?;
        let version = match self.expected_version {
            ExpectedVersion::NewStream => AggregateVersion::FIRST,
            ExpectedVersion::Exactly(previous) => previous
                .next()
                .map_err(|_| RefusalCode::ResourceBudgetExceeded)?,
        };
        Ok(ForgeEvent {
            aggregate: AggregateId::PullRequestLabels(self.number),
            version,
            payload: ForgeEventPayload::PullRequestLabelsChangedNative(
                NativePullRequestLabelsEvent {
                    actor,
                    labels: self.labels.clone(),
                },
            ),
        })
    }
}

impl PullRequestLabelsIntent {
    /// Version one and the initial after-set are identity commitment material,
    /// not a chosen publication position or a claim about current labels.
    pub fn commitment_event(&self, actor: PrincipalId) -> Result<ForgeEvent, RefusalCode> {
        validate_additions(&self.labels).map_err(|_| RefusalCode::EvidenceInvalid)?;
        Ok(ForgeEvent {
            aggregate: AggregateId::PullRequestLabels(self.number),
            version: AggregateVersion::FIRST,
            payload: ForgeEventPayload::PullRequestLabelsAddedNative(
                NativePullRequestLabelsAddedEvent {
                    actor,
                    additions: self.labels.clone(),
                    labels: self.labels.clone(),
                },
            ),
        })
    }
}

fn validate_additions(labels: &[String]) -> Result<(), CodecRefusal> {
    validate_labels(labels)?;
    if labels.is_empty() {
        return Err(invalid_native("pull_request_labels.additions"));
    }
    Ok(())
}

/// Complete current labels and their actor, regardless of how they were set.
/// Both canonical kinds carry a full after-set; readers need only one frontier.
#[must_use]
pub fn selected_labels(payload: &ForgeEventPayload) -> Option<(PrincipalId, &[String])> {
    match payload {
        ForgeEventPayload::PullRequestLabelsChangedNative(change) => {
            Some((change.actor, &change.labels))
        }
        ForgeEventPayload::PullRequestLabelsAddedNative(change) => {
            Some((change.actor, &change.labels))
        }
        _ => None,
    }
}

fn read_labels(input: &mut Decoder<'_>) -> Result<Vec<String>, CodecRefusal> {
    let count = input
        .clone()
        .read_scalar::<u32>("pull_request_labels.labels")?;
    if count as usize > MAX_LABELS {
        return Err(invalid_native("pull_request_labels.count"));
    }
    let labels = input.read_sequence("pull_request_labels.labels", |input| {
        let bytes = input.read_bytes("pull_request_labels.label")?;
        if bytes.len() > MAX_LABEL_BYTES {
            return Err(invalid_native("pull_request_labels.label_limit"));
        }
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| invalid_native("pull_request_labels.utf8"))
    })?;
    validate_labels(&labels)?;
    Ok(labels)
}

impl NativePullRequestLabelsEvent {
    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        validate_labels(&self.labels)?;
        out.write_opaque_id(self.actor.as_bytes());
        out.write_sequence("pull_request_labels.labels", &self.labels, |out, label| {
            out.write_bytes("pull_request_labels.label", label.as_bytes())
        })
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let actor = PrincipalId::from_bytes(input.read_opaque_id("pull_request_labels.actor")?);
        let labels = read_labels(input)?;
        Ok(Self { actor, labels })
    }
}

impl NativePullRequestLabelsAddedEvent {
    pub fn validate(&self) -> Result<(), CodecRefusal> {
        validate_additions(&self.additions)?;
        validate_labels(&self.labels)?;
        if self
            .additions
            .iter()
            .any(|label| self.labels.binary_search(label).is_err())
        {
            return Err(invalid_native("pull_request_labels.missing_addition"));
        }
        Ok(())
    }

    pub(super) fn write(&self, out: &mut Encoder) -> Result<(), CodecRefusal> {
        self.validate()?;
        out.write_opaque_id(self.actor.as_bytes());
        for labels in [&self.additions, &self.labels] {
            out.write_sequence("pull_request_labels.labels", labels, |out, label| {
                out.write_bytes("pull_request_labels.label", label.as_bytes())
            })?;
        }
        Ok(())
    }

    pub(super) fn read(input: &mut Decoder<'_>) -> Result<Self, CodecRefusal> {
        let value = Self {
            actor: PrincipalId::from_bytes(input.read_opaque_id("pull_request_labels.actor")?),
            additions: read_labels(input)?,
            labels: read_labels(input)?,
        };
        value.validate()?;
        Ok(value)
    }
}

pub(super) fn validate_event(event: &ForgeEvent) -> Result<(), CodecRefusal> {
    if matches!(event.aggregate, AggregateId::PullRequestLabels(_))
        != matches!(
            event.payload,
            ForgeEventPayload::PullRequestLabelsChangedNative(_)
                | ForgeEventPayload::PullRequestLabelsAddedNative(_)
        )
    {
        return Err(invalid_native("pull_request_labels.aggregate_kind"));
    }
    if let ForgeEventPayload::PullRequestLabelsChangedNative(change) = &event.payload {
        validate_labels(&change.labels)?;
    }
    if let ForgeEventPayload::PullRequestLabelsAddedNative(change) = &event.payload {
        change.validate()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_codec::{CanonicalBody, DecodeLimits, decode_body, encode_body};

    fn command() -> PullRequestLabelsCommand {
        PullRequestLabelsCommand {
            number: PullRequestNumber::FIRST,
            expected_version: ExpectedVersion::NewStream,
            labels: vec!["bug".into(), "é".into()],
        }
    }

    #[test]
    fn labels_have_new_required_tags_and_exact_independent_payload_bytes() {
        let actor = PrincipalId::from_bytes([7; 16]);
        let event = command().proposed_event(actor).unwrap();
        let mut payload = Encoder::new();
        event.write_payload(&mut payload).unwrap();
        let mut expected = Encoder::new();
        expected.write_scalar(0_u64);
        expected.write_scalar(15_u32);
        expected.write_scalar(1_u64);
        expected.write_scalar(1_u64);
        expected.write_scalar(27_u32);
        expected.write_opaque_id(actor.as_bytes());
        expected.write_scalar(2_u32);
        expected.write_bytes("label", b"bug").unwrap();
        expected.write_bytes("label", "é".as_bytes()).unwrap();
        assert_eq!(payload.into_bytes(), expected.into_bytes());
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for length in 0..frame.len() {
            assert!(decode_body::<ForgeEvent>(&frame[..length], DecodeLimits::DEFAULT).is_err());
        }
        let mut wrong = event.clone();
        wrong.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST);
        assert!(encode_body(&wrong).is_err());
        let mut clear = command();
        clear.expected_version = ExpectedVersion::Exactly(AggregateVersion::FIRST);
        clear.labels.clear();
        assert_eq!(clear.proposed_event(actor).unwrap().version.get(), 2);
        assert_ne!(
            encode_body(&clear.proposed_event(actor).unwrap()).unwrap(),
            frame
        );
    }

    #[test]
    fn exact_label_set_bounds_have_permitted_twins() {
        for labels in [
            vec![],
            vec!["x".repeat(MAX_LABEL_BYTES)],
            (0..MAX_LABELS).map(|n| format!("label-{n:02}")).collect(),
        ] {
            validate_labels(&labels).unwrap();
        }
        for labels in [
            vec!["".into()],
            vec![" \t".into()],
            vec!["x\0y".into()],
            vec!["a".into(), "a".into()],
            vec!["z".into(), "a".into()],
            vec!["é".repeat(MAX_LABEL_BYTES / 2 + 1)],
            (0..=MAX_LABELS).map(|n| format!("label-{n:02}")).collect(),
        ] {
            assert!(validate_labels(&labels).is_err());
        }
    }

    #[test]
    fn additions_have_distinct_required_bytes_and_bounded_complete_frontiers() {
        let actor = PrincipalId::from_bytes([7; 16]);
        let intent = PullRequestLabelsIntent {
            number: PullRequestNumber::FIRST,
            labels: vec!["bug".into(), "é".into()],
        };
        let event = intent.commitment_event(actor).unwrap();
        let mut payload = Encoder::new();
        event.write_payload(&mut payload).unwrap();
        let mut expected = Encoder::new();
        expected.write_scalar(0_u64);
        expected.write_scalar(15_u32);
        expected.write_scalar(1_u64);
        expected.write_scalar(1_u64);
        expected.write_scalar(29_u32);
        expected.write_opaque_id(actor.as_bytes());
        for _ in 0..2 {
            expected.write_scalar(2_u32);
            expected.write_bytes("label", b"bug").unwrap();
            expected.write_bytes("label", "é".as_bytes()).unwrap();
        }
        assert_eq!(payload.into_bytes(), expected.into_bytes());
        let frame = encode_body(&event).unwrap();
        assert_eq!(
            decode_body::<ForgeEvent>(&frame, DecodeLimits::DEFAULT).unwrap(),
            event
        );
        for length in 0..frame.len() {
            assert!(decode_body::<ForgeEvent>(&frame[..length], DecodeLimits::DEFAULT).is_err());
        }
        let mut empty = intent.clone();
        empty.labels.clear();
        assert!(empty.commitment_event(actor).is_err());
        for mutation in 0..4 {
            let mut changed = event.clone();
            if mutation == 0 {
                changed.aggregate = AggregateId::PullRequest(PullRequestNumber::FIRST);
            } else {
                let ForgeEventPayload::PullRequestLabelsAddedNative(change) = &mut changed.payload
                else {
                    unreachable!()
                };
                match mutation {
                    1 => change.additions.clear(),
                    2 => {
                        change.labels.remove(0);
                    }
                    _ => {
                        change.labels = (0..=MAX_LABELS).map(|n| format!("label-{n:02}")).collect();
                    }
                };
            }
            assert!(encode_body(&changed).is_err(), "mutation {mutation}");
        }
    }
}
