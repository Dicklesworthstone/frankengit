//! Stable webhook JSON over the exact canonical event codec.
//!
//! `DeliveryRequest` carries an authority-selected root and its independently
//! verified events. Keep that root verbatim: the admission reader can normalize
//! a legacy, empty ref-only evidence body to an empty `ForgeEventBatch`.
//! Re-hashing that normalized value would substitute a different commitment.
//!
//! Each event carries its complete `fgit-codec::encode_body` frame as lowercase
//! hex, plus its numeric kind and aggregate version for routing. This preserves
//! every native field and byte-valued Git name without a second, lossy event
//! model. The envelope is versioned; it is not a GitHub-compatible JSON schema.
//! Attempt and wall-clock metadata belong in HTTP headers, never in this body.

use fgit_admission::merge::native::settlement::DeliveryRequest;
use fgit_types::RefusalCode;

const MAX_EVENTS: usize = 65_536;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = 64 * 1024 * 1024;
const HEX: &[u8; 16] = b"0123456789abcdef";

pub(super) fn encode(request: &DeliveryRequest<'_>) -> Result<String, RefusalCode> {
    encode_with_limit(request, MAX_PAYLOAD_BYTES)
}

fn encode_with_limit(request: &DeliveryRequest<'_>, limit: usize) -> Result<String, RefusalCode> {
    if request.events.events.len() > MAX_EVENTS {
        return Err(RefusalCode::ResourceBudgetExceeded);
    }
    // IDs are bounded ASCII slugs; digests have a closed, ASCII representation.
    // User-controlled event strings appear only inside canonical hex frames.
    let header = format!(
        "{{\"schema\":\"frankengit.webhook.v1\",\"delivery_id\":\"{}\",\"destination\":\"{}\",\"payload_root\":\"{}\",\"events_count\":{},\"events\":[",
        request.key.as_str(),
        request.destination.as_str(),
        request.payload_root,
        request.events.events.len(),
    );
    let mut payload = String::new();
    append(&mut payload, &header, limit)?;
    for (index, event) in request.events.events.iter().enumerate() {
        let frame =
            fgit_codec::encode_body(event).map_err(|_| RefusalCode::CanonicalFramingInvalid)?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(RefusalCode::ResourceBudgetExceeded);
        }
        if index != 0 {
            append(&mut payload, ",", limit)?;
        }
        append(
            &mut payload,
            &format!(
                "{{\"kind\":{},\"version\":{},\"canonical_frame_hex\":\"",
                event.payload.kind(),
                event.version.get(),
            ),
            limit,
        )?;
        let hex_bytes = frame
            .len()
            .checked_mul(2)
            .ok_or(RefusalCode::ResourceBudgetExceeded)?;
        reserve(&mut payload, hex_bytes, limit)?;
        for byte in frame {
            payload.push(char::from(HEX[usize::from(byte >> 4)]));
            payload.push(char::from(HEX[usize::from(byte & 15)]));
        }
        append(&mut payload, "\"}", limit)?;
    }
    append(&mut payload, "]}", limit)?;
    Ok(payload)
}

fn reserve(payload: &mut String, bytes: usize, limit: usize) -> Result<(), RefusalCode> {
    if payload
        .len()
        .checked_add(bytes)
        .is_none_or(|length| length > limit)
    {
        return Err(RefusalCode::ResourceBudgetExceeded);
    }
    payload
        .try_reserve(bytes)
        .map_err(|_| RefusalCode::ResourceBudgetExceeded)
}

fn append(payload: &mut String, value: &str, limit: usize) -> Result<(), RefusalCode> {
    reserve(payload, value.len(), limit)?;
    payload.push_str(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_forge::{
        AggregateId, AggregateVersion, ForgeEvent, ForgeEventBatch, ForgeEventPayload,
        PullRequestNumber,
    };
    use fgit_types::{AsciiSlug, Digest, DigestAlgorithmId, DigestBytes};

    fn legacy_root() -> Digest {
        Digest::new(
            DigestAlgorithmId::try_new(1).unwrap(),
            DigestBytes::try_new(&[0xaa; 32]).unwrap(),
        )
    }

    fn events() -> ForgeEventBatch {
        ForgeEventBatch {
            events: vec![ForgeEvent {
                aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(7).unwrap()),
                version: AggregateVersion::try_new(2).unwrap(),
                payload: ForgeEventPayload::PullRequestClosed { withdrawn: true },
            }],
        }
    }

    fn request(events: &ForgeEventBatch) -> DeliveryRequest<'_> {
        DeliveryRequest {
            key: AsciiSlug::from_static("event-delivery"),
            destination: AsciiSlug::from_static("test-webhook"),
            payload_root: fgit_admission::evidence::evidence_root(events).unwrap(),
            events,
        }
    }

    #[test]
    fn payload_contains_the_complete_decodable_event_not_only_a_count() {
        let events = events();
        let request = request(&events);
        let body = encode(&request).unwrap();
        let marker = "\"canonical_frame_hex\":\"";
        let start = body.find(marker).unwrap() + marker.len();
        let encoded = body[start..].split('"').next().unwrap();
        let frame = super::super::persistence::hex_decode(encoded).unwrap();
        let decoded =
            fgit_codec::decode_body::<ForgeEvent>(&frame, fgit_codec::DecodeLimits::DEFAULT)
                .unwrap();
        assert_eq!(decoded, events.events[0]);
        assert!(body.contains("\"kind\":4,\"version\":2"));
        assert!(body.contains(&format!("\"payload_root\":\"{}\"", request.payload_root)));
        assert!(body.contains("\"schema\":\"frankengit.webhook.v1\""));
    }

    #[test]
    fn retry_bodies_are_identical_and_do_not_embed_attempt_or_time() {
        let events = events();
        let request = request(&events);
        let first = encode(&request).unwrap();
        assert_eq!(first, encode(&request).unwrap());
        assert!(!first.contains("\"attempt\""));
        assert!(!first.contains("\"timestamp\""));
    }

    #[test]
    fn changing_an_event_changes_the_body_and_invalidates_its_signature() {
        let mut events = events();
        let first = encode(&request(&events)).unwrap();
        let secret =
            fgit_forge::webhook::WebhookSecret::new(b"0123456789abcdef0123456789abcdef").unwrap();
        let tag = fgit_forge::webhook::WebhookSecretRotation::new(secret.clone())
            .sign_active(first.as_bytes());
        events.events[0].payload = ForgeEventPayload::PullRequestClosed { withdrawn: false };
        let second = encode(&request(&events)).unwrap();
        assert_ne!(first, second);
        assert!(!secret.verify(second.as_bytes(), &tag));
    }

    #[test]
    fn payload_budget_is_exact_and_refuses_before_network_dispatch() {
        let events = events();
        let request = request(&events);
        let body = encode(&request).unwrap();
        assert_eq!(encode_with_limit(&request, body.len()), Ok(body.clone()));
        assert_eq!(
            encode_with_limit(&request, body.len() - 1),
            Err(RefusalCode::ResourceBudgetExceeded),
        );
        assert_eq!(
            encode_with_limit(&request, 0),
            Err(RefusalCode::ResourceBudgetExceeded),
        );
    }

    #[test]
    fn empty_normalized_events_keep_the_authority_selected_root() {
        let events = ForgeEventBatch { events: Vec::new() };
        let request = DeliveryRequest {
            // This is the caller's verified legacy evidence root, not the
            // canonical identity of a newly constructed empty forge batch.
            payload_root: legacy_root(),
            ..request(&events)
        };
        let body = encode(&request).unwrap();
        assert!(body.ends_with("\"events_count\":0,\"events\":[]}"));
        assert!(body.contains(&request.payload_root.to_string()));
    }

    #[test]
    fn event_order_and_non_utf8_ref_bytes_survive_the_envelope() {
        let mut events = events();
        events.events.push(ForgeEvent {
            aggregate: AggregateId::PullRequest(PullRequestNumber::try_new(8).unwrap()),
            version: AggregateVersion::try_new(1).unwrap(),
            payload: ForgeEventPayload::PullRequestOpened {
                source_ref: b"refs/heads/quoted-\"-\\-\xff".to_vec(),
                target_ref: b"refs/heads/main".to_vec(),
                source_tip: legacy_root(),
                target_tip: legacy_root(),
            },
        });
        let body = encode(&request(&events)).unwrap();
        let first = super::super::hex_encode(fgit_codec::encode_body(&events.events[0]).unwrap());
        let second = super::super::hex_encode(fgit_codec::encode_body(&events.events[1]).unwrap());
        assert!(body.find(&first).unwrap() < body.find(&second).unwrap());
        assert!(body.is_ascii());
        assert!(body.contains("\"events_count\":2"));
    }
}
