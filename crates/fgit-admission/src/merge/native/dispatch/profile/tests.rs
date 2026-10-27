//! Pure codec/reconciliation oracles, not HTTP or crash-durability proof.
use super::*;
use fgit_codec::harness::digest_of;
use fgit_codec::{DecodeLimits, decode_body, encode_body};
use fgit_resource::settlement::{DeliveryVerdict, ProbeVerdict};

fn initial() -> (CanonicalDispatchProgress, CanonicalOutboxEffectState) {
    let key =
        AsciiSlug::from_static("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    let origin = CanonicalOutboxEffectState::committed(
        RepositoryId::from_bytes([1; 16]),
        key,
        fgit_codec::harness::tx_id(),
        digest_of(3),
    )
    .transition(LifecycleEvent::Defer, None)
    .unwrap();
    let routes = [7, 8]
        .map(|id| DispatchRoute {
            id,
            binding: digest_of(id as u8),
            max_attempts: 3,
            initial_delay_millis: 1,
            max_delay_millis: 10,
        })
        .to_vec();
    (
        CanonicalDispatchProgress::start(
            origin.repository_id(),
            key,
            AsciiSlug::from_static("forge-projection"),
            origin.payload_root(),
            origin.root().unwrap(),
            PrincipalId::from_bytes([4; 16]),
            routes,
        )
        .unwrap(),
        origin,
    )
}
fn reload(body: &CanonicalDispatchProgress) -> CanonicalDispatchProgress {
    let bytes = encode_body(body).unwrap();
    let decoded: CanonicalDispatchProgress = decode_body(&bytes, DecodeLimits::DEFAULT).unwrap();
    assert_eq!(decoded, *body);
    assert_eq!(encode_body(&decoded).unwrap(), bytes);
    decoded
}
#[test]
fn one_acknowledged_route_cannot_retire_its_pending_sibling() {
    let (p, origin) = initial();
    let p = reload(&p);
    let sent = p.dispatch(7, 100).unwrap();
    sent.verify_successor_of(&p).unwrap();
    let ack = reload(
        &sent
            .observe(
                7,
                101,
                Observation::Delivery(DeliveryVerdict::Accepted),
                b"HTTP 204".to_vec(),
            )
            .unwrap(),
    );
    ack.verify_successor_of(&sent).unwrap();
    assert!(ack.finish(&origin).is_err());
    assert_eq!(
        ack.routes()[1].state,
        ReconcileState::Pending { attempt: 1 }
    );
    let sent = ack.dispatch(8, 102).unwrap();
    let ack = sent
        .observe(
            8,
            103,
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"HTTP 202".to_vec(),
        )
        .unwrap();
    let (finished, effect, receipt) = ack.finish(&origin).unwrap();
    reload(&finished).verify_successor_of(&ack).unwrap();
    assert_eq!(effect.state(), ObligationState::Acknowledged);
    assert_eq!(
        receipt.disposition(),
        OutboxDeliveryDisposition::Acknowledged
    );
    assert!(finished.dispatch(7, 104).is_err());
}
#[test]
fn lost_weak_marker_becomes_indeterminate_without_another_dispatch() {
    let (p, origin) = initial();
    let sent = reload(&p.dispatch(7, 100).unwrap());
    assert!(sent.dispatch(7, 101).is_err());
    let unknown = sent
        .observe(
            7,
            101,
            Observation::Probe(ProbeVerdict::Unknown),
            b"weak receiver cannot prove absence".to_vec(),
        )
        .unwrap();
    assert!(matches!(
        unknown.routes()[0].state,
        ReconcileState::Indeterminate { .. }
    ));
    assert!(unknown.dispatch(7, 102).is_err());
    assert!(unknown.finish(&origin).is_err());
    let sent = unknown.dispatch(8, 102).unwrap();
    let ack = sent
        .observe(
            8,
            103,
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"HTTP 204".to_vec(),
        )
        .unwrap();
    let (_, effect, receipt) = ack.finish(&origin).unwrap();
    assert_eq!(effect.state(), ObligationState::Escalated);
    assert_eq!(
        receipt.disposition(),
        OutboxDeliveryDisposition::Indeterminate
    );
}
#[test]
fn canonical_retry_ceiling_backoff_and_every_route_binding_are_immutable() {
    let (p, _) = initial();
    let sent = p.dispatch(7, 100).unwrap();
    let retry = sent
        .observe(
            7,
            101,
            Observation::Delivery(DeliveryVerdict::TransientFailure),
            b"HTTP 503".to_vec(),
        )
        .unwrap();
    assert_eq!(retry.routes()[0].attempt, 2);
    assert!(retry.routes()[0].not_before_millis >= 101);
    if retry.routes()[0].not_before_millis > 101 {
        assert!(retry.dispatch(7, 100).is_err());
    }
    let mut altered = retry.clone();
    altered.routes[1].route.binding = digest_of(99);
    assert!(altered.verify_successor_of(&sent).is_err());
    let mut altered = retry.clone();
    altered.routes[0].route.max_attempts = 16;
    assert!(altered.verify_successor_of(&sent).is_err());
    let mut altered = retry;
    altered.owner = PrincipalId::from_bytes([9; 16]);
    assert!(altered.verify_successor_of(&sent).is_err());
    assert!(
        sent.observe(
            7,
            99,
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"ack".to_vec()
        )
        .is_err()
    );
    let mut reverse = p.routes.iter().map(|m| m.route.clone()).collect::<Vec<_>>();
    reverse.reverse();
    assert!(
        CanonicalDispatchProgress::start(
            p.repository,
            p.key,
            p.destination,
            p.payload,
            p.origin,
            p.owner,
            reverse
        )
        .is_err()
    );
}
#[test]
fn terminal_evidence_and_exact_predecessor_are_required() {
    let (p, _) = initial();
    let sent = p.dispatch(7, 100).unwrap();
    assert!(
        sent.observe(
            7,
            101,
            Observation::Delivery(DeliveryVerdict::Accepted),
            vec![]
        )
        .is_err()
    );
    assert!(
        sent.observe(
            7,
            101,
            Observation::Delivery(DeliveryVerdict::Accepted),
            vec![0; 4097]
        )
        .is_err()
    );
    let ack = sent
        .observe(
            7,
            101,
            Observation::Delivery(DeliveryVerdict::Accepted),
            b"ack".to_vec(),
        )
        .unwrap();
    assert!(ack.verify_successor_of(&p).is_err());
    let mut missing = ack;
    missing.previous = Some(digest_of(88));
    assert!(missing.verify_successor_of(&sent).is_err());
}
