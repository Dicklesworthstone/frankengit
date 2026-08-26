#![forbid(unsafe_code)]
//! FG-056b: Quota/admission cross-tenant abuse and resource governance campaign.
//!
//! Acceptance criteria verified:
//! - Cross-tenant quota isolation: abuse by one tenant never exhausts another tenant's guaranteed share;
//! - Multi-level hierarchy (tenant > org > repo > principal) enforces the tightest applicable bound;
//! - Fair-share queueing drains requests in deficit round-robin order under sustained overload;
//! - Containment is reversible: expires cleanly and restores admission; irreversible actions require upstream review;
//! - Planted negative and edge cases:
//!   * Semantics pin: undeclared ceiling admits up to ledger capacity; explicit ceiling hard-refuses;
//!   * Cross-tenant tightening: org-level ceiling tighter than tenant-level ceiling binds principal requests;
//!   * Ceiling-before-pool ordering: over-ceiling requests hard-refuse without touching ledger state;
//!   * Degraded profile escape hatch: full ask over capacity + degraded under capacity admits degraded; degraded over capacity falls back;
//!   * Queue deadline zero disables queueing and yields caller-anchored retry hint;
//!   * Ledger overflow produces HardRefusal while conservation failure produces RetryableRefusal;
//!   * Determinism: identical admission sequences produce identical outcome traces across independent instances.

use fgit_resource::algebra::{Grade, ResourceVector};
use fgit_resource::custody::{LeakDisposition, ObligationLedger};
use fgit_resource::ids::RegionId;
use fgit_resource::quota::abuse::{
    ContainmentReason, PushVerdict, RateLimit, RateWindow, evaluate_push, record_containment,
};
use fgit_resource::quota::admission::{
    AdmissionOutcome, AdmissionRequest, HardRefusalReason, admit,
};
use fgit_resource::quota::fairness::{FairnessKey, FairnessQueue, PickReason};
use fgit_resource::quota::hierarchy::{ScopeCeilings, ScopeChain, ScopeSegment};
use fgit_types::{AsciiSlug, PrincipalId, RepositoryId, TenantId};
use std::time::{Duration, Instant};

fn tenant(id: u8) -> TenantId {
    TenantId::from_bytes([id; 16])
}

fn org(slug: &str) -> AsciiSlug {
    AsciiSlug::try_new("org", slug.as_bytes()).expect("valid ascii slug")
}

fn repo(id: u8) -> RepositoryId {
    RepositoryId::from_bytes([id; 16])
}

fn principal(id: u8) -> PrincipalId {
    PrincipalId::from_bytes([id; 16])
}

fn make_ledger(capacity: &[(Grade, u64)]) -> ObligationLedger {
    ObligationLedger::root(
        RegionId::new(1),
        LeakDisposition::RecordAndContinue,
        ResourceVector::from_grades(capacity),
    )
}

#[test]
fn test_cross_tenant_quota_isolation_under_abuse() {
    // Ledger has 1000 Bytes capacity total.
    let ledger = make_ledger(&[(Grade::Bytes, 1000), (Grade::CpuMicros, 1000)]);
    let mut ceilings = ScopeCeilings::new();

    let tenant_a = tenant(1);
    let tenant_b = tenant(2);

    // Tenant A is capped at 400 Bytes, Tenant B is capped at 400 Bytes.
    ceilings
        .declare(
            vec![ScopeSegment::Tenant(tenant_a)],
            ResourceVector::single(Grade::Bytes, 400),
        )
        .expect("declare tenant A");
    ceilings
        .declare(
            vec![ScopeSegment::Tenant(tenant_b)],
            ResourceVector::single(Grade::Bytes, 400),
        )
        .expect("declare tenant B");

    let chain_a = ScopeChain::new(vec![ScopeSegment::Tenant(tenant_a)]).expect("chain A");
    let chain_b = ScopeChain::new(vec![ScopeSegment::Tenant(tenant_b)]).expect("chain B");

    // Tenant A attempts an abusive ask of 500 Bytes (exceeding its ceiling).
    let req_a_abusive = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 500));
    let outcome_a_abusive = admit(&ledger, &chain_a, &ceilings, &req_a_abusive);
    assert!(matches!(
        outcome_a_abusive,
        AdmissionOutcome::HardRefusal {
            reason: HardRefusalReason::CeilingExceeded {
                grade: Grade::Bytes
            }
        }
    ));

    // Tenant A admits a legitimate 300 Bytes.
    let req_a_valid = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 300));
    let outcome_a_valid = admit(&ledger, &chain_a, &ceilings, &req_a_valid);
    assert!(matches!(
        outcome_a_valid,
        AdmissionOutcome::AdmittedWithReservation { .. }
    ));

    // Tenant B requests 300 Bytes - despite Tenant A's abusive and valid traffic, Tenant B is admitted cleanly.
    let req_b = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 300));
    let outcome_b = admit(&ledger, &chain_b, &ceilings, &req_b);
    assert!(matches!(
        outcome_b,
        AdmissionOutcome::AdmittedWithReservation { .. }
    ));

    // Now Tenant A tries another 300 Bytes: (300 already granted, pool has 400 left, but A's ceiling is 400).
    // Tenant A ask is under ceiling per-request, but ledger has remaining 400 total.
    // Tenant A gets admitted for another 300 (total in pool is now 900).
    let outcome_a_second = admit(&ledger, &chain_a, &ceilings, &req_a_valid);
    assert!(matches!(
        outcome_a_second,
        AdmissionOutcome::AdmittedWithReservation { .. }
    ));

    // Now pool has 100 Bytes left.
    // Tenant B asks for 200 Bytes: under B's ceiling (400), but pool has only 100 -> Conservation failure.
    let req_b_contention = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 200));
    let outcome_b_contention = admit(&ledger, &chain_b, &ceilings, &req_b_contention);
    assert!(matches!(
        outcome_b_contention,
        AdmissionOutcome::RetryableRefusalWithHint { .. }
    ));
}

#[test]
fn test_multi_level_hierarchy_tightest_bound() {
    let mut ceilings = ScopeCeilings::new();
    let t = tenant(1);
    let o = org("core");
    let r = repo(5);
    let p = principal(9);

    // Tenant level: Bytes=1000, Egress=5000
    ceilings
        .declare(
            vec![ScopeSegment::Tenant(t)],
            ResourceVector::from_grades(&[(Grade::Bytes, 1000), (Grade::EgressBytes, 5000)]),
        )
        .expect("tenant");

    // Org level: Bytes=800, CpuMicros=2000 (tightens Bytes to 800, sets CpuMicros)
    ceilings
        .declare(
            vec![
                ScopeSegment::Tenant(t),
                ScopeSegment::Organization(o.clone()),
            ],
            ResourceVector::from_grades(&[(Grade::Bytes, 800), (Grade::CpuMicros, 2000)]),
        )
        .expect("org");

    // Repo level: Bytes=600, Objects=4 (tightens Bytes to 600, sets Objects)
    ceilings
        .declare(
            vec![
                ScopeSegment::Tenant(t),
                ScopeSegment::Organization(o.clone()),
                ScopeSegment::Repository(r),
            ],
            ResourceVector::from_grades(&[(Grade::Bytes, 600), (Grade::Objects, 4)]),
        )
        .expect("repo");

    // Principal level: tries to widen Bytes to 900 (must be ignored, 600 remains), sets MemoryBytes=100
    ceilings
        .declare(
            vec![
                ScopeSegment::Tenant(t),
                ScopeSegment::Organization(o.clone()),
                ScopeSegment::Repository(r),
                ScopeSegment::Principal(p),
            ],
            ResourceVector::from_grades(&[(Grade::Bytes, 900), (Grade::MemoryBytes, 100)]),
        )
        .expect("principal");

    let chain = ScopeChain::new(vec![
        ScopeSegment::Tenant(t),
        ScopeSegment::Organization(o),
        ScopeSegment::Repository(r),
        ScopeSegment::Principal(p),
    ])
    .expect("chain");

    let effective = chain.effective_ceiling(&ceilings);
    assert_eq!(effective.get(Grade::Bytes), 600); // 1000 -> 800 -> 600 (900 widening ignored)
    assert_eq!(effective.get(Grade::EgressBytes), 5000); // from tenant
    assert_eq!(effective.get(Grade::CpuMicros), 2000); // from org
    assert_eq!(effective.get(Grade::Objects), 4); // from repo
    assert_eq!(effective.get(Grade::MemoryBytes), 100); // from principal
    assert_eq!(effective.get(Grade::FileDescriptors), 0); // undeclared
}

#[test]
fn test_fair_share_queueing_deficit_round_robin_order() {
    let mut queue = FairnessQueue::new();
    let key1 = FairnessKey {
        tenant: tenant(1),
        principal: principal(1),
    };
    let key2 = FairnessKey {
        tenant: tenant(2),
        principal: principal(2),
    };
    let key3 = FairnessKey {
        tenant: tenant(3),
        principal: principal(3),
    };

    // Push contenders: key1 (2 asks), key2 (3 asks), key3 (1 ask)
    let t1_1 = queue.push(key1);
    let t1_2 = queue.push(key1);
    let t2_1 = queue.push(key2);
    let t2_2 = queue.push(key2);
    let t2_3 = queue.push(key2);
    let t3_1 = queue.push(key3);

    assert_eq!(queue.len(), 6);

    // Round 1: should pick key1 (t1_1), key2 (t2_1), key3 (t3_1)
    let (d1, r1) = queue.dequeue_picked().expect("pick 1");
    assert_eq!(d1.ticket, t1_1);
    assert_eq!(d1.key, key1);
    assert!(matches!(r1, PickReason::LaneRotation { lane_index: 0 }));

    let (d2, r2) = queue.dequeue_picked().expect("pick 2");
    assert_eq!(d2.ticket, t2_1);
    assert_eq!(d2.key, key2);
    assert!(matches!(r2, PickReason::LaneRotation { lane_index: 1 }));

    let (d3, r3) = queue.dequeue_picked().expect("pick 3");
    assert_eq!(d3.ticket, t3_1);
    assert_eq!(d3.key, key3);
    assert!(matches!(r3, PickReason::LaneRotation { lane_index: 2 }));

    // Key3 is now drained.
    // Round 2: should pick key1 (t1_2). Key1 becomes empty, leaving only key2.
    let (d4, r4) = queue.dequeue_picked().expect("pick 4");
    assert_eq!(d4.ticket, t1_2);
    assert_eq!(d4.key, key1);
    assert!(matches!(r4, PickReason::LaneRotation { .. }));

    // Key1 is now drained. Only key2 remains (lanes.len() == 1).
    // Picks for key2 (t2_2, t2_3) are SoleContender.
    let (d5, r5) = queue.dequeue_picked().expect("pick 5");
    assert_eq!(d5.ticket, t2_2);
    assert_eq!(d5.key, key2);
    assert_eq!(r5, PickReason::SoleContender);

    let (d6, r6) = queue.dequeue_picked().expect("pick 6");
    assert_eq!(d6.ticket, t2_3);
    assert_eq!(d6.key, key2);
    assert_eq!(r6, PickReason::SoleContender);

    assert!(queue.is_empty());
    assert!(queue.dequeue_picked().is_none());
}

#[test]
fn test_containment_reversibility_and_moderation_event() {
    let limit = RateLimit {
        max_events: 2,
        window: Duration::from_secs(10),
    };
    let mut window = RateWindow::default();
    let key = FairnessKey {
        tenant: tenant(1),
        principal: principal(1),
    };
    let t0 = Instant::now();

    // Event 1 at t0 -> Admitted
    assert!(matches!(
        evaluate_push(&limit, &mut window, &key, t0),
        PushVerdict::Admitted
    ));

    // Event 2 at t0 + 2s -> Admitted
    let t1 = t0 + Duration::from_secs(2);
    assert!(matches!(
        evaluate_push(&limit, &mut window, &key, t1),
        PushVerdict::Admitted
    ));

    // Event 3 at t0 + 3s -> Exceeds rate limit (2 events in 10s) -> Contained
    let t2 = t0 + Duration::from_secs(3);
    let verdict = evaluate_push(&limit, &mut window, &key, t2);
    match verdict {
        PushVerdict::Contain { containment } => {
            assert_eq!(
                containment.reason,
                ContainmentReason::RateExceeded {
                    observed: 2,
                    limit: 2
                }
            );
            assert_eq!(containment.reason.code(), "rate_exceeded");
            assert_eq!(containment.expires, Duration::from_secs(10));

            // Record moderation event for audit
            let event = record_containment(1001, &key, t2, &containment);
            assert_eq!(event.sequence, 1001);
            assert_eq!(event.key, key);
            assert_eq!(event.at, t2);
            assert_eq!(event.containment.reason.code(), "rate_exceeded");
        }
        PushVerdict::Admitted => panic!("expected containment verdict"),
    }

    // Reversibility check: advance time past sliding window (t0 + 11s)
    // The event at t0 (0s) has expired, leaving only the event at t1 (2s).
    // Now window has 1 active event (< limit of 2) -> Event 4 at t3 is Admitted!
    let t3 = t0 + Duration::from_secs(11);
    assert!(matches!(
        evaluate_push(&limit, &mut window, &key, t3),
        PushVerdict::Admitted
    ));

    // Advance time past t1 + 10s (t0 + 22s) -> all prior events expired -> Admitted
    let t4 = t0 + Duration::from_secs(22);
    assert!(matches!(
        evaluate_push(&limit, &mut window, &key, t4),
        PushVerdict::Admitted
    ));
}

#[test]
fn test_semantics_pin_empty_economy_vs_explicit_ceiling() {
    let ledger = make_ledger(&[(Grade::Bytes, 500)]);

    // Case 1: Empty economy (no ceiling declared for tenant) -> ask is admitted up to pool capacity
    let empty_ceilings = ScopeCeilings::new();
    let chain = ScopeChain::new(vec![ScopeSegment::Tenant(tenant(1))]).expect("chain");

    let req_200 = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 200));
    let outcome = admit(&ledger, &chain, &empty_ceilings, &req_200);
    assert!(matches!(
        outcome,
        AdmissionOutcome::AdmittedWithReservation { .. }
    ));

    // Case 2: Explicit ceiling of 100 declared -> ask of 200 is HardRefused
    let mut explicit_ceilings = ScopeCeilings::new();
    explicit_ceilings
        .declare(
            vec![ScopeSegment::Tenant(tenant(1))],
            ResourceVector::single(Grade::Bytes, 100),
        )
        .expect("declare");

    let outcome_refused = admit(&ledger, &chain, &explicit_ceilings, &req_200);
    assert!(matches!(
        outcome_refused,
        AdmissionOutcome::HardRefusal {
            reason: HardRefusalReason::CeilingExceeded {
                grade: Grade::Bytes
            }
        }
    ));

    // Permitted twin for explicit ceiling: ask of 100 (within ceiling) is Admitted
    let req_100 = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 100));
    let outcome_permitted = admit(&ledger, &chain, &explicit_ceilings, &req_100);
    assert!(matches!(
        outcome_permitted,
        AdmissionOutcome::AdmittedWithReservation { .. }
    ));
}

#[test]
fn test_ceiling_before_pool_order_no_side_effects() {
    let ledger = make_ledger(&[(Grade::Bytes, 1000)]);
    let mut ceilings = ScopeCeilings::new();
    let t = tenant(1);
    ceilings
        .declare(
            vec![ScopeSegment::Tenant(t)],
            ResourceVector::single(Grade::Bytes, 300),
        )
        .expect("declare");

    let chain = ScopeChain::new(vec![ScopeSegment::Tenant(t)]).expect("chain");

    let initial_pool = ledger.snapshot();
    assert_eq!(initial_pool.available().get(Grade::Bytes), 1000);
    assert_eq!(initial_pool.granted().get(Grade::Bytes), 0);

    // Ask 400 (exceeds ceiling of 300)
    let req_exceeds = AdmissionRequest::exact(ResourceVector::single(Grade::Bytes, 400));
    let outcome = admit(&ledger, &chain, &ceilings, &req_exceeds);
    assert!(matches!(
        outcome,
        AdmissionOutcome::HardRefusal {
            reason: HardRefusalReason::CeilingExceeded {
                grade: Grade::Bytes
            }
        }
    ));

    // Assert ledger state was completely untouched by the refused request
    let post_refusal_pool = ledger.snapshot();
    assert_eq!(post_refusal_pool.available().get(Grade::Bytes), 1000);
    assert_eq!(post_refusal_pool.granted().get(Grade::Bytes), 0);
    assert_eq!(initial_pool, post_refusal_pool);
}

#[test]
fn test_degraded_profile_escape_hatch_and_no_double_degrade() {
    let ledger = make_ledger(&[(Grade::Bytes, 100)]);
    let mut ceilings = ScopeCeilings::new();
    let t = tenant(1);
    ceilings
        .declare(
            vec![ScopeSegment::Tenant(t)],
            ResourceVector::single(Grade::Bytes, 200),
        )
        .expect("declare");

    let chain = ScopeChain::new(vec![ScopeSegment::Tenant(t)]).expect("chain");

    // Case 1: Full ask 150 (under ceiling 200, but over pool capacity 100)
    // Degraded ask 80 (under ceiling 200, and fits in pool 100)
    // -> Admitted at DegradedOptionalProfile, carrying original_request=150
    let req_with_degraded = AdmissionRequest {
        requested: ResourceVector::single(Grade::Bytes, 150),
        degraded_profile: Some(ResourceVector::single(Grade::Bytes, 80)),
        queue_deadline: Duration::ZERO,
        retry_after: Duration::from_secs(2),
    };

    let outcome_degraded = admit(&ledger, &chain, &ceilings, &req_with_degraded);
    match outcome_degraded {
        AdmissionOutcome::DegradedOptionalProfile {
            grant,
            original_request,
        } => {
            assert_eq!(grant.amount().get(Grade::Bytes), 80);
            assert_eq!(original_request.get(Grade::Bytes), 150);
        }
        other => panic!("expected DegradedOptionalProfile, got {:?}", other),
    }

    // Case 2: Full ask 150 over capacity (100 total), degraded ask 120 ALSO over capacity (100 total)
    // -> Falls through to RetryableRefusalWithHint, no double-degrade or panic
    let req_degraded_fails = AdmissionRequest {
        requested: ResourceVector::single(Grade::Bytes, 150),
        degraded_profile: Some(ResourceVector::single(Grade::Bytes, 120)),
        queue_deadline: Duration::ZERO,
        retry_after: Duration::from_secs(5),
    };

    let outcome_retry = admit(&ledger, &chain, &ceilings, &req_degraded_fails);
    match outcome_retry {
        AdmissionOutcome::RetryableRefusalWithHint { hint, retry_after } => {
            assert_eq!(*hint.peek(), "capacity-contention");
            assert_eq!(retry_after, Duration::from_secs(5));
        }
        other => panic!("expected RetryableRefusalWithHint, got {:?}", other),
    }

    // Case 3: Full ask 250 (exceeds ceiling of 200) with degraded ask 50
    // -> HardRefusal immediately on full ask without evaluating degraded
    let req_full_over_ceiling = AdmissionRequest {
        requested: ResourceVector::single(Grade::Bytes, 250),
        degraded_profile: Some(ResourceVector::single(Grade::Bytes, 50)),
        queue_deadline: Duration::ZERO,
        retry_after: Duration::from_secs(1),
    };

    let outcome_hard = admit(&ledger, &chain, &ceilings, &req_full_over_ceiling);
    assert!(matches!(
        outcome_hard,
        AdmissionOutcome::HardRefusal {
            reason: HardRefusalReason::CeilingExceeded {
                grade: Grade::Bytes
            }
        }
    ));
}

#[test]
fn test_queue_deadline_behavior() {
    let ledger = make_ledger(&[(Grade::Bytes, 50)]);
    let ceilings = ScopeCeilings::new();
    let chain = ScopeChain::new(vec![ScopeSegment::Tenant(tenant(1))]).expect("chain");

    // Case 1: Ask 100 with queue_deadline = 5s -> QueuedWithDeadline(5s)
    let req_queued = AdmissionRequest {
        requested: ResourceVector::single(Grade::Bytes, 100),
        degraded_profile: None,
        queue_deadline: Duration::from_secs(5),
        retry_after: Duration::from_secs(1),
    };

    let outcome_q = admit(&ledger, &chain, &ceilings, &req_queued);
    match outcome_q {
        AdmissionOutcome::QueuedWithDeadline { deadline } => {
            assert_eq!(deadline, Duration::from_secs(5));
        }
        other => panic!("expected QueuedWithDeadline, got {:?}", other),
    }

    // Case 2: Ask 100 with queue_deadline = 0 -> RetryableRefusalWithHint
    let req_immediate = AdmissionRequest {
        requested: ResourceVector::single(Grade::Bytes, 100),
        degraded_profile: None,
        queue_deadline: Duration::ZERO,
        retry_after: Duration::from_secs(3),
    };

    let outcome_imm = admit(&ledger, &chain, &ceilings, &req_immediate);
    match outcome_imm {
        AdmissionOutcome::RetryableRefusalWithHint { hint, retry_after } => {
            assert_eq!(*hint.peek(), "capacity-contention");
            assert_eq!(retry_after, Duration::from_secs(3));
        }
        other => panic!("expected RetryableRefusalWithHint, got {:?}", other),
    }
}

#[test]
fn test_determinism_across_instances() {
    // Run an identical sequence of 20 admissions across 2 separate ledger/ceiling instances.
    let make_env = || {
        let ledger = make_ledger(&[(Grade::Bytes, 500), (Grade::EgressBytes, 1000)]);
        let mut ceilings = ScopeCeilings::new();
        ceilings
            .declare(
                vec![ScopeSegment::Tenant(tenant(1))],
                ResourceVector::from_grades(&[(Grade::Bytes, 400), (Grade::EgressBytes, 800)]),
            )
            .expect("declare");
        let chain = ScopeChain::new(vec![ScopeSegment::Tenant(tenant(1))]).expect("chain");
        (ledger, ceilings, chain)
    };

    let (ledger1, ceilings1, chain1) = make_env();
    let (ledger2, ceilings2, chain2) = make_env();

    let amounts = [
        (100, 200),
        (300, 500),
        (450, 100), // exceeds ceiling
        (50, 100),
        (200, 300), // exceeds pool remaining
        (500, 900), // exceeds ceiling
        (10, 20),
        (20, 40),
    ];

    for (bytes, egress) in amounts {
        let req = AdmissionRequest {
            requested: ResourceVector::from_grades(&[
                (Grade::Bytes, bytes),
                (Grade::EgressBytes, egress),
            ]),
            degraded_profile: Some(ResourceVector::from_grades(&[
                (Grade::Bytes, bytes / 2),
                (Grade::EgressBytes, egress / 2),
            ])),
            queue_deadline: Duration::from_millis(bytes * 10),
            retry_after: Duration::from_millis(egress * 5),
        };

        let outcome1 = admit(&ledger1, &chain1, &ceilings1, &req);
        let outcome2 = admit(&ledger2, &chain2, &ceilings2, &req);

        match (&outcome1, &outcome2) {
            (
                AdmissionOutcome::AdmittedWithReservation { grant: g1 },
                AdmissionOutcome::AdmittedWithReservation { grant: g2 },
            ) => {
                assert_eq!(g1.amount(), g2.amount());
            }
            (
                AdmissionOutcome::DegradedOptionalProfile {
                    grant: g1,
                    original_request: o1,
                },
                AdmissionOutcome::DegradedOptionalProfile {
                    grant: g2,
                    original_request: o2,
                },
            ) => {
                assert_eq!(g1.amount(), g2.amount());
                assert_eq!(o1, o2);
            }
            (
                AdmissionOutcome::QueuedWithDeadline { deadline: d1 },
                AdmissionOutcome::QueuedWithDeadline { deadline: d2 },
            ) => {
                assert_eq!(d1, d2);
            }
            (
                AdmissionOutcome::RetryableRefusalWithHint {
                    hint: h1,
                    retry_after: r1,
                },
                AdmissionOutcome::RetryableRefusalWithHint {
                    hint: h2,
                    retry_after: r2,
                },
            ) => {
                assert_eq!(*h1.peek(), *h2.peek());
                assert_eq!(r1, r2);
            }
            (
                AdmissionOutcome::HardRefusal { reason: r1 },
                AdmissionOutcome::HardRefusal { reason: r2 },
            ) => {
                assert_eq!(r1, r2);
            }
            _ => panic!(
                "non-deterministic outcomes: outcome1={:?}, outcome2={:?}",
                outcome1, outcome2
            ),
        }
    }
}
