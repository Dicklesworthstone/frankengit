//! Verified fabric work preserves both clocks and every remaining non-time limit.
use super::*;
use crate::{FabricReadCeiling, VerifiedFabricPackSource};

fn wall_time(node: &OneNode, context: &FsqliteCx) -> Duration {
    context
        .attached_native_cx()
        .unwrap()
        .budget()
        .remaining(node.runtime.now())
        .deadline
        .unwrap()
}

#[test]
fn verified_fabric_credit_cannot_exceed_the_original_transport_allowance() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let session = session_deadline();
    let request = node.upload_request_context(&session);
    let before = request.authority().attached_native_cx().unwrap().budget();
    let ceiling = FabricReadCeiling::for_upload(&node, request.authority(), &session).unwrap();

    // The class can earn more time than the transport allows. This credit
    // cannot extend the outer session or the native request past its clock.
    ceiling.note_read(request.authority(), 40_000);
    ceiling.rearm(request.authority());
    assert_eq!(session.budget(), Duration::from_secs(10));
    assert_eq!(
        request
            .authority()
            .attached_native_cx()
            .unwrap()
            .budget()
            .deadline,
        before.deadline
    );

    // A real selected-work allowance can raise the outer ceiling. Database
    // credit is still capped there, including in a newly minted read phase.
    assert!(session.note_selected_upload_work(10_000));
    // An independent upper bound projects the wall deadline using the
    // opposite sample order, allowing preemption in either measurement.
    let wall_lower = Instant::now();
    let native_upper = node.runtime.now();
    let remaining_cap = (session.started + session.budget()).saturating_duration_since(wall_lower);
    let absolute_cap = before.with_timeout(native_upper, remaining_cap).deadline;
    ceiling.rearm(request.authority());
    assert_eq!(session.budget(), Duration::from_secs(20));
    assert_eq!(
        session.shared.verified_fabric_bytes.load(Ordering::Relaxed),
        40_000
    );
    let left = wall_time(&node, request.authority());
    assert!(left > Duration::from_secs(15) && left <= Duration::from_secs(20));
    let after = request.authority().attached_native_cx().unwrap().budget();
    assert!(after.deadline <= absolute_cap);
    assert_eq!(after.poll_quota, before.poll_quota);
    assert_eq!(after.cost_quota, before.cost_quota);
    assert_eq!(after.priority, before.priority);

    // More verified bytes cannot compound the already capped allowance.
    ceiling.note_read(request.authority(), usize::MAX);
    for _ in 0..2 {
        ceiling.rearm(request.authority());
        assert_eq!(
            request
                .authority()
                .attached_native_cx()
                .unwrap()
                .budget()
                .deadline,
            after.deadline
        );
    }
    let resumed = node.upload_request_context(&session);
    let left = wall_time(&node, resumed.authority());
    assert!(left > Duration::from_secs(15) && left <= Duration::from_secs(20));
    assert_eq!(session.budget(), Duration::from_secs(20));
    node.shutdown().unwrap();
}

#[test]
fn upload_database_clock_shares_actual_verified_reads_across_phases_with_one_cap() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let scratch = ScratchDirectory::new();
        let policy = BudgetPolicy::finite_defaults()
            .with_class_limits(
                BudgetClass::Database,
                ClassLimits::finite(Duration::from_secs(5), 1_000_000, 50_000_000),
            )
            .unwrap();
        let (node, _) = OneNode::init(
            test_config(scratch.path().to_path_buf())
                .with_object_format(format)
                .with_runtime_budgets(policy),
        )
        .unwrap();
        let small = vec![b's'; 2_000];
        let large = vec![b'l'; 40_000];
        let small_id = put_object(&node, ObjectType::Blob, small.clone());
        let large_id = put_object(&node, ObjectType::Blob, large.clone());
        let session = session_deadline();
        session.note_admitted(5_000);
        assert!(session.note_selected_upload_work(40_000));
        let request = node.upload_request_context(&session);
        let ceiling = FabricReadCeiling::for_upload(&node, request.authority(), &session).unwrap();
        let exhaustion = Cell::new(None);
        let live = || !session.expired();
        let source = VerifiedFabricPackSource {
            fabric: &node.fabric,
            object_format: format,
            maximum_object_bytes: large.len(),
            database_context: request.authority(),
            database_exhaustion: &exhaustion,
            session_is_live: Some(&live),
        };

        // Ingress and selected lengths extended the transport to its cap, but
        // only this successful native-verified body read earns Database time.
        assert_eq!(session.budget(), Duration::from_secs(40));
        assert!(wall_time(&node, request.authority()) <= Duration::from_secs(5));
        assert_eq!(
            source
                .read_object_within(&small_id, Some(&ceiling))
                .unwrap(),
            (ObjectType::Blob, small)
        );
        assert_eq!(
            session.shared.verified_fabric_bytes.load(Ordering::Relaxed),
            2_000
        );
        let left = wall_time(&node, request.authority());
        assert!(left > Duration::from_secs(5) && left <= Duration::from_secs(7));

        let resumed = node.upload_request_context(&session);
        let resumed_ceiling =
            FabricReadCeiling::for_upload(&node, resumed.authority(), &session).unwrap();
        resumed_ceiling.rearm(resumed.authority());
        let left = wall_time(&node, resumed.authority());
        assert!(left > Duration::from_secs(5) && left <= Duration::from_secs(7));
        assert_eq!(
            session.shared.verified_fabric_bytes.load(Ordering::Relaxed),
            2_000
        );

        let next_source = VerifiedFabricPackSource {
            database_context: resumed.authority(),
            ..source
        };
        assert_eq!(
            next_source
                .read_object_within(&large_id, Some(&resumed_ceiling))
                .unwrap(),
            (ObjectType::Blob, large)
        );
        assert_eq!(
            session.shared.verified_fabric_bytes.load(Ordering::Relaxed),
            42_000
        );
        let capped = resumed.authority().attached_native_cx().unwrap().budget();
        let left = wall_time(&node, resumed.authority());
        assert!(left > Duration::from_secs(30) && left <= Duration::from_secs(35));
        resumed_ceiling.rearm(resumed.authority());
        assert_eq!(
            resumed
                .authority()
                .attached_native_cx()
                .unwrap()
                .budget()
                .deadline,
            capped.deadline
        );
        assert!(exhaustion.get().is_none());
        node.shutdown().unwrap();
    }
}

#[test]
fn fabric_clock_extension_preserves_remaining_quotas_and_caller_priority() {
    let scratch = ScratchDirectory::new();
    let policy = BudgetPolicy::finite_defaults();
    let (node, _) =
        OneNode::init(test_config(scratch.path().to_path_buf()).with_runtime_budgets(policy))
            .unwrap();
    let base = policy.limits_for(BudgetClass::Database).timeout.unwrap();
    let session = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(base + Duration::from_secs(60)).unwrap(),
        GitDaemonSessionWorkScaling::try_new(Duration::from_millis(1), Duration::from_secs(30))
            .unwrap(),
    );
    let context = FsqliteCx::new();
    let mut residual = ClassLimits {
        timeout: Some(base),
        poll_quota: 81,
        cost_quota: Some(47),
        priority: 255,
    }
    .at(node.runtime.now());
    for _ in 0..3 {
        let _ = residual.consume_poll();
    }
    assert!(residual.consume_cost(7));
    context.set_native_cx(node.runtime.request_cx_with_budget(residual));
    let before = context.attached_native_cx().unwrap().budget();
    // Asupersync meets priority using max: this caller explicitly chose more
    // urgent work than the class/root default. Rearming cannot reset it.
    assert_eq!(before.priority, 255);
    assert!(
        node.request_context()
            .authority()
            .attached_native_cx()
            .unwrap()
            .budget()
            .priority
            < before.priority
    );
    let ceiling = FabricReadCeiling::for_upload(&node, &context, &session).unwrap();
    ceiling.note_read(&context, 2_000);
    ceiling.rearm(&context);
    let after = context.attached_native_cx().unwrap().budget();
    assert!(wall_time(&node, &context) > base);
    assert_eq!(after.poll_quota, before.poll_quota);
    assert_eq!(after.cost_quota, before.cost_quota);
    assert_eq!(after.priority, before.priority);
    assert_eq!(after.poll_quota, 78);
    assert_eq!(after.cost_quota, Some(40));
    node.shutdown().unwrap();
}

#[test]
fn fabric_credit_cannot_revive_a_cancelled_or_exhausted_native_context() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(
        test_config(scratch.path().to_path_buf())
            .with_runtime_budgets(BudgetPolicy::finite_defaults()),
    )
    .unwrap();
    let expired = FsqliteCx::new();
    expired.set_native_cx(node.runtime.request_cx_with_budget(
        ClassLimits::finite(Duration::ZERO, 100, 100).at(node.runtime.now()),
    ));
    assert!(FabricReadCeiling::for_upload(&node, &expired, &session_deadline()).is_none());
    assert!(matches!(
        checkpoint_pack_context(&expired),
        PackContextCheckpoint::Stopped {
            budget_exhaustion: Some(Exhaustion::Deadline)
        }
    ));

    for (polls, cost, dimension) in [
        (100, 100, Exhaustion::Deadline),
        (0, 100, Exhaustion::PollQuota),
        (100, 0, Exhaustion::CostQuota),
    ] {
        let context = FsqliteCx::new();
        let limits = ClassLimits::finite(Duration::from_secs(2), polls, cost);
        context.set_native_cx(
            node.runtime
                .request_cx_with_budget(limits.at(node.runtime.now())),
        );
        let session = session_deadline();
        assert!(session.note_selected_upload_work(10_000));
        let ceiling = FabricReadCeiling::for_upload(&node, &context, &session).unwrap();
        let before = context.attached_native_cx().unwrap().budget();
        if dimension == Exhaustion::Deadline {
            // Let the originally attached deadline expire without a checkpoint
            // setting its cancellation bit before the verified read returns.
            std::thread::sleep(
                before
                    .remaining_time(node.runtime.now())
                    .unwrap_or_default(),
            );
            assert!(before.is_past_deadline(node.runtime.now()));
        }
        ceiling.note_read(&context, usize::MAX);
        ceiling.rearm(&context);
        assert_eq!(
            context.attached_native_cx().unwrap().budget(),
            before,
            "{dimension:?}"
        );
        assert_eq!(
            session.shared.verified_fabric_bytes.load(Ordering::Relaxed),
            0
        );
        assert!(matches!(
            checkpoint_pack_context(&context),
            PackContextCheckpoint::Stopped { budget_exhaustion: Some(found) } if found == dimension
        ));
    }
    let session = session_deadline();
    let request = node.upload_request_context(&session);
    let ceiling = FabricReadCeiling::for_upload(&node, request.authority(), &session).unwrap();
    request.cancel();
    let before = request.authority().attached_native_cx().unwrap().budget();
    ceiling.note_read(request.authority(), usize::MAX);
    ceiling.rearm(request.authority());
    assert_eq!(
        request
            .authority()
            .attached_native_cx()
            .unwrap()
            .budget()
            .deadline,
        before.deadline
    );
    assert_eq!(
        session.shared.verified_fabric_bytes.load(Ordering::Relaxed),
        0
    );
    assert!(request.authority().is_cancel_requested());
    node.shutdown().unwrap();
}
