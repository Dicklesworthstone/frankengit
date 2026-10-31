//! Upload work and terminal reporting have distinct, finite clocks.
use super::*;
use crate::{GitDaemonSessionDeadline, GitDaemonSessionWorkScaling};
use std::time::Instant;

fn session_deadline() -> GitDaemonSessionDeadline {
    GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::try_new(Duration::from_secs(10)).unwrap(),
        GitDaemonSessionWorkScaling::try_new(Duration::from_millis(1), Duration::from_secs(30))
            .unwrap(),
    )
}

#[test]
fn selected_upload_allowance_is_shared_bounded_and_never_added_twice() {
    let deadline = session_deadline();
    let twin = deadline.clone();
    deadline.note_admitted(1000);
    assert_eq!(deadline.budget(), Duration::from_secs(11));
    assert!(deadline.note_selected_upload_work(2000));
    assert_eq!(twin.budget(), Duration::from_secs(13));
    assert!(twin.note_selected_upload_work(2000));
    assert!(twin.note_selected_upload_work(1000));
    assert_eq!(deadline.budget(), Duration::from_secs(13));
    assert!(deadline.note_selected_upload_work(usize::MAX));
    deadline.note_admitted(usize::MAX);
    assert_eq!(deadline.budget(), Duration::from_secs(40));
    let flat = GitDaemonSessionDeadline::new(
        GitDaemonSessionTimeout::DEFAULT,
        GitDaemonSessionWorkScaling::FLAT,
    );
    assert!(flat.note_selected_upload_work(usize::MAX));
    assert_eq!(flat.budget(), GitDaemonSessionTimeout::DEFAULT.duration());
}

#[test]
fn terminal_upload_report_never_revives_work_and_is_only_armed_once() {
    let mut deadline = session_deadline();
    deadline.started = Instant::now()
        .checked_sub(Duration::from_secs(11))
        .expect("test clock supports a past deadline");
    assert!(deadline.expired());
    assert!(!deadline.note_selected_upload_work(usize::MAX));
    assert!(deadline.remaining_write().is_err());
    deadline.begin_terminal_response();
    let expiry = *deadline.shared.terminal_response.get().unwrap();
    assert!(deadline.remaining_write().is_ok());
    assert!(deadline.remaining().is_err());
    assert!(!deadline.note_selected_upload_work(usize::MAX));
    deadline.begin_terminal_response();
    assert_eq!(deadline.shared.terminal_response.get(), Some(&expiry));
    // A terminal phase already in the past cannot be replaced by retrying.
    let stopped = session_deadline();
    stopped
        .shared
        .terminal_response
        .set(
            Instant::now()
                .checked_sub(Duration::from_secs(1))
                .expect("test clock supports a past deadline"),
        )
        .unwrap();
    stopped.begin_terminal_response();
    assert!(stopped.remaining_write().is_err());
    assert!(!stopped.note_selected_upload_work(1000));
}

#[test]
fn raw_upload_timeout_writes_an_actionable_err_after_its_work_clock_expires() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let mut deadline = session_deadline();
    deadline.started = Instant::now()
        .checked_sub(Duration::from_secs(11))
        .expect("test clock supports a past deadline");
    {
        let mut writer = crate::DeadlineTcpStream::new(&mut stream, deadline.clone());
        assert!(matches!(
            crate::check_selected_pack_deadline(
                &mut writer,
                &WireLimits::default(),
                Some(&deadline),
            ),
            Err(GitDaemonTransportRefusal::SessionDeadlineExceeded { .. })
        ));
        assert!(writer.prepare_read().is_err(), "Git input remains expired");
    }
    stream.shutdown(Shutdown::Write).unwrap();
    let mut response = Vec::new();
    peer.read_to_end(&mut response).unwrap();
    let packet_len =
        usize::from_str_radix(std::str::from_utf8(&response[..4]).unwrap(), 16).unwrap();
    let text = std::str::from_utf8(&response[4..packet_len]).unwrap();
    assert!(
        text.starts_with("ERR "),
        "terminal diagnostics precede pack negotiation"
    );
    for flag in [
        "--session-timeout-secs",
        "--session-secs-per-mib",
        "--session-max-extension-secs",
    ] {
        assert!(text.contains(flag), "{text}");
    }
    assert_eq!(
        response.len(),
        packet_len,
        "one error packet, no pack prefix or flush"
    );
    assert!(deadline.expired());
}

#[test]
fn selected_upload_rearming_keeps_remaining_transfer_quotas_and_priority() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    let context = FsqliteCx::new();
    let limits = ClassLimits {
        timeout: Some(Duration::from_secs(5)),
        poll_quota: 81,
        cost_quota: Some(47),
        priority: 17,
    };
    let mut residual = limits.at(node.runtime.now());
    for _ in 0..3 {
        let _ = residual.consume_poll();
    }
    assert!(residual.consume_cost(7));
    context.set_native_cx(node.runtime.request_cx_with_budget(residual));
    let before = context.attached_native_cx().unwrap().budget();
    let deadline = session_deadline();
    node.rearm_session_pack_materialization_context(&context, &deadline, 2000)
        .unwrap();
    let after = context.attached_native_cx().unwrap().budget();
    let remaining = after.remaining(node.runtime.now());
    assert!(remaining.deadline.unwrap() > Duration::from_secs(11));
    assert_eq!(after.priority, before.priority);
    // Native checkpoints observe these quotas; synchronous checkpoints do not
    // spend scheduler polls. Rearming must carry the exact current values.
    assert_eq!(after.poll_quota, before.poll_quota);
    assert_eq!(after.cost_quota, before.cost_quota);
    assert_eq!(after.poll_quota, 78);
    assert_eq!(after.cost_quota, Some(40));
    assert_eq!(deadline.budget(), Duration::from_secs(12));
    let second = after.poll_quota;
    node.rearm_session_pack_materialization_context(&context, &deadline, 2000)
        .unwrap();
    assert_eq!(deadline.budget(), Duration::from_secs(12));
    assert_eq!(
        context.attached_native_cx().unwrap().budget().poll_quota,
        second
    );
    node.shutdown().unwrap();
}

#[test]
fn stopped_transfer_contexts_earn_no_upload_allowance_or_replacement() {
    let scratch = ScratchDirectory::new();
    let (node, _) = OneNode::init(test_config(scratch.path().to_path_buf())).unwrap();
    for limits in [
        ClassLimits::finite(Duration::ZERO, 100, 100),
        ClassLimits::finite(Duration::from_secs(30), 0, 100),
        ClassLimits::finite(Duration::from_secs(30), 100, 0),
    ] {
        let context = FsqliteCx::new();
        context.set_native_cx(
            node.runtime
                .request_cx_with_budget(limits.at(node.runtime.now())),
        );
        let deadline = session_deadline();
        assert!(
            node.rearm_session_pack_materialization_context(&context, &deadline, usize::MAX)
                .is_err()
        );
        assert_eq!(
            deadline
                .shared
                .selected_upload_bytes
                .load(Ordering::Relaxed),
            0
        );
        assert!(matches!(
            checkpoint_pack_context(&context),
            PackContextCheckpoint::Stopped { .. }
        ));
    }
    let context = node.session_pack_materialization_context(&session_deadline());
    context.cancel();
    let deadline = session_deadline();
    assert!(
        node.rearm_session_pack_materialization_context(&context, &deadline, 2000)
            .is_err()
    );
    assert_eq!(
        deadline
            .shared
            .selected_upload_bytes
            .load(Ordering::Relaxed),
        0
    );
    assert!(context.is_cancel_requested());
    node.shutdown().unwrap();
}
