use super::*;
use fgit_pack::full_bundle::FullBundleHeader;
use fgit_pack::full_bundle::stream::{StreamFullBundleError, StreamFullBundleLimits};
use fgit_pack::{PackError, read_streamed_pack};
use fgit_runtime::{ClassLimits, Exhaustion};
use std::collections::BTreeSet;
use std::future::poll_fn;
use std::io::{self, Cursor, Write};
use std::task::Poll;
use std::time::{Duration, Instant};

fn stream(
    node: &OneNode,
    visibility: &RefVisibility,
    query: StreamBundleExportQuery,
) -> (SelectedStreamBundleExport, Vec<u8>) {
    let request = node.request_context();
    let mut output = Vec::new();
    let result = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(&request, visibility, query, &mut output))
        .unwrap();
    (result, output)
}

fn recover(bytes: &[u8], limits: &StreamFullBundleLimits) -> (FullBundleHeader, BTreeSet<GitOid>) {
    let mut input = Cursor::new(bytes);
    let header = FullBundleHeader::read(&mut input, limits.envelope, &mut || true).unwrap();
    let mut ids = BTreeSet::new();
    read_streamed_pack(
        &mut input,
        header.format(),
        &limits.pack,
        &mut || true,
        |entry| -> Result<(), io::Error> {
            let kind = fgit_pack::object_type_from_base_entry(entry.entry.header.kind).unwrap();
            let id = git_object_id(header.format(), kind, &entry.entry.inflated);
            assert!(ids.insert(id), "duplicate object in streamed bundle");
            Ok(())
        },
    )
    .unwrap();
    (header, ids)
}

fn selection_pack_error(error: &StreamBundleExportRefusal) -> &PackError {
    let StreamBundleExportRefusal::Source(error) = error else {
        panic!("expected source refusal, got {error:?}");
    };
    let NodeWorkspaceRefusal::BundleGraph(error) = error.as_ref() else {
        panic!("expected graph refusal, got {error:?}");
    };
    let crate::NodePackMaterializationRefusal::Pack(error) = error.as_ref() else {
        panic!("expected pack refusal, got {error:?}");
    };
    let PackWriteError::Pack(error) = error.as_ref() else {
        panic!("expected bounded pack refusal, got {error:?}");
    };
    error
}

#[test]
fn both_formats_stream_exact_source_and_retry_without_changing_authority() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let (node, base, _child, _) = fixture(&root, format);
        accepted(apply(
            &node,
            &[create("refs/heads/topic", base)],
            "stream-topic",
        ));
        let before = snapshot(&node);
        let query = StreamBundleExportQuery {
            expected_head: Some(before.basis().id()),
            ..Default::default()
        };
        let (selected, bytes) = stream(&node, &Default::default(), query.clone());
        assert_eq!(selected.head(), before.basis().id());
        assert_eq!(selected.generation(), before.basis().generation());
        assert_eq!(selected.receipt().format(), format);
        assert_eq!(selected.receipt().bundle_bytes(), bytes.len());
        assert_eq!(
            selected.receipt().bundle_sha256(),
            fgit_crypto::sha256_digest(&bytes)
        );
        assert_eq!(selected.receipt().object_count(), 4);
        let (header, ids) = recover(&bytes, &query.limits);
        // HEAD comes only from the canonical target (genesis names main),
        // never from a branch's spelling.
        let main = reference("refs/heads/main");
        assert_eq!(before.snapshot().head_target.as_ref(), Some(&main));
        assert_eq!(header.head(), before.snapshot().refs.get(&main).copied());
        assert_eq!(header.references().len(), 2);
        assert_eq!(&ids, before.selected_closure().closure().objects());
        let (retried, repeated) = stream(&node, &Default::default(), query);
        assert_eq!(bytes, repeated);
        assert_eq!(selected.receipt(), retried.receipt());
        assert_eq!(snapshot(&node).basis(), before.basis());
        assert_eq!(snapshot(&node).snapshot().refs, before.snapshot().refs);

        let target = Scratch::new();
        let destination = empty_node(&target, format);
        accepted(import(&destination, &bytes, "streamed-import"));
        assert_eq!(
            snapshot(&destination).snapshot().refs,
            before.snapshot().refs
        );
        assert_eq!(
            snapshot(&destination).selected_closure().closure(),
            before.selected_closure().closure()
        );
        destination.shutdown().unwrap();
        node.shutdown().unwrap();
    }
}

#[test]
fn stale_head_invalid_timeout_and_empty_visibility_refuse_before_output() {
    let root = Scratch::new();
    let (node, base, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let old_head = snapshot(&node).basis().id();
    accepted(apply(
        &node,
        &[create("refs/heads/later", base)],
        "stream-later",
    ));
    let before = snapshot(&node);
    let request = node.request_context();
    let mut output = Vec::new();
    let stale = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery {
                expected_head: Some(old_head),
                ..Default::default()
            },
            &mut output,
        ));
    assert!(matches!(
        stale,
        Err(StreamBundleExportRefusal::ExpectedHead)
    ));
    assert!(output.is_empty());
    for timeout in [Duration::ZERO, Duration::from_secs(3601)] {
        let result = node
            .runtime()
            .block_on(node.export_full_git_bundle_stream_in(
                &request,
                &Default::default(),
                StreamBundleExportQuery {
                    timeout,
                    ..Default::default()
                },
                &mut output,
            ));
        assert!(matches!(
            result,
            Err(StreamBundleExportRefusal::InvalidTimeout)
        ));
        assert!(output.is_empty());
    }
    let result = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery {
                timeout: Duration::from_nanos(1),
                ..Default::default()
            },
            &mut output,
        ));
    assert!(matches!(result, Err(StreamBundleExportRefusal::Deadline)));
    assert!(output.is_empty());
    let mut hidden = RefVisibility::default();
    hidden.push_rule(b"refs", &Default::default()).unwrap();
    let result = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &hidden,
            StreamBundleExportQuery::default(),
            &mut output,
        ));
    assert!(
        matches!(result, Err(StreamBundleExportRefusal::Source(error))
        if matches!(error.as_ref(), NodeWorkspaceRefusal::RefUnavailable))
    );
    assert!(output.is_empty());
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn selection_limits_refuse_before_output_and_exact_payload_boundary_succeeds() {
    let root = Scratch::new();
    let (node, _, _, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let before = snapshot(&node);
    let (baseline, _) = stream(
        &node,
        &Default::default(),
        StreamBundleExportQuery::default(),
    );
    let payload = baseline.receipt().total_object_bytes();
    let mut exact = StreamBundleExportQuery::default();
    exact.limits.pack.max_total_expanded_bytes = payload;
    exact.limits.pack.max_entries = baseline.receipt().object_count();
    exact.limits.pack.max_index_entries =
        usize::try_from(baseline.receipt().object_count()).unwrap();
    exact.limits.max_graph_edges = 4; // child tree + parent, base tree, tree blob.
    exact.limits.envelope.max_references = 2; // main and the canonical HEAD naming it.
    let (selected, _) = stream(&node, &Default::default(), exact.clone());
    assert_eq!(selected.receipt(), baseline.receipt());

    let mut short = exact.clone();
    short.limits.pack.max_total_expanded_bytes = payload - 1;
    let request = node.request_context();
    let mut output = Vec::new();
    let error = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &Default::default(),
            short,
            &mut output,
        ))
        .unwrap_err();
    assert!(
        matches!(selection_pack_error(&error), PackError::TotalExpandedLimit { actual, limit }
        if *actual == payload && *limit == payload - 1)
    );
    assert!(
        output.is_empty(),
        "selection must stop before any header or pack output"
    );

    let mut limits = Vec::new();
    let mut limited = exact.clone();
    limited.limits.pack.max_entries = 1;
    limits.push(limited);
    let mut limited = exact.clone();
    limited.limits.pack.max_index_entries = 1;
    limits.push(limited);
    let mut limited = exact.clone();
    limited.limits.pack.max_object_bytes = 1;
    limits.push(limited);
    let mut limited = exact.clone();
    limited.limits.max_graph_edges = 1;
    limits.push(limited);
    let mut limited = exact;
    limited.limits.envelope.max_references = 0;
    limits.push(limited);
    for query in limits {
        let result = node
            .runtime()
            .block_on(node.export_full_git_bundle_stream_in(
                &request,
                &Default::default(),
                query,
                &mut output,
            ));
        assert!(matches!(result, Err(StreamBundleExportRefusal::Source(_))));
        assert!(output.is_empty());
    }
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn selected_ref_names_and_exact_encoded_header_have_prewrite_byte_bounds() {
    let root = Scratch::new();
    let (node, base, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    accepted(apply(
        &node,
        &[create("refs/heads/topic-with-a-longer-name", base)],
        "stream-header",
    ));
    let before = snapshot(&node);
    let (baseline, bytes) = stream(
        &node,
        &Default::default(),
        StreamBundleExportQuery::default(),
    );
    let mut input = Cursor::new(&bytes);
    let header = FullBundleHeader::read(
        &mut input,
        StreamBundleExportQuery::default().limits.envelope,
        &mut || true,
    )
    .unwrap();
    let header_bytes = usize::try_from(input.position()).unwrap();
    let selected_name_bytes: usize = header
        .references()
        .iter()
        .map(|reference| reference.name().as_bytes().len())
        .sum();
    assert!(header_bytes > selected_name_bytes);
    let mut exact = StreamBundleExportQuery::default();
    exact.limits.envelope.max_header_bytes = header_bytes;
    let (selected, repeated) = stream(&node, &Default::default(), exact.clone());
    assert_eq!(repeated, bytes);
    assert_eq!(selected.receipt(), baseline.receipt());

    let request = node.request_context();
    let mut output = Vec::new();
    for maximum in [
        header_bytes - 1,
        selected_name_bytes,
        selected_name_bytes - 1,
    ] {
        let mut query = exact.clone();
        query.limits.envelope.max_header_bytes = maximum;
        let error = node
            .runtime()
            .block_on(node.export_full_git_bundle_stream_in(
                &request,
                &Default::default(),
                query,
                &mut output,
            ))
            .unwrap_err();
        if maximum < selected_name_bytes {
            assert!(
                matches!(error, StreamBundleExportRefusal::Source(_)),
                "name custody must be bounded before calling the codec"
            );
        } else {
            assert!(
                matches!(error, StreamBundleExportRefusal::Stream(_)),
                "exact-name custody is permitted; the encoded header still must fit"
            );
        }
        assert!(output.is_empty());
    }
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn caller_hidden_and_deleted_only_history_are_not_export_roots() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (seed, base, child, _) = fixture(&source_root, format);
        seed.shutdown().unwrap();
        let source = source_root.0.join("source");
        fs::write(source.join("refs/heads/main"), format!("{base}\n")).unwrap();
        fs::write(source.join("refs/heads/topic"), format!("{child}\n")).unwrap();
        let target = Scratch::new();
        let node = empty_node(&target, format);
        let request = node.request_context();
        let receipt = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &request,
                &source,
                principal(),
                b"stream-visible-fixture",
            ))
            .unwrap();
        assert!(
            receipt.commands.iter().all(|command| matches!(
                command.terminal.outcome,
                DecisionOutcome::Committed { .. }
            ))
        );
        let mut visibility = RefVisibility::default();
        visibility
            .push_rule(b"refs/heads/topic", &Default::default())
            .unwrap();
        let query = StreamBundleExportQuery::default();
        let (_, filtered) = stream(&node, &visibility, query.clone());
        let (header, ids) = recover(&filtered, &query.limits);
        assert_eq!(header.references().len(), 1);
        assert_eq!(header.references()[0].name(), &reference("refs/heads/main"));
        // The canonical HEAD (main) is visible here, so the bundle carries it.
        assert_eq!(header.head(), Some(base));
        assert!(ids.contains(&base));
        assert!(!ids.contains(&child));
        assert_eq!(ids.len(), 3);
        // Keep default-branch protection intact; the deleted-only tip must
        // belong to a non-default branch, not an illegal main deletion.
        let before = snapshot(&node);
        assert!(matches!(
            apply(
                &node,
                &[RefCommand {
                    name: reference("refs/heads/main"),
                    expected_old: ExpectedOld::Exactly(base),
                    proposed_new: ProposedNew::Delete,
                    force: false,
                }],
                "stream-default-delete"
            ),
            Err(NodeWorkspaceRefusal::BranchOperation(_))
        ));
        assert_eq!(snapshot(&node).basis(), before.basis());
        accepted(apply(
            &node,
            &[RefCommand {
                name: reference("refs/heads/topic"),
                expected_old: ExpectedOld::Exactly(child),
                proposed_new: ProposedNew::Delete,
                force: false,
            }],
            "stream-delete",
        ));
        assert!(
            node.read_git_object(child).is_ok(),
            "deleted history remains stored"
        );
        let (_, after_delete) = stream(&node, &Default::default(), query);
        assert_eq!(after_delete, filtered);
        node.shutdown().unwrap();
    }
}

#[test]
fn inherited_native_budget_causes_and_caller_cancellation_stay_typed() {
    let root = Scratch::new();
    let (node, _, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let before = snapshot(&node);
    for (limits, expected) in [
        (
            ClassLimits::finite(Duration::ZERO, 1000, 1000),
            Exhaustion::Deadline,
        ),
        (
            ClassLimits::finite(Duration::from_secs(30), 0, 1000),
            Exhaustion::PollQuota,
        ),
        (
            ClassLimits::finite(Duration::from_secs(30), 1000, 0),
            Exhaustion::CostQuota,
        ),
    ] {
        let request = node.request_context();
        request.authority().set_native_cx(
            node.runtime()
                .request_cx_with_budget(limits.at(node.runtime().now())),
        );
        let mut output = Vec::new();
        let result = node
            .runtime()
            .block_on(node.export_full_git_bundle_stream_in(
                &request,
                &Default::default(),
                StreamBundleExportQuery::default(),
                &mut output,
            ));
        assert!(
            matches!(result, Err(StreamBundleExportRefusal::Cancelled { exhaustion: Some(cause) })
            if cause == expected),
            "{expected:?}: {result:?}"
        );
        assert!(output.is_empty());
    }
    let request = node.request_context();
    request.cancel();
    let mut output = Vec::new();
    assert!(matches!(
        node.runtime()
            .block_on(node.export_full_git_bundle_stream_in(
                &request,
                &Default::default(),
                StreamBundleExportQuery::default(),
                &mut output,
            )),
        Err(StreamBundleExportRefusal::Cancelled { .. })
    ));
    assert!(output.is_empty());
    assert_eq!(snapshot(&node).basis(), before.basis());
    stream(
        &node,
        &Default::default(),
        StreamBundleExportQuery::default(),
    );
    node.shutdown().unwrap();
}

#[test]
fn a_pulse_stop_before_materialization_does_not_cancel_the_parent_request() {
    let root = Scratch::new();
    let (node, _, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let before = snapshot(&node);
    let request = node.request_context();
    let calls = Cell::new(0);
    let mut output = Vec::new();
    let result = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_controlled_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery::default(),
            &mut output,
            &mut || {
                calls.set(calls.get() + 1);
                calls.get() != 2
            },
        ));
    assert!(matches!(
        result,
        Err(StreamBundleExportRefusal::Cancelled { exhaustion: None })
    ));
    assert_eq!(
        calls.get(),
        2,
        "the rejected probe must never be called again"
    );
    assert!(output.is_empty());
    assert!(matches!(
        crate::checkpoint_pack_context(request.authority()),
        crate::PackContextCheckpoint::Live
    ));
    let retried = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery::default(),
            &mut output,
        ))
        .unwrap();
    assert_eq!(retried.head(), before.basis().id());
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}

#[test]
fn immediately_ready_stop_ticks_are_consumed_once_and_pending_ticks_keep_their_wake() {
    use std::cell::RefCell;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Wake, Waker};

    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    struct RegisteredTick<'a>(&'a RefCell<Option<Waker>>);
    impl Future for RegisteredTick<'_> {
        type Output = ();
        fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
            self.0.replace(Some(context.waker().clone()));
            Poll::Pending
        }
    }
    let wakes = Arc::new(CountWake(AtomicUsize::new(0)));
    let waker = Waker::from(wakes.clone());
    let mut context = Context::from_waker(&waker);
    // Ready, like Sleep, panics if polled again after completion. Every new
    // tick is immediately ready here: this is a deterministic scheduling unit
    // test, not a substitute for the native export/drain tests below.
    let mut ready = std::pin::pin!(std::future::ready(()));
    for expected in 1..=4 {
        super::super::streaming::rearm_stop_tick(ready.as_mut(), &mut context, || {
            std::future::ready(())
        });
        assert_eq!(wakes.0.load(Ordering::SeqCst), expected);
    }
    let registration = RefCell::new(None);
    let mut pending = std::pin::pin!(RegisteredTick(&registration));
    super::super::streaming::rearm_stop_tick(pending.as_mut(), &mut context, || {
        panic!("a pending tick must retain its registered wake")
    });
    assert_eq!(wakes.0.load(Ordering::SeqCst), 4);
    registration
        .borrow_mut()
        .take()
        .expect("the pending timer registered its wake")
        .wake();
    assert_eq!(wakes.0.load(Ordering::SeqCst), 5);
}

#[test]
fn pending_materialization_stop_is_woken_and_drained_without_a_child_wake() {
    let root = Scratch::new();
    let (node, _, _, _) = fixture(&root, GitHashAlgorithm::Sha1);
    let request = node.request_context();
    let (child, cancellation) = request.authority().create_child_with_local_cancel_relay();
    let polls = Cell::new(0);
    let drained = Cell::new(false);
    let observed_stop = Cell::new(false);
    // Intentionally register no child wake: a caller-owned stop has no native
    // authority completion to wake it. Only the production driver's timer can
    // bring this operation back to its cancellation checkpoint and completion.
    let pending = poll_fn(|_| {
        polls.set(polls.get() + 1);
        if child.is_cancel_requested() {
            drained.set(true);
            Poll::Ready(42)
        } else {
            Poll::Pending
        }
    });
    let result = node
        .runtime()
        .block_on(super::super::streaming::drain_materialization(
            &node,
            pending,
            Instant::now(),
            Duration::from_secs(5),
            || {
                if polls.get() != 0 {
                    observed_stop.set(true);
                    assert!(
                        cancellation.cancel_local(fsqlite_types::cx::CancelReason::UserInterrupt)
                    );
                }
            },
        ));
    assert_eq!(result, 42);
    assert!(observed_stop.get());
    assert!(
        drained.get(),
        "the same pending operation must run to completion"
    );
    assert!(polls.get() >= 2);
    assert!(matches!(
        crate::checkpoint_pack_context(request.authority()),
        crate::PackContextCheckpoint::Live
    ));
    node.shutdown().unwrap();
}

struct FailingSink {
    bytes: Vec<u8>,
    remaining: usize,
}
impl Write for FailingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected output refusal"));
        }
        let count = self.remaining.min(bytes.len()).min(7);
        self.bytes.extend_from_slice(&bytes[..count]);
        self.remaining -= count;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("node export must not flush caller-owned staging");
    }
}

struct PulseSink<'a> {
    bytes: Vec<u8>,
    stop: &'a Cell<bool>,
}
impl Write for PulseSink<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = bytes.len().min(7);
        self.bytes.extend_from_slice(&bytes[..count]);
        self.stop.set(true);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        panic!("node export must not flush caller-owned staging");
    }
}

#[test]
fn partial_output_failure_and_stop_never_publish_and_allow_a_fresh_sink_retry() {
    let root = Scratch::new();
    let (node, _, _, _) = fixture(&root, GitHashAlgorithm::Sha256);
    let before = snapshot(&node);
    let (_, expected) = stream(
        &node,
        &Default::default(),
        StreamBundleExportQuery::default(),
    );
    let request = node.request_context();
    let mut broken = FailingSink {
        bytes: Vec::new(),
        remaining: 19,
    };
    let result = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery::default(),
            &mut broken,
        ));
    assert!(matches!(
        result,
        Err(StreamBundleExportRefusal::Stream(
            StreamFullBundleError::Io(_)
        ))
    ));
    assert_eq!(broken.bytes.len(), 19);
    let stop = Cell::new(false);
    let observed_stops = Cell::new(0);
    let mut stopped = PulseSink {
        bytes: Vec::new(),
        stop: &stop,
    };
    let result = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_controlled_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery::default(),
            &mut stopped,
            &mut || {
                if stop.replace(false) {
                    observed_stops.set(observed_stops.get() + 1);
                    false
                } else {
                    true
                }
            },
        ));
    assert!(matches!(
        result,
        Err(StreamBundleExportRefusal::Cancelled { exhaustion: None })
    ));
    assert_eq!(observed_stops.get(), 1);
    assert_eq!(stopped.bytes.len(), 7);
    let mut retry = Vec::new();
    let selected = node
        .runtime()
        .block_on(node.export_full_git_bundle_stream_in(
            &request,
            &Default::default(),
            StreamBundleExportQuery::default(),
            &mut retry,
        ))
        .unwrap();
    assert_eq!(selected.head(), before.basis().id());
    assert_eq!(retry, expected);
    assert_eq!(snapshot(&node).basis(), before.basis());
    node.shutdown().unwrap();
}
