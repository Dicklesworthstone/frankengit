#![forbid(unsafe_code)]
//! Real native pack parsing with an independently owned, one-use handoff.
//! The observer checks structural custody; it does not claim ref admission.

use std::cell::Cell;

use fgit_git_object::{ObjectType, Sha1, Sha256, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, Deadline, ObjectId, PackError, PackLimits,
    PackPlanner, PackWriteError, PackWriteProfile, PackWriter, QuarantinedPack, RetainedPackBytes,
};
use fgit_types::RefusalCode;
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveContext, ReceiveError, ReceiveLimits, ReceivePack,
    ReceiveQuarantineHandoff, ReceiveRequest, SignedPushProfile,
};
use fgit_wire::smart_http::rpc::{ReceiveRpc, RpcError};
use fgit_wire::smart_http::{HttpLimits, ProtocolVersion, parse_head};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits, encode_packets};

struct Blob(CanonicalPackObject);

impl CanonicalObjectSource for Blob {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        assert_eq!(*id, self.0.id());
        Ok(self.0.clone())
    }
}

fn blob_pack(format: GitObjectFormat) -> (ObjectId, Vec<u8>, Vec<u8>) {
    let body = b"one private native quarantine, before writer admission\n".repeat(64);
    let id = match format {
        GitObjectFormat::Sha1 => ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &body)),
        GitObjectFormat::Sha256 => {
            ObjectId::from(native_object_oid::<Sha256>(ObjectType::Blob, &body))
        }
    };
    let source = Blob(CanonicalPackObject::new(
        id,
        ObjectType::Blob,
        body.clone(),
        Vec::new(),
        0,
        0,
    ));
    let plan = PackPlanner::new(format, PackWriteProfile::STORED_V1, PackLimits::default())
        .plan(&source, &[id], &mut || true)
        .unwrap();
    let (pack, _) = PackWriter::new(PackLimits::default())
        .write(&plan, &mut || true)
        .unwrap();
    (id, body, pack)
}

fn context(format: GitObjectFormat, limits: ReceiveLimits) -> ReceiveContext {
    let caps = format!("report-status delete-refs object-format={format}");
    ReceiveContext::new(
        format,
        Capabilities::parse_v1(caps.as_bytes(), &limits.wire).unwrap(),
        limits,
        SignedPushProfile::Refuse,
    )
    .unwrap()
}

fn wire(format: GitObjectFormat, target: ObjectId, pack: Option<&[u8]>) -> Vec<u8> {
    let zero = "00".repeat(format.digest_len());
    let (old, new) = if pack.is_some() {
        (zero, target.to_string())
    } else {
        (target.to_string(), zero)
    };
    let mut bytes = encode_packets(
        &[
            Packet::Data(
                format!(
                    "{old} {new} refs/tags/owned\0report-status delete-refs object-format={format}"
                )
                .into_bytes(),
            ),
            Packet::Flush,
        ],
        &WireLimits::default(),
    )
    .unwrap();
    if let Some(pack) = pack {
        bytes.extend_from_slice(pack);
    }
    bytes
}

fn machine(format: GitObjectFormat, bytes: &[u8], limits: ReceiveLimits) -> ReceivePack {
    let mut machine = ReceivePack::new(context(format, limits)).unwrap();
    for fragment in bytes.chunks(7) {
        machine.push_bytes(fragment).unwrap();
    }
    machine
}

struct Observe<'a> {
    body: Option<&'a [u8]>,
    calls: usize,
    refusal: Option<RefusalCode>,
    cancel_after: Option<&'a Cell<bool>>,
}

impl<'a> Observe<'a> {
    const fn new(body: Option<&'a [u8]>) -> Self {
        Self {
            body,
            calls: 0,
            refusal: None,
            cancel_after: None,
        }
    }
}

impl ReceiveQuarantineHandoff for Observe<'_> {
    fn handoff(
        &mut self,
        _: &ReceiveRequest,
        _: Option<&QuarantinedPack>,
        _: &QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        panic!("the owned handoff must forward its live cancellation boundary");
    }

    fn handoff_with_deadline(
        &mut self,
        request: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
        deadline: &mut dyn Deadline,
    ) -> Result<(), ReceiveError> {
        assert!(deadline.checkpoint());
        assert_eq!(request.commands.len(), 1);
        assert_eq!(request.commands[0].ref_name, b"refs/tags/owned");
        assert_eq!(receipt.delete_only, self.body.is_none());
        match self.body {
            Some(body) => {
                let pack = pack.expect("the same native pack reaches the handoff");
                assert_eq!(receipt.object_count, 1);
                assert_eq!(pack.entries().len(), 1);
                assert_eq!(pack.entries()[0].inflated, body);
            }
            None => {
                assert!(pack.is_none());
                assert_eq!(receipt.object_count, 0);
                assert_eq!(receipt.pack_bytes, 0);
            }
        }
        self.calls += 1;
        if let Some(cancelled) = self.cancel_after {
            cancelled.set(true);
        }
        match self.refusal {
            Some(code) => Err(ReceiveError::AuthoritativeRefusal(code)),
            None => Ok(()),
        }
    }
}

#[test]
fn separated_and_immediate_handoffs_preserve_the_same_native_input() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, body, pack) = blob_pack(format);
        for delete in [false, true] {
            let bytes = wire(format, id, (!delete).then_some(pack.as_slice()));
            let expected_body = (!delete).then_some(body.as_slice());
            let mut immediate = Observe::new(expected_body);
            let expected = machine(format, &bytes, ReceiveLimits::default())
                .finish_with_handoff(&mut immediate, &mut || true)
                .unwrap();
            let mut delayed = Observe::new(expected_body);
            let quarantine = machine(format, &bytes, ReceiveLimits::default())
                .into_quarantine(&mut || true)
                .unwrap();
            assert_eq!(delayed.calls, 0, "parsing does not invoke admission");
            assert_eq!(quarantine.request(), &expected.request);
            assert_eq!(quarantine.receipt(), &expected.quarantine);
            let observed = quarantine.handoff(&mut delayed, &mut || true).unwrap();
            assert_eq!(observed, expected);
            assert_eq!(delayed.calls, 1);
            assert_eq!(immediate.calls, 1);
        }
    }
}

#[test]
fn corrupt_or_over_budget_pack_never_yields_a_quarantine_owner() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, body, pack) = blob_pack(format);
        let mut corrupt = pack.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(matches!(
            machine(
                format,
                &wire(format, id, Some(&corrupt)),
                ReceiveLimits::default()
            )
            .into_quarantine(&mut || true),
            Err(ReceiveError::Pack(PackError::TrailerChecksumMismatch))
        ));
        let bytes = wire(format, id, Some(&pack));
        let limits = ReceiveLimits {
            pack: PackLimits {
                max_object_bytes: body.len() - 1,
                ..PackLimits::default()
            },
            ..ReceiveLimits::default()
        };
        assert!(matches!(
            machine(format, &bytes, limits).into_quarantine(&mut || true),
            Err(ReceiveError::Pack(PackError::ObjectSizeLimit { .. }))
        ));
        let mut allowed = Observe::new(Some(&body));
        machine(format, &bytes, ReceiveLimits::default())
            .into_quarantine(&mut || true)
            .unwrap()
            .handoff(&mut allowed, &mut || true)
            .unwrap();
        assert_eq!(allowed.calls, 1, "the identical bounded valid pack passes");
    }
}

#[test]
fn cancellation_during_parse_or_between_phases_cannot_enter_the_handoff() {
    let format = GitObjectFormat::Sha1;
    let (id, body, pack) = blob_pack(format);
    let bytes = wire(format, id, Some(&pack));
    let mut checkpoints = 0;
    drop(
        machine(format, &bytes, ReceiveLimits::default())
            .into_quarantine(&mut || {
                checkpoints += 1;
                true
            })
            .unwrap(),
    );
    assert!(
        checkpoints > 2,
        "the actual pack parser cooperates during work"
    );
    for stop_at in [1, checkpoints / 2, checkpoints] {
        let mut observed = 0;
        assert!(
            machine(format, &bytes, ReceiveLimits::default())
                .into_quarantine(&mut || {
                    observed += 1;
                    observed < stop_at
                })
                .is_err()
        );
    }
    let quarantine = machine(format, &bytes, ReceiveLimits::default())
        .into_quarantine(&mut || true)
        .unwrap();
    let mut handoff = Observe::new(Some(&body));
    assert_eq!(
        quarantine.handoff(&mut handoff, &mut || false),
        Err(ReceiveError::Cancelled)
    );
    assert_eq!(handoff.calls, 0);
    // A new transport attempt is independent of the discarded owner.
    machine(format, &bytes, ReceiveLimits::default())
        .into_quarantine(&mut || true)
        .unwrap()
        .handoff(&mut handoff, &mut || true)
        .unwrap();
    assert_eq!(handoff.calls, 1);
}

#[test]
fn consuming_handoff_preserves_its_refusal_or_success_after_late_cancellation() {
    let format = GitObjectFormat::Sha256;
    let (id, body, pack) = blob_pack(format);
    let bytes = wire(format, id, Some(&pack));
    for refusal in [None, Some(RefusalCode::ObjectClosureIncomplete)] {
        let cancelled = Cell::new(false);
        let mut handoff = Observe::new(Some(&body));
        handoff.refusal = refusal;
        handoff.cancel_after = Some(&cancelled);
        let quarantine = machine(format, &bytes, ReceiveLimits::default())
            .into_quarantine(&mut || true)
            .unwrap();
        let outcome = quarantine.handoff(&mut handoff, &mut || !cancelled.get());
        assert!(cancelled.get());
        assert_eq!(handoff.calls, 1);
        match refusal {
            Some(code) => assert_eq!(outcome, Err(ReceiveError::AuthoritativeRefusal(code))),
            None => assert!(
                outcome.is_ok(),
                "a late stop cannot replace the handoff result"
            ),
        }
    }
}

fn http_rpc(format: GitObjectFormat, bytes: &[u8], chunked: bool, complete: bool) -> ReceiveRpc {
    let framing = if chunked {
        "Transfer-Encoding: chunked".to_owned()
    } else {
        format!("Content-Length: {}", bytes.len() + usize::from(!complete))
    };
    let head = format!(
        "POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\n{framing}\r\n\r\n"
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut rpc = ReceiveRpc::new(
        &request,
        ProtocolVersion::V0,
        context(format, ReceiveLimits::default()),
        HttpLimits::default(),
    )
    .unwrap();
    let input = if chunked {
        let mut input = format!("{:x}\r\n", bytes.len()).into_bytes();
        input.extend_from_slice(bytes);
        input.extend_from_slice(if complete { b"\r\n0\r\n\r\n" } else { b"\r\n" });
        input
    } else {
        bytes.to_vec()
    };
    for fragment in input.chunks(11) {
        let step = rpc.push(fragment, &mut || true).unwrap();
        assert_eq!(step.consumed, fragment.len());
    }
    rpc
}

#[test]
fn http_must_finish_its_entire_envelope_before_transferring_native_quarantine() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, body, pack) = blob_pack(format);
        for delete in [false, true] {
            let bytes = wire(format, id, (!delete).then_some(pack.as_slice()));
            for chunked in [false, true] {
                assert!(matches!(
                    http_rpc(format, &bytes, chunked, false).into_quarantine(&mut || true),
                    Err(RpcError::Http(_))
                ));
                let mut handoff = Observe::new((!delete).then_some(body.as_slice()));
                let owned = http_rpc(format, &bytes, chunked, true)
                    .into_quarantine(&mut || true)
                    .unwrap();
                assert_eq!(handoff.calls, 0);
                owned.handoff(&mut handoff, &mut || true).unwrap();
                assert_eq!(handoff.calls, 1);
            }
        }
    }
}

/// An advisory speculation sees exactly the input the one consuming handoff
/// later sees and keeps custody. A cancelled speculation never calls the
/// handoff, and a speculative refusal decides nothing: the consuming handoff
/// still runs and returns its own result (frankengit-root-doctrine-x2mv.4.9).
#[test]
fn speculation_sees_the_same_input_and_leaves_the_one_consuming_handoff() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, body, pack) = blob_pack(format);
        for delete in [false, true] {
            let bytes = wire(format, id, (!delete).then_some(pack.as_slice()));
            let expected_body = (!delete).then_some(body.as_slice());
            let mut immediate = Observe::new(expected_body);
            let expected = machine(format, &bytes, ReceiveLimits::default())
                .finish_with_handoff(&mut immediate, &mut || true)
                .unwrap();
            let quarantine = machine(format, &bytes, ReceiveLimits::default())
                .into_quarantine(&mut || true)
                .unwrap();
            let mut cancelled = Observe::new(expected_body);
            assert_eq!(
                quarantine.speculate(&mut cancelled, &mut || false),
                Err(ReceiveError::Cancelled)
            );
            assert_eq!(cancelled.calls, 0);
            let mut speculative = Observe::new(expected_body);
            speculative.refusal = Some(RefusalCode::EvidenceInvalid);
            assert_eq!(
                quarantine.speculate(&mut speculative, &mut || true),
                Err(ReceiveError::AuthoritativeRefusal(
                    RefusalCode::EvidenceInvalid
                ))
            );
            assert_eq!(speculative.calls, 1);
            assert_eq!(quarantine.request(), &expected.request);
            let mut authoritative = Observe::new(expected_body);
            let observed = quarantine
                .handoff(&mut authoritative, &mut || true)
                .unwrap();
            assert_eq!(observed, expected);
            assert_eq!(authoritative.calls, 1);
        }
    }
}

/// git's remote-curl sends a lone flush packet before any request larger
/// than http.postBuffer and requires 200. That complete body is a probe in
/// either framing. A flush followed by more bytes is an ordinary request
/// with no commands, refused as before, and a caller that does not answer
/// probes still refuses one (frankengit-wh86).
#[test]
fn a_lone_flush_body_is_a_probe_and_anything_more_is_still_refused() {
    let format = GitObjectFormat::Sha1;
    for chunked in [false, true] {
        let probe = http_rpc(format, b"0000", chunked, true);
        assert!(probe.is_probe(), "chunked={chunked}");
        assert!(matches!(
            probe.into_quarantine(&mut || true),
            Err(RpcError::Receive(ReceiveError::MissingCommands))
        ));
        assert!(
            !http_rpc(format, b"0000", chunked, false).is_probe(),
            "an incomplete body is not yet a probe"
        );
    }
    let head = "POST /repo.git/git-receive-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 8\r\n\r\n";
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let mut rpc = ReceiveRpc::new(
        &request,
        ProtocolVersion::V0,
        context(format, ReceiveLimits::default()),
        HttpLimits::default(),
    )
    .unwrap();
    rpc.push(b"0000", &mut || true).unwrap();
    assert!(!rpc.is_probe(), "the body is not complete");
    assert!(matches!(
        rpc.push(b"0000", &mut || true),
        Err(RpcError::Receive(ReceiveError::MissingCommands))
    ));
}

#[derive(Default)]
struct ObserveRetention {
    calls: usize,
    retained: Option<RetainedPackBytes>,
    body: Option<Vec<u8>>,
}

impl ReceiveQuarantineHandoff for ObserveRetention {
    fn handoff(
        &mut self,
        _: &ReceiveRequest,
        pack: Option<&QuarantinedPack>,
        receipt: &QuarantineReceipt,
    ) -> Result<(), ReceiveError> {
        self.calls += 1;
        if let Some(pack) = pack {
            assert_eq!(pack.header.object_count, receipt.object_count);
            self.body = Some(pack.entries()[0].inflated.clone());
            if let Some(retained) = pack.retained_bytes() {
                assert_eq!(retained.object_count(), receipt.object_count);
                assert_eq!(retained.format(), receipt.object_format);
                assert_eq!(retained.checksum(), pack.trailer);
                assert_eq!(retained.bytes().len(), receipt.pack_bytes);
                self.retained = Some(retained.clone());
            }
        }
        Ok(())
    }
}

#[test]
fn retention_is_explicit_bounded_and_changes_neither_handoff_nor_completion() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, body, pack) = blob_pack(format);
        let bytes = wire(format, id, Some(&pack));
        let mut expected = None;
        // The fragmented ingress allocation may exceed its length. The large
        // explicit cap admits that capacity; undersized caps preserve parsing.
        for cap in [None, Some(0), Some(pack.len() - 1), Some(128 * 1024)] {
            for delayed in [false, true] {
                let mut machine = machine(format, &bytes, ReceiveLimits::default());
                if let Some(cap) = cap {
                    machine = machine.with_pack_retention(cap);
                }
                let mut handoff = ObserveRetention::default();
                let completion = if delayed {
                    machine
                        .into_quarantine(&mut || true)
                        .unwrap()
                        .handoff(&mut handoff, &mut || true)
                } else {
                    machine.finish_with_handoff(&mut handoff, &mut || true)
                }
                .unwrap();
                assert_eq!(handoff.calls, 1);
                assert_eq!(handoff.body.as_deref(), Some(body.as_slice()));
                if cap == Some(128 * 1024) {
                    let retained = handoff.retained.unwrap();
                    assert_eq!(retained.bytes(), pack);
                    assert!(retained.retained_capacity() <= cap.unwrap());
                } else {
                    assert!(handoff.retained.is_none());
                }
                if let Some(expected) = &expected {
                    assert_eq!(&completion, expected);
                } else {
                    expected = Some(completion);
                }
            }
        }
        let mut delete = ObserveRetention::default();
        machine(format, &wire(format, id, None), ReceiveLimits::default())
            .with_pack_retention(128 * 1024)
            .finish_with_handoff(&mut delete, &mut || true)
            .unwrap();
        assert_eq!(delete.calls, 1);
        assert!(delete.body.is_none());
        assert!(delete.retained.is_none());
    }
}

#[test]
fn retained_receive_still_refuses_corruption_and_cancellation_before_handoff() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, _, pack) = blob_pack(format);
        for cap in [0, 128 * 1024] {
            let mut corrupted = pack.clone();
            *corrupted.last_mut().unwrap() ^= 1;
            let mut handoff = ObserveRetention::default();
            let mut corrupt = machine(
                format,
                &wire(format, id, Some(&corrupted)),
                ReceiveLimits::default(),
            )
            .with_pack_retention(cap);
            assert_eq!(
                corrupt.finish_with_handoff(&mut handoff, &mut || true),
                Err(ReceiveError::Pack(PackError::TrailerChecksumMismatch))
            );
            assert_eq!(corrupt.quarantine_len(), 0);
            let bytes = wire(format, id, Some(&pack));
            let mut cancelled =
                machine(format, &bytes, ReceiveLimits::default()).with_pack_retention(cap);
            assert_eq!(
                cancelled.finish_with_handoff(&mut handoff, &mut || false),
                Err(ReceiveError::Cancelled)
            );
            assert_eq!(cancelled.quarantine_len(), 0);
            let owned = machine(format, &bytes, ReceiveLimits::default())
                .with_pack_retention(cap)
                .into_quarantine(&mut || true)
                .unwrap();
            assert_eq!(
                owned.handoff(&mut handoff, &mut || false),
                Err(ReceiveError::Cancelled)
            );
            assert_eq!(handoff.calls, 0);
            assert!(handoff.retained.is_none());
            machine(format, &bytes, ReceiveLimits::default())
                .with_pack_retention(cap)
                .finish_with_handoff(&mut handoff, &mut || true)
                .unwrap();
            assert_eq!(handoff.calls, 1, "a fresh valid receive still succeeds");
        }
    }
}

#[test]
fn http_retention_still_requires_complete_content_length_or_chunked_framing() {
    for format in [GitObjectFormat::Sha1, GitObjectFormat::Sha256] {
        let (id, _, pack) = blob_pack(format);
        let bytes = wire(format, id, Some(&pack));
        for chunked in [false, true] {
            for cap in [0, 128 * 1024] {
                let incomplete = http_rpc(format, &bytes, chunked, false).with_pack_retention(cap);
                assert!(matches!(
                    incomplete.into_quarantine(&mut || true),
                    Err(RpcError::Http(_))
                ));
                let quarantine = http_rpc(format, &bytes, chunked, true)
                    .with_pack_retention(cap)
                    .into_quarantine(&mut || true)
                    .unwrap();
                let mut handoff = ObserveRetention::default();
                quarantine.handoff(&mut handoff, &mut || true).unwrap();
                assert_eq!(handoff.calls, 1);
                if cap == 0 {
                    assert!(handoff.retained.is_none());
                } else {
                    assert_eq!(handoff.retained.unwrap().bytes(), pack);
                }
            }
        }
    }
}
