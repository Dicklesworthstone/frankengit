#![forbid(unsafe_code)]
//! Actual fg process, persisted authority and a durable keyed filesystem sink.
//! This is receipt inspection evidence, not HTTP settlement or TLS evidence.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use fgit_admission::merge::native::settlement::{DeliveryRequest, OutboxDestination};
use fgit_authority::IdempotencyKey;
use fgit_codec::{CanonicalOutboxDeliveryReceipt, DecodeLimits, OutboxDeliveryDisposition};
use fgit_forge::event::issue::{IssueAction, IssueCommand};
use fgit_forge::{ExpectedVersion, IssueNumber};
use fgit_node::{LoopbackReceiveSession, NodeConfig, OneNode};
use fgit_resource::settlement::{DeliveryVerdict, ProbeVerdict};
use fgit_resource::{DownstreamIdempotency, ReconcilePolicy};
use fgit_types::{
    AsciiSlug, GitHashAlgorithm, HeadGeneration, PrincipalId, RefusalCode, RepositoryId, TenantId,
};

const TENANT: &str = "11111111111111111111111111111111";
const REPOSITORY: &str = "22222222222222222222222222222222";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "fg-receipt-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn config(&self, format: GitHashAlgorithm) -> NodeConfig {
        NodeConfig::new(
            self.0.join("node"),
            TenantId::from_hex(TENANT).unwrap(),
            RepositoryId::from_hex(REPOSITORY).unwrap(),
        )
        .with_object_format(format)
        .with_worker_threads(2)
    }
    fn command(&self, format: GitHashAlgorithm, action: &str, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_fg"))
            .args([
                "webhook",
                action,
                self.0.join("node").to_str().unwrap(),
                TENANT,
                REPOSITORY,
                "--trusted-local",
                "--object-format",
                format.as_str(),
            ])
            .args(extra)
            .output()
            .unwrap()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

// The sink owns a stable key directory, synchronizes bytes before a root-last
// no-replace publication and compares parameters on every duplicate/probe.
// A pending staging name never proves downstream acceptance.
struct DiskSink {
    root: PathBuf,
    audience: AsciiSlug,
    reject: bool,
    calls: usize,
}
impl DiskSink {
    fn frame(&self, request: &DeliveryRequest<'_>) -> Result<Vec<u8>, RefusalCode> {
        if request.destination != self.audience
            || fgit_admission::evidence::evidence_root(request.events)? != request.payload_root
        {
            return Err(RefusalCode::EvidenceInvalid);
        }
        let mut bytes = format!(
            "rejected:{}\n{}\n{}\n{}\n",
            self.reject, request.key, request.destination, request.payload_root
        )
        .into_bytes();
        bytes.extend(
            fgit_codec::encode_body(request.events)
                .map_err(|_| RefusalCode::CanonicalFramingInvalid)?,
        );
        Ok(bytes)
    }
    fn probe_bytes(&self, request: &DeliveryRequest<'_>) -> Result<ProbeVerdict, RefusalCode> {
        let bytes = self.frame(request)?;
        match fs::read(self.root.join(request.key.as_str())) {
            Ok(stored) if stored == bytes => {
                fs::File::open(&self.root)
                    .and_then(|dir| dir.sync_all())
                    .map_err(|_| RefusalCode::EvidenceMissing)?;
                Ok(if self.reject {
                    ProbeVerdict::NotDelivered
                } else {
                    ProbeVerdict::Delivered
                })
            }
            Ok(_) => Err(RefusalCode::EvidenceInvalid),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProbeVerdict::NotDelivered)
            }
            Err(_) => Err(RefusalCode::EvidenceMissing),
        }
    }
    fn publish(&self, request: &DeliveryRequest<'_>) -> Result<DeliveryVerdict, RefusalCode> {
        let bytes = self.frame(request)?;
        let staging = self
            .root
            .join(format!(".pending-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staging)
            .map_err(|_| RefusalCode::EvidenceMissing)?;
        let result = (|| {
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|_| RefusalCode::EvidenceMissing)?;
            drop(file);
            match fs::hard_link(&staging, self.root.join(request.key.as_str())) {
                Ok(()) => Ok(if self.reject {
                    DeliveryVerdict::PermanentRejection
                } else {
                    DeliveryVerdict::Accepted
                }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stored = fs::read(self.root.join(request.key.as_str()))
                        .map_err(|_| RefusalCode::EvidenceMissing)?;
                    if stored != bytes {
                        return Err(RefusalCode::EvidenceInvalid);
                    }
                    Ok(if self.reject {
                        DeliveryVerdict::PermanentRejection
                    } else {
                        DeliveryVerdict::DuplicateSuppressed
                    })
                }
                Err(_) => Err(RefusalCode::EvidenceMissing),
            }
        })();
        fs::remove_file(staging).map_err(|_| RefusalCode::EvidenceMissing)?;
        fs::File::open(&self.root)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| RefusalCode::EvidenceMissing)?;
        result
    }
}
impl<C: Sync + ?Sized> OutboxDestination<C> for DiskSink {
    fn destination(&self) -> AsciiSlug {
        self.audience
    }
    fn idempotency(&self) -> DownstreamIdempotency {
        DownstreamIdempotency::Strong
    }
    async fn probe<'a>(
        &'a mut self,
        _cx: &'a C,
        request: &'a DeliveryRequest<'_>,
    ) -> Result<(ProbeVerdict, Vec<u8>), RefusalCode> {
        let verdict = self.probe_bytes(request)?;
        Ok((
            verdict,
            if verdict == ProbeVerdict::Delivered {
                b"durable keyed sink".to_vec()
            } else {
                Vec::new()
            },
        ))
    }
    async fn deliver<'a>(
        &'a mut self,
        _cx: &'a C,
        request: &'a DeliveryRequest<'_>,
        _attempt: u32,
    ) -> Result<(DeliveryVerdict, Vec<u8>), RefusalCode> {
        self.calls += 1;
        Ok((
            self.publish(request)?,
            b"durable keyed sink decision".to_vec(),
        ))
    }
}

fn success(output: Output) -> String {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn refused(output: Output) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}
fn field<'a>(json: &'a str, name: &str) -> &'a str {
    json.split_once(&format!("\"{name}\":\""))
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}

#[test]
fn fg_recovers_original_retired_receipts_in_both_formats_without_resending() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for reject in [false, true] {
            let scratch = Scratch::new();
            let (mut node, _) = OneNode::init(scratch.config(format)).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let request = node.request_context();
            let session = LoopbackReceiveSession::authenticated(
                PrincipalId::from_bytes([3; 16]),
                IdempotencyKey::new(b"receipt-issue".to_vec()).unwrap(),
            );
            let command = IssueCommand {
                number: IssueNumber::try_new(1).unwrap(),
                expected_version: ExpectedVersion::NewStream,
                action: IssueAction::Open {
                    title: "Receipt survives retirement".into(),
                    body: "real committed event".into(),
                    labels: vec![],
                },
            };
            node.runtime()
                .block_on(node.admit_issue_durable_in(
                    &request,
                    &session,
                    &command,
                    Default::default(),
                ))
                .unwrap();
            let page = node
                .runtime()
                .block_on(node.read_forge_outbox_snapshot_in(&request, 100, None))
                .unwrap();
            assert_eq!(page.entries.len(), 1);
            let key = page.entries[0].delivery_key();
            let audience = page.entries[0].destination();
            node.shutdown().unwrap();
            let active_page = success(scratch.command(format, "outbox", &[]));
            let parameters = [
                "--delivery-id",
                key.as_str(),
                "--destination",
                audience.as_str(),
            ];
            refused(scratch.command(format, "receipt", &parameters));

            let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let receiver_root = scratch.0.join("receiver");
            fs::create_dir(&receiver_root).unwrap();
            fs::File::open(&scratch.0).unwrap().sync_all().unwrap();
            let mut sink = DiskSink {
                root: receiver_root,
                audience,
                reject,
                calls: 0,
            };
            let request = node.outbox_delivery_context();
            let effect = node
                .runtime()
                .block_on(node.deliver_forge_outbox_in(
                    &request,
                    &session,
                    key,
                    &mut sink,
                    ReconcilePolicy::new(std::num::NonZeroU32::new(4).unwrap()),
                    Default::default(),
                ))
                .unwrap();
            let expected = node
                .runtime()
                .block_on(node.read_retired_forge_receipt_in(&request, key, audience, None))
                .unwrap();
            let terminal_head = expected.source_head();
            let original_receipt = expected.receipt().clone();
            assert_eq!(
                Some(original_receipt.root().unwrap()),
                effect.evidence_root()
            );
            node.shutdown().unwrap();

            let report = success(scratch.command(format, "receipt", &parameters));
            assert_eq!(report.lines().count(), 1);
            assert_eq!(field(&report, "type"), "forge_delivery_receipt");
            assert_eq!(field(&report, "source_head"), terminal_head.to_string());
            assert_eq!(field(&report, "delivery_id"), key.as_str());
            assert_eq!(field(&report, "destination"), audience.as_str());
            assert_eq!(
                field(&report, "receipt_root"),
                original_receipt.root().unwrap().to_string()
            );
            assert_eq!(
                field(&report, "disposition"),
                if reject {
                    "terminally_refused"
                } else {
                    "acknowledged"
                }
            );
            let hex = field(&report, "canonical_frame_hex");
            assert_eq!(hex.len() % 2, 0);
            let frame: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            let decoded: CanonicalOutboxDeliveryReceipt =
                fgit_codec::decode_body(&frame, DecodeLimits::DEFAULT).unwrap();
            assert_eq!(decoded, original_receipt);
            assert_eq!(
                decoded.disposition(),
                if reject {
                    OutboxDeliveryDisposition::TerminallyRefused
                } else {
                    OutboxDeliveryDisposition::Acknowledged
                }
            );
            for property in [
                "\"retired\":true",
                "\"canonical_settled\":true",
                "\"sent\":false",
                "\"node_closed\":true",
            ] {
                assert!(report.contains(property));
            }
            let mut pinned = parameters.to_vec();
            pinned.extend(["--expected-head", field(&report, "snapshot_token")]);
            assert_eq!(success(scratch.command(format, "receipt", &pinned)), report);
            let mut stale = parameters.to_vec();
            stale.extend(["--expected-head", field(&active_page, "snapshot_token")]);
            refused(scratch.command(format, "receipt", &stale));
            refused(scratch.command(
                format,
                "receipt",
                &[
                    "--delivery-id",
                    key.as_str(),
                    "--destination",
                    "wrong-audience",
                ],
            ));
            refused(scratch.command(
                format,
                "receipt",
                &[
                    "--delivery-id",
                    "not-a-delivery",
                    "--destination",
                    audience.as_str(),
                ],
            ));
            refused(scratch.command(format, "inspect", &parameters));

            let mut node = OneNode::open_existing(scratch.config(format)).unwrap();
            node.bring_into_service(HeadGeneration::FIRST).unwrap();
            let request = node.request_context();
            let after = node
                .runtime()
                .block_on(node.read_forge_outbox_snapshot_in(&request, 100, None))
                .unwrap();
            assert_eq!(after.source_head, terminal_head);
            assert!(after.entries.is_empty());
            assert_eq!(sink.calls, 1);
            assert_eq!(fs::read_dir(&sink.root).unwrap().count(), 1);
            node.shutdown().unwrap();
        }
    }
}
