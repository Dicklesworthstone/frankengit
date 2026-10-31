//! Stream more than the former inventory ceiling through real native identity,
//! original-commitment and complete graph verification. Only bounded metadata
//! and one generated record are retained, never the whole archive or blob set.

use super::*;
use fgit_admission::PermittedObjectClosure;
use fgit_authority_fsqlite::{
    ExportedBody, ExportedHead, ExportedIssuance, IssuanceSequence, SCHEMA_VERSION, mint_token,
};
use fgit_crypto::{git_object_id, git_payload_commitment};
use fgit_types::{CANONICAL_CODEC_VERSION, GitOid, RefName, RepositoryIncarnationId};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Chain, Cursor, Read};

#[derive(Clone, Copy)]
enum Body {
    Blob(u64),
    Tree,
    Commit,
}
impl Body {
    const fn kind(self) -> GitObjectKind {
        match self {
            Self::Blob(_) => GitObjectKind::Blob,
            Self::Tree => GitObjectKind::Tree,
            Self::Commit => GitObjectKind::Commit,
        }
    }
}

struct Inventory {
    identity: Identity,
    authority: Vec<u8>,
    rows: Vec<(GitOid, Body)>,
    selected: BTreeSet<GitOid>,
    refs: BTreeMap<RefName, GitOid>,
    tree: Vec<u8>,
    commit: Vec<u8>,
}
impl Inventory {
    fn new(format: GitHashAlgorithm, objects: usize) -> Self {
        assert!(objects >= 3);
        let mut rows = Vec::with_capacity(objects);
        let mut tree = Vec::new();
        for index in 0..objects - 2 {
            let id = git_object_id(format, GitObjectKind::Blob, &(index as u64).to_be_bytes());
            rows.push((id, Body::Blob(index as u64)));
            tree.extend_from_slice(format!("100644 file-{index:06}\0").as_bytes());
            tree.extend_from_slice(id.as_bytes());
        }
        let tree_id = git_object_id(format, GitObjectKind::Tree, &tree);
        let commit = format!(
            "tree {tree_id}\nauthor Inventory <i@example.invalid> 1 +0000\ncommitter Inventory <i@example.invalid> 1 +0000\n\ncomplete inventory\n"
        )
        .into_bytes();
        let commit_id = git_object_id(format, GitObjectKind::Commit, &commit);
        rows.push((tree_id, Body::Tree));
        rows.push((commit_id, Body::Commit));
        rows.sort_by_key(|row| row.0);
        let selected = rows.iter().map(|row| row.0).collect::<BTreeSet<_>>();
        assert_eq!(selected.len(), objects);

        // Authority rows and Git object counts are distinct budgets. This real
        // canonical closure above 100k IDs fits one existing portable body and
        // its unchanged decoder/frame limits; no codec ceiling is enlarged.
        let closure = PermittedObjectClosure::new(selected.clone());
        let frame = fgit_codec::encode_body(&closure).unwrap();
        let decoded = fgit_codec::decode_body::<PermittedObjectClosure>(
            &frame,
            fgit_codec::DecodeLimits::DEFAULT,
        )
        .unwrap();
        assert_eq!(decoded, closure);
        let token = mint_token(StoreInstanceId::from_raw(41), IssuanceSequence::FIRST)
            .to_opaque_bytes()
            .to_vec();
        let authority = export_bundle(&ExportBundle {
            schema_version: SCHEMA_VERSION,
            instance: 41,
            bodies: vec![ExportedBody {
                key: b"closure".to_vec(),
                body: frame,
            }],
            head: Some(ExportedHead {
                key: b"head".to_vec(),
                token: token.clone(),
                generation: 1,
                body: b"portable stream fixture".to_vec(),
            }),
            issuance: vec![ExportedIssuance {
                token,
                sequence: 1,
                head_key: b"head".to_vec(),
                generation: 1,
                body: b"portable stream fixture".to_vec(),
            }],
        })
        .unwrap();
        Self {
            identity: Identity {
                tenant: TenantId::from_bytes([1; 16]),
                repository: RepositoryId::from_bytes([2; 16]),
                incarnation: RepositoryIncarnationId::from_bytes([3; 16]),
                format,
            },
            authority,
            rows,
            selected,
            refs: BTreeMap::from([(RefName::try_new(b"refs/heads/main").unwrap(), commit_id)]),
            tree,
            commit,
        }
    }

    fn payload(&self, body: Body) -> Cow<'_, [u8]> {
        match body {
            Body::Blob(index) => Cow::Owned(index.to_be_bytes().to_vec()),
            Body::Tree => Cow::Borrowed(&self.tree),
            Body::Commit => Cow::Borrowed(&self.commit),
        }
    }

    fn prefix(&self, declared_objects: u64) -> Vec<u8> {
        let mut bytes = b"FGSRC001".to_vec();
        bytes.extend_from_slice(self.identity.tenant.as_bytes());
        bytes.extend_from_slice(self.identity.repository.as_bytes());
        bytes.extend_from_slice(self.identity.incarnation.as_bytes());
        bytes.push(match self.identity.format {
            GitHashAlgorithm::Sha1 => 1,
            GitHashAlgorithm::Sha256 => 2,
        });
        bytes.extend_from_slice(&(self.authority.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.authority);
        bytes.extend_from_slice(&declared_objects.to_be_bytes());
        bytes
    }

    fn encode(&self, output: &mut impl Write, limits: TransferLimits) -> Result<Seal, String> {
        let mut encoder = StreamEncoder::with_checkpoint(
            output,
            self.identity,
            &self.authority,
            self.rows.len(),
            None,
            limits,
            &mut || Ok(()),
        )?;
        for &(id, kind) in &self.rows {
            let body = self.payload(kind);
            encoder.object_stream(
                id,
                kind.kind(),
                body.len() as u64,
                &commitment(kind.kind(), &body),
                &mut body.as_ref(),
                &mut || Ok(()),
            )?;
        }
        encoder.finish(&mut || Ok(()))
    }
}

fn commitment(kind: GitObjectKind, body: &[u8]) -> [u8; 32] {
    git_payload_commitment(kind, body, CANONICAL_CODEC_VERSION)
        .digest()
        .as_bytes()
        .try_into()
        .unwrap()
}

/// Independent wire source: generate one record header/body at a time, in the
/// same native-ID order. The encoder's digest authenticates this actual stream.
struct GeneratedArchive<'a> {
    inventory: &'a Inventory,
    prefix: Cursor<Vec<u8>>,
    record: Option<Chain<Cursor<Vec<u8>>, Cursor<Cow<'a, [u8]>>>>,
    opened: &'a Cell<usize>,
}
impl<'a> GeneratedArchive<'a> {
    fn new(inventory: &'a Inventory, declared: u64, opened: &'a Cell<usize>) -> Self {
        Self {
            inventory,
            prefix: Cursor::new(inventory.prefix(declared)),
            record: None,
            opened,
        }
    }
}
impl Read for GeneratedArchive<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let count = self.prefix.read(output)?;
        if count != 0 {
            return Ok(count);
        }
        loop {
            if let Some(record) = &mut self.record {
                let count = record.read(output)?;
                if count != 0 {
                    return Ok(count);
                }
                self.record = None;
            }
            let Some(&(id, body)) = self.inventory.rows.get(self.opened.get()) else {
                return Ok(0);
            };
            self.opened.set(self.opened.get() + 1);
            let payload = self.inventory.payload(body);
            let mut header = id.as_bytes().to_vec();
            header.push(match body {
                Body::Commit => 1,
                Body::Tree => 2,
                Body::Blob(_) => 3,
            });
            header.extend_from_slice(&(payload.len() as u64).to_be_bytes());
            header.extend_from_slice(&commitment(body.kind(), &payload));
            self.record = Some(Cursor::new(header).chain(Cursor::new(payload)));
        }
    }
}

#[derive(Default)]
struct CountingSink {
    bytes: u64,
    maximum_write: usize,
}
impl Write for CountingSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes += bytes.len() as u64;
        self.maximum_write = self.maximum_write.max(bytes.len());
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn both_domains_stream_and_audit_100001_native_objects_under_explicit_inventory_budget() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let fixture = Inventory::new(format, 100_001);
        let selected_limits = TransferLimits {
            max_objects: fixture.rows.len(),
            ..Default::default()
        };
        let mut default_sink = CountingSink::default();
        assert!(
            fixture
                .encode(&mut default_sink, TransferLimits::default())
                .unwrap_err()
                .contains("object-count")
        );
        assert_eq!(
            default_sink.bytes, 0,
            "refuse before output or payload work"
        );
        let mut output = CountingSink::default();
        let seal = fixture.encode(&mut output, selected_limits).unwrap();
        assert_eq!(output.bytes, seal.bytes);
        assert!(output.maximum_write <= 64 * 1024);

        let opened = Cell::new(0);
        assert!(
            StreamDecoder::new(
                GeneratedArchive::new(&fixture, fixture.rows.len() as u64, &opened),
                TransferLimits::default(),
                &mut || Ok(()),
            )
            .is_err()
        );
        assert_eq!(opened.get(), 0, "count refusal must precede record work");
        let mut decoder = StreamDecoder::new(
            GeneratedArchive::new(&fixture, fixture.rows.len() as u64, &opened),
            selected_limits,
            &mut || Ok(()),
        )
        .unwrap();
        assert_eq!(decoder.header().objects, fixture.rows.len());
        assert_eq!(decoder.header().authority.bodies.len(), 1);
        assert!(
            ObjectGraphAudit::new(
                &fixture.selected,
                format,
                limits(TransferLimits::default()),
                &mut || true,
            )
            .is_err()
        );
        let mut graph = ObjectGraphAudit::new(
            &fixture.selected,
            format,
            limits(selected_limits),
            &mut || true,
        )
        .unwrap();
        while decoder
            .visit_record(&mut || Ok(()), |header, body| {
                payload::observe(
                    &mut graph,
                    header,
                    body,
                    selected_limits.max_blob_bytes,
                    &mut || true,
                )?;
                Ok(())
            })
            .unwrap()
        {}
        assert_eq!(decoder.finish(seal.digest, &mut || Ok(())).unwrap().1, seal);
        let report = graph.finish(&fixture.refs, &mut || true).unwrap();
        assert_eq!(report.objects, 100_001);
        assert_eq!(report.references, 1);
        assert_eq!(report.local_edges, 100_000);
        assert_eq!(report.external_gitlinks, 0);
        assert_eq!(
            report.payload_bytes,
            ((fixture.rows.len() - 2) * 8 + fixture.tree.len() + fixture.commit.len()) as u64,
        );
        assert_eq!(opened.get(), fixture.rows.len());
    }
}

#[test]
fn declared_inventory_and_its_minimum_framing_refuse_before_any_record_work() {
    let fixture = Inventory::new(GitHashAlgorithm::Sha256, 3);
    let opened = Cell::new(0);
    for count in [4, 1_000_001, u64::MAX] {
        assert!(
            StreamDecoder::new(
                GeneratedArchive::new(&fixture, count, &opened),
                TransferLimits {
                    max_objects: 3,
                    ..Default::default()
                },
                &mut || Ok(()),
            )
            .is_err()
        );
        assert_eq!(opened.get(), 0);
    }
    let minimum_record = (fixture.identity.format.digest_len() + 1 + 8 + 32) as u64;
    let framing = fixture.prefix(3).len() as u64 + 3 * minimum_record;
    let too_small = TransferLimits {
        max_objects: 1_000_000,
        max_archive_bytes: framing - 1,
        ..Default::default()
    };
    assert!(fixture.encode(&mut io::sink(), too_small).is_err());
    assert!(
        StreamDecoder::new(
            GeneratedArchive::new(&fixture, 3, &opened),
            too_small,
            &mut || Ok(()),
        )
        .is_err()
    );
    assert_eq!(opened.get(), 0);
    for max_objects in [0, 1_000_001, usize::MAX] {
        assert!(
            TransferLimits {
                max_objects,
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
    // A higher object allowance changes no bytes and cannot bypass byte limits.
    let ordinary = fixture.encode(&mut io::sink(), Default::default()).unwrap();
    let larger = TransferLimits {
        max_objects: 1_000_000,
        ..Default::default()
    };
    assert_eq!(fixture.encode(&mut io::sink(), larger).unwrap(), ordinary);
    let exact = TransferLimits {
        max_archive_bytes: ordinary.bytes,
        ..larger
    };
    assert_eq!(fixture.encode(&mut io::sink(), exact).unwrap(), ordinary);
    assert!(
        fixture
            .encode(
                &mut io::sink(),
                TransferLimits {
                    max_archive_bytes: ordinary.bytes - 1,
                    ..larger
                },
            )
            .is_err()
    );
}
