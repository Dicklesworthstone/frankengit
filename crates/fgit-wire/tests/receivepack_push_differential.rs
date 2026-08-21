#![forbid(unsafe_code)]
//! FG-019c: report-status on a real push, differentially against pinned Git.
//!
//! The bridge half of
//! `scripts/e2e/suites/wire/receivepack_push_differential.sh`. Two `#[ignore]`d
//! phases: one writes the push payloads the suite pipes into the sandboxed
//! oracle, the other compares what Git answered against what our encoder
//! produces for the same verdict.
//!
//! ## Why the payload is built here and not in the suite
//!
//! A receive-pack command line is `<old> SP <new> SP <ref> NUL <caps>`, and
//! **bash `$(…)` silently drops NUL bytes**. Building the payload in shell sent
//! Git a ref literally named `refs/heads/doomedreport-status`, and Git answered
//! with no report-status at all. A lane wired up that way would have compared
//! two empty sections and reported a match. So the bytes are emitted from Rust,
//! where a NUL survives.
//!
//! ## What is compared, and the boundary that is not crossed
//!
//! `report_status` turns a verdict into wire bytes; it does not decide the
//! verdict. Deciding requires the authority stack and the head-bound projection
//! that does not exist yet. So this compares **framing for a verdict Git
//! already reached**: given that Git said this command succeeded, do we frame
//! "succeeded" the way Git frames it?
//!
//! That is a real obligation — `unpack ok`, `ok <ref>`, `ng <ref> <reason>`,
//! their pkt-line lengths and the terminating flush are what every real client
//! parses — and it is deliberately weaker than "we agree with Git about whether
//! the push should succeed". **This file must never be cited for the second
//! claim.** The verdicts come from Git precisely so that no fixture of mine
//! stages the outcome; an earlier corpus on this bead did exactly that and was
//! withdrawn.
//!
//! ## The two cases, and why deletes
//!
//! Deletes are the documented path that carries no pack, so the corpus needs no
//! object closure to be a genuine end-to-end push. Both outcomes are exercised:
//!
//! * an **accepted** delete, where the expected-old matches — Git answers `ok`;
//! * a **refused** delete, where the expected-old is a real object that is not
//!   the ref's current value — Git answers
//!   `ng <ref> incorrect old value provided`.
//!
//! The refusal case was chosen after measuring rather than assuming. Deleting
//! with an *unresolvable* old oid does **not** produce `ng`: Git 2.54.0 reports
//! `warning: allowing deletion of corrupt ref` and answers `ok`. Those are two
//! different behaviours and only the second is an expected-old check, so the
//! corpus uses a resolvable-but-wrong oid to reach the check it means to reach.
//!
//! ## A defect this lane found, and the fix it now guards
//!
//! The `delete_without_negotiated_capability` cell exists because our machine
//! refused a push that Git accepted: a delete whose client did not echo
//! `delete-refs`. That was ruled a **compatibility defect in ours** — the
//! capability is a *server* advertisement telling the client it may send
//! zero-id deletes, not something the client echoes back — and repaired in
//! `fgit-wire` at ee5663e.
//!
//! The cell now requires the two sides to **agree**, and a refusal is a defect.
//! It is kept rather than deleted: once a defect is fixed, the probe that found
//! it is the only thing that would notice it coming back.
//!
//! ## Non-claims
//!
//! * **Framing, not decisions.** See above.
//! * Delete-path only. A push carrying a pack is not exercised here; Git needs
//!   one even when the new object is already present, and building that corpus
//!   is a separate slice.
//! * Agreement with Git 2.54.0 is agreement with one pinned version.
//! * The oracle is sandboxed and pinned; no production path reaches it
//!   (AGENTS.md §3.1).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fgit_git_object::{ObjectType, Sha1, native_object_oid};
use fgit_pack::{
    CanonicalObjectSource, CanonicalPackObject, ObjectFormat, ObjectId, PackLimits, PackPlanner,
    PackWriteError, PackWriteProfile, PackWriter,
};
use fgit_wire::receive::{
    QuarantineReceipt, ReceiveCancellation, ReceiveCommandStatus, ReceiveContext, ReceiveEvent,
    ReceiveLimits, ReceivePack, ReceiveQuarantineHandoff, ReceiveRequest, SignedPushProfile,
    UnpackStatus, report_status,
};
use fgit_wire::{Capabilities, GitObjectFormat, Packet, WireLimits, encode_packets};

const CORPUS_ENV: &str = "FGIT_PUSH_DIFF_CORPUS_DIR";
const OUTPUT_ENV: &str = "FGIT_PUSH_DIFF_OUTPUT_DIR";

const ZERO: &str = "0000000000000000000000000000000000000000";
/// What an ordinary client sends alongside a delete.
const CAPS: &str = "report-status delete-refs";

/// The same push with `delete-refs` omitted.
///
/// Git 2.54.0 accepts this; our machine refuses it as
/// `DeleteRefsNotNegotiated`. That divergence is measured rather than designed
/// around — see the `delete_without_negotiated_capability` cell.
const CAPS_WITHOUT_DELETE_REFS: &str = "report-status";

/// The two cases, named the way the suite names their files.
const ACCEPTED_REF: &str = "refs/heads/accepted";
const REFUSED_REF: &str = "refs/heads/refused";

/// The ref a pack-carrying push creates. It must not already exist.
const CREATED_REF: &str = "refs/heads/created";

// ---------------------------------------------------------------------------
// A real Git object closure, and a pack carrying it
// ---------------------------------------------------------------------------

/// One corpus object with the closure edges the planner walks.
#[derive(Clone)]
struct Object {
    id: ObjectId,
    object_type: ObjectType,
    body: Vec<u8>,
    references: Vec<ObjectId>,
}

fn raw_oid_bytes(id: ObjectId) -> Vec<u8> {
    match id {
        ObjectId::Sha1(oid) => oid.as_bytes().to_vec(),
        ObjectId::Sha256(oid) => oid.as_bytes().to_vec(),
    }
}

fn hex_oid(id: ObjectId) -> String {
    raw_oid_bytes(id)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn blob(content: &[u8]) -> Object {
    let body = content.to_vec();
    Object {
        id: ObjectId::from(native_object_oid::<Sha1>(ObjectType::Blob, &body)),
        object_type: ObjectType::Blob,
        body,
        references: Vec::new(),
    }
}

/// A single-entry tree. Git requires entry ordering; one entry makes the
/// ordering question vacuous, which is deliberate — tree ordering is
/// fg017b's obligation and is not re-litigated here.
fn tree(name: &str, blob_id: ObjectId) -> Object {
    let mut body = Vec::new();
    body.extend_from_slice(b"100644 ");
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    body.extend_from_slice(&raw_oid_bytes(blob_id));
    Object {
        id: ObjectId::from(native_object_oid::<Sha1>(ObjectType::Tree, &body)),
        object_type: ObjectType::Tree,
        body,
        references: vec![blob_id],
    }
}

/// A parentless commit with a fixed timestamp.
///
/// A clock here would make the pack bytes differ between runs, so the identity
/// the suite pushes would change every time and the oracle transcript could
/// never be compared against a stable expectation.
fn commit(tree_id: ObjectId) -> Object {
    let mut body = Vec::new();
    body.extend_from_slice(b"tree ");
    body.extend_from_slice(hex_oid(tree_id).as_bytes());
    body.push(b'\n');
    body.extend_from_slice(
        b"author FrankenGit FG-019c <fg019c@invalid.example> 1700000000 +0000\n",
    );
    body.extend_from_slice(
        b"committer FrankenGit FG-019c <fg019c@invalid.example> 1700000000 +0000\n",
    );
    body.push(b'\n');
    body.extend_from_slice(b"fg019c push differential\n");
    Object {
        id: ObjectId::from(native_object_oid::<Sha1>(ObjectType::Commit, &body)),
        object_type: ObjectType::Commit,
        body,
        references: vec![tree_id],
    }
}

struct ClosureSource {
    objects: Vec<Object>,
}

impl CanonicalObjectSource for ClosureSource {
    fn load(&self, id: &ObjectId) -> Result<CanonicalPackObject, PackWriteError> {
        let (index, object) = self
            .objects
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.id == *id)
            .unwrap_or_else(|| panic!("closure is missing an object it referenced: {id:?}"));
        Ok(CanonicalPackObject::new(
            object.id,
            object.object_type,
            object.body.clone(),
            object.references.clone(),
            u64::try_from(index).unwrap_or(u64::MAX),
            u64::from(raw_oid_bytes(object.id).first().copied().unwrap_or(0)),
        ))
    }
}

/// The commit our push creates, and a pack carrying its full closure.
///
/// Written by `fgit-pack`'s own `PackWriter`, so a Git acceptance here is
/// evidence about **our** pack bytes rather than about a fixture.
fn closure_and_pack() -> (ObjectId, Vec<u8>) {
    let file = blob(b"fg019c\n");
    let root = tree("README", file.id);
    let head = commit(root.id);
    let head_id = head.id;

    let source = ClosureSource {
        objects: vec![file, root, head],
    };
    let planner = PackPlanner::new(
        ObjectFormat::Sha1,
        PackWriteProfile::STORED_V1,
        PackLimits::default(),
    );
    let mut deadline = || true;
    let plan = planner
        .plan(&source, &[head_id], &mut deadline)
        .unwrap_or_else(|error| panic!("planning the push closure failed: {error:?}"));
    assert_eq!(
        plan.entries().len(),
        3,
        "the pushed closure must carry the commit, its tree, and its blob"
    );

    let writer = PackWriter::new(PackLimits::default());
    let mut deadline = || true;
    let (bytes, _receipt) = writer
        .write(&plan, &mut deadline)
        .unwrap_or_else(|error| panic!("writing the push pack failed: {error:?}"));
    (head_id, bytes)
}

// ---------------------------------------------------------------------------
// Phase 1: emit the payloads
// ---------------------------------------------------------------------------

/// One pkt-line carrying a receive command, NUL and all.
fn command_packet(old: &str, new: &str, ref_name: &str, caps: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(old.as_bytes());
    payload.push(b' ');
    payload.extend_from_slice(new.as_bytes());
    payload.push(b' ');
    payload.extend_from_slice(ref_name.as_bytes());
    payload.push(0);
    payload.extend_from_slice(caps.as_bytes());

    let mut packet = format!("{:04x}", payload.len() + 4).into_bytes();
    packet.extend_from_slice(&payload);
    packet
}

/// A complete delete-only push: one command, then flush, and no pack.
fn delete_push_with(old: &str, ref_name: &str, caps: &str) -> Vec<u8> {
    let mut payload = command_packet(old, ZERO, ref_name, caps);
    payload.extend_from_slice(b"0000");
    payload
}

fn delete_push(old: &str, ref_name: &str) -> Vec<u8> {
    delete_push_with(old, ref_name, CAPS)
}

/// Reads `<ref>\t<oid>` lines the suite wrote after building the repository.
fn oracle_oids(corpus: &Path) -> Vec<(String, String)> {
    let raw = fs::read_to_string(corpus.join("oids.tsv"))
        .unwrap_or_else(|error| panic!("the suite must supply oids.tsv: {error}"));
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (name, oid) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("oids.tsv line is not <ref>\\t<oid>: {line:?}"));
            (name.to_owned(), oid.trim().to_owned())
        })
        .collect()
}

fn oid_for(oids: &[(String, String)], name: &str) -> String {
    oids.iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, oid)| oid.clone())
        .unwrap_or_else(|| panic!("the suite did not report an oid for {name}"))
}

/// Writes the two push payloads for the suite to pipe into the oracle.
#[test]
#[ignore = "phase 1 of receivepack_push_differential.sh"]
fn emit_push_payloads_for_the_oracle() {
    let corpus = corpus_dir();
    let oids = oracle_oids(&corpus);

    // Accepted: the expected-old is the ref's actual value.
    let accepted = delete_push(&oid_for(&oids, ACCEPTED_REF), ACCEPTED_REF);
    // Refused: the expected-old is a real, resolvable object that is NOT this
    // ref's value. A non-existent oid would take Git's corrupt-ref path
    // instead and answer `ok`, which would not exercise the check at all.
    let refused = delete_push(&oid_for(&oids, "other-commit"), REFUSED_REF);

    assert!(
        accepted.contains(&0),
        "the accepted payload lost its NUL, so Git would read a fused ref name"
    );
    assert!(
        refused.contains(&0),
        "the refused payload lost its NUL, so Git would read a fused ref name"
    );

    // A third payload, identical to the accepted one except that the client
    // does not negotiate `delete-refs`. Git accepts it; we do not. The suite
    // pipes it so the divergence is measured on both sides rather than
    // asserted from one.
    let unnegotiated = delete_push_with(
        &oid_for(&oids, "unnegotiated-commit"),
        "refs/heads/unnegotiated",
        CAPS_WITHOUT_DELETE_REFS,
    );

    fs::write(corpus.join("push-accepted.pkt"), &accepted).expect("write accepted payload");
    fs::write(corpus.join("push-refused.pkt"), &refused).expect("write refused payload");
    fs::write(corpus.join("push-unnegotiated.pkt"), &unnegotiated)
        .expect("write unnegotiated payload");

    // A create carrying a real pack. Git needs one even when the object is
    // already present, so this is the only shape that exercises the pack path
    // end to end through a push.
    let (head_id, pack) = closure_and_pack();
    let mut created = command_packet(ZERO, &hex_oid(head_id), CREATED_REF, CAPS);
    created.extend_from_slice(b"0000");
    created.extend_from_slice(&pack);
    fs::write(corpus.join("push-created.pkt"), &created).expect("write created payload");
    fs::write(corpus.join("created-oid.txt"), hex_oid(head_id)).expect("write created oid");
}

// ---------------------------------------------------------------------------
// Phase 2: compare
// ---------------------------------------------------------------------------

/// Splits a pkt-line stream into payloads, stopping at the first flush.
///
/// Returns the payloads consumed and the offset just past the flush, so the
/// caller can step over Git's advertisement to reach the report-status that
/// follows it.
fn read_until_flush(bytes: &[u8], mut cursor: usize) -> (Vec<Vec<u8>>, usize) {
    let mut payloads = Vec::new();
    while cursor + 4 <= bytes.len() {
        let header = match std::str::from_utf8(&bytes[cursor..cursor + 4]) {
            Ok(header) => header,
            Err(_) => break,
        };
        let declared = match usize::from_str_radix(header, 16) {
            Ok(declared) => declared,
            Err(_) => break,
        };
        if declared == 0 {
            return (payloads, cursor + 4);
        }
        if declared < 4 || cursor + declared > bytes.len() {
            break;
        }
        payloads.push(bytes[cursor + 4..cursor + declared].to_vec());
        cursor += declared;
    }
    (payloads, cursor)
}

/// Git's report-status section: everything after the advertisement's flush.
fn report_section(response: &[u8]) -> Vec<Vec<u8>> {
    let (_advertisement, after) = read_until_flush(response, 0);
    let (report, _end) = read_until_flush(response, after);
    report
}

/// Parses one receive command through the real wire machine, or reports why
/// the machine refused it.
fn try_request_from(payload: &[u8]) -> Result<ReceiveRequest, String> {
    let context = ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"report-status delete-refs", &WireLimits::default())
            .expect("server capabilities"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("receive context");
    let mut machine = ReceivePack::new(context).expect("machine");

    let (packets, _after) = read_until_flush(payload, 0);
    for packet in packets {
        machine
            .push_packet(Packet::Data(packet))
            .map_err(|error| format!("{error:?}"))?;
    }
    let transition = machine
        .push_packet(Packet::Flush)
        .map_err(|error| format!("{error:?}"))?;
    match transition.events.first() {
        Some(ReceiveEvent::RequestReady(request)) => Ok((**request).clone()),
        other => Err(format!("no request ready: {other:?}")),
    }
}

/// Parses one receive command through the real wire machine.
///
/// The request is built by `ReceivePack` from the very bytes Git was sent, so
/// the ref names our encoder emits are the ones Git parsed, not ones this test
/// retyped.
fn request_from(payload: &[u8]) -> ReceiveRequest {
    let context = ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"report-status delete-refs", &WireLimits::default())
            .expect("server capabilities"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("receive context");
    let mut machine = ReceivePack::new(context).expect("machine");

    let (packets, _after) = read_until_flush(payload, 0);
    for packet in packets {
        machine
            .push_packet(Packet::Data(packet))
            .expect("the payload Git accepted must parse here too");
    }
    let transition = machine.push_packet(Packet::Flush).expect("command flush");
    let Some(ReceiveEvent::RequestReady(request)) = transition.events.first() else {
        panic!("the command flush must expose a parsed request");
    };
    (**request).clone()
}

/// Our report-status bytes for a verdict Git already reached.
fn ours(payload: &[u8], status: ReceiveCommandStatus) -> Vec<Vec<u8>> {
    let request = request_from(payload);
    let packets = report_status(
        &request,
        UnpackStatus::Ok,
        &[status],
        &ReceiveLimits::default(),
    )
    .expect("report-status encodes");
    let bytes = encode_packets(&packets, &WireLimits::default()).expect("report-status packets");
    let (lines, _end) = read_until_flush(&bytes, 0);
    lines
}

/// Counts what the quarantine handed over, so a pack acceptance can be
/// asserted on its contents rather than on a bare `Ok`.
#[derive(Default)]
struct CountingHandoff {
    entries: usize,
    saw_pack: bool,
}

impl ReceiveQuarantineHandoff for CountingHandoff {
    fn handoff(
        &mut self,
        _request: &ReceiveRequest,
        pack: Option<&fgit_pack::QuarantinedPack>,
        _receipt: &QuarantineReceipt,
    ) -> Result<(), fgit_wire::receive::ReceiveError> {
        self.saw_pack = pack.is_some();
        self.entries = pack.map_or(0, |pack| pack.entries().len());
        Ok(())
    }
}

struct NeverCancels;

impl ReceiveCancellation for NeverCancels {
    fn checkpoint(&mut self) -> bool {
        true
    }
}

/// Drives our receive machine over a complete push, pack bytes included.
///
/// Returns how many pack entries reached the quarantine handoff, or the reason
/// our machine refused. This is what turns "Git accepted our pack" into a
/// two-sided statement.
fn drive_full_push(payload: &[u8]) -> Result<usize, String> {
    let context = ReceiveContext::new(
        GitObjectFormat::Sha1,
        Capabilities::parse_v1(b"report-status delete-refs", &WireLimits::default())
            .expect("server capabilities"),
        ReceiveLimits::default(),
        SignedPushProfile::Refuse,
    )
    .expect("receive context");
    let mut machine = ReceivePack::new(context).expect("machine");

    let (packets, after_flush) = read_until_flush(payload, 0);
    for packet in packets {
        machine
            .push_packet(Packet::Data(packet))
            .map_err(|error| format!("command refused: {error:?}"))?;
    }
    machine
        .push_packet(Packet::Flush)
        .map_err(|error| format!("command flush refused: {error:?}"))?;

    // Everything after the command flush is the pack, delivered in chunks the
    // way a client would deliver it.
    for chunk in payload[after_flush..].chunks(64) {
        machine
            .push_bytes(chunk)
            .map_err(|error| format!("pack byte refused: {error:?}"))?;
    }

    let mut handoff = CountingHandoff::default();
    let mut cancellation = NeverCancels;
    machine
        .finish_with_handoff(&mut handoff, &mut cancellation)
        .map_err(|error| format!("handoff refused: {error:?}"))?;
    if !handoff.saw_pack {
        return Err("the handoff received no pack".to_owned());
    }
    Ok(handoff.entries)
}

enum Verdict {
    Match,
    /// A difference that is settled: each side is correct to differ, and no
    /// owner ruling is outstanding.
    AcceptedDivergence(&'static str),
    Defect(String),
}

impl Verdict {
    fn render(&self) -> String {
        match self {
            Self::Match => "match".to_owned(),
            Self::AcceptedDivergence(rationale) => {
                format!("accepted-divergence-with-rationale:{rationale}")
            }
            Self::Defect(detail) => format!("defect:{detail}"),
        }
    }
}

fn show(line: &[u8]) -> String {
    String::from_utf8_lossy(line).trim_end().to_owned()
}

fn compare_lines(oracle: &[u8], ours: &[u8], what: &str) -> Verdict {
    if oracle == ours {
        Verdict::Match
    } else {
        Verdict::Defect(format!(
            "{what}: oracle {:?} vs ours {:?}",
            show(oracle),
            show(ours)
        ))
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(
        env::var(CORPUS_ENV).unwrap_or_else(|_| panic!("{CORPUS_ENV} must name the oracle corpus")),
    )
}

/// Compares Git's report-status with ours, for the verdicts Git reached.
#[test]
#[ignore = "phase 2 of receivepack_push_differential.sh"]
fn our_report_status_frames_what_git_frames() {
    let corpus = corpus_dir();
    let output = PathBuf::from(
        env::var(OUTPUT_ENV)
            .unwrap_or_else(|_| panic!("{OUTPUT_ENV} must name an output directory")),
    );
    fs::create_dir_all(&output).expect("output directory");

    let mut cells: Vec<(&str, Verdict)> = Vec::new();

    let accepted_payload = fs::read(corpus.join("push-accepted.pkt")).expect("accepted payload");
    let refused_payload = fs::read(corpus.join("push-refused.pkt")).expect("refused payload");
    let accepted_response =
        fs::read(corpus.join("oracle-accepted.bin")).expect("oracle accepted response");
    let refused_response =
        fs::read(corpus.join("oracle-refused.bin")).expect("oracle refused response");

    let oracle_accepted = report_section(&accepted_response);
    let oracle_refused = report_section(&refused_response);

    // The load-bearing precondition: Git must actually have answered. A silent
    // empty section is how the shell-built-payload bug hid itself.
    cells.push((
        "oracle_answered_both_pushes",
        if oracle_accepted.len() == 2 && oracle_refused.len() == 2 {
            Verdict::Match
        } else {
            Verdict::Defect(format!(
                "expected two report lines per push, got {} and {}",
                oracle_accepted.len(),
                oracle_refused.len()
            ))
        },
    ));
    // And Git must have reached *different* verdicts, or the corpus is testing
    // one path twice.
    cells.push((
        "oracle_reached_both_verdicts",
        if oracle_accepted.get(1).map(|line| line.starts_with(b"ok ")) == Some(true)
            && oracle_refused.get(1).map(|line| line.starts_with(b"ng ")) == Some(true)
        {
            Verdict::Match
        } else {
            Verdict::Defect(format!(
                "expected one ok and one ng, got {:?} and {:?}",
                oracle_accepted.get(1).map(|line| show(line)),
                oracle_refused.get(1).map(|line| show(line))
            ))
        },
    ));

    if matches!(cells[0].1, Verdict::Defect(_)) || matches!(cells[1].1, Verdict::Defect(_)) {
        write_verdict(&output, &cells);
        panic!("the oracle transcripts are unusable; see verdict.tsv");
    }

    let ours_accepted = ours(&accepted_payload, ReceiveCommandStatus::Ok);
    let ours_refused = ours(
        &refused_payload,
        ReceiveCommandStatus::Rejected {
            // The verdict is Git's; only the wording is ours, and the wording
            // is classified below rather than compared.
            message: b"stale info".to_vec(),
        },
    );
    fs::write(
        &output.join("fgit-accepted.txt"),
        oracle_accepted
            .iter()
            .chain(ours_accepted.iter())
            .map(|line| show(line) + "\n")
            .collect::<String>(),
    )
    .ok();

    cells.push((
        "unpack_line",
        compare_lines(&oracle_accepted[0], &ours_accepted[0], "unpack line"),
    ));
    cells.push((
        "accepted_command_line",
        compare_lines(
            &oracle_accepted[1],
            &ours_accepted[1],
            "accepted command line",
        ),
    ));

    // The refusal: the `ng <ref> ` prefix is protocol and must match; the
    // reason text after it is each server's own and is classified.
    let oracle_ng = &oracle_refused[1];
    let ours_ng = &ours_refused[1];
    let prefix = format!("ng {REFUSED_REF} ").into_bytes();
    cells.push((
        "refused_command_prefix",
        if oracle_ng.starts_with(&prefix) && ours_ng.starts_with(&prefix) {
            Verdict::Match
        } else {
            Verdict::Defect(format!(
                "ng prefix: oracle {:?} vs ours {:?}",
                show(oracle_ng),
                show(ours_ng)
            ))
        },
    ));
    cells.push((
        "refusal_reason_text",
        if oracle_ng == ours_ng {
            Verdict::Defect(
                "our refusal text is byte-identical to Git's, which would mean copying its wording rather than reporting our own"
                    .to_owned(),
            )
        } else {
            Verdict::AcceptedDivergence(
                "reason-text-is-server-specific;Git-says-incorrect-old-value-provided-and-fgit-says-stale-info",
            )
        },
    ));
    cells.push((
        "unpack_line_on_refusal",
        compare_lines(
            &oracle_refused[0],
            &ours_refused[0],
            "unpack line on a refused push",
        ),
    ));

    // ---- the measured divergence ----------------------------------------
    // Both sides observed: Git answers this push, our machine refuses to parse
    // it. Recorded as a divergence rather than accommodated, because widening
    // our parser to match would be a protocol decision its owner should make,
    // and narrowing the corpus to avoid the case would hide it.
    let unnegotiated_payload =
        fs::read(corpus.join("push-unnegotiated.pkt")).expect("unnegotiated payload");
    let unnegotiated_response =
        fs::read(corpus.join("oracle-unnegotiated.bin")).expect("oracle unnegotiated response");
    let oracle_unnegotiated = report_section(&unnegotiated_response);
    let ours_unnegotiated = try_request_from(&unnegotiated_payload);

    // RULED, and the direction reversed. This cell recorded a divergence:
    // Git accepted a delete whose client did not echo `delete-refs`, and our
    // machine refused it as `DeleteRefsNotNegotiated`. ProudJaguar ruled that a
    // **compatibility defect in ours** — the Git protocol-capabilities
    // documentation makes `delete-refs` a SERVER advertisement telling the
    // client it may send zero-id deletes, not something the client echoes back.
    // Repaired in `fgit-wire` at ee5663e, which validates zero-id deletes
    // against the server advertisement.
    //
    // So agreement is now the requirement rather than the surprise, and a
    // refusal is a regression. The cell is deliberately kept — deleting it once
    // the defect was fixed would remove the only thing that would notice it
    // coming back.
    cells.push((
        "delete_without_negotiated_capability",
        match (oracle_unnegotiated.len(), &ours_unnegotiated) {
            (2, Ok(_)) => Verdict::Match,
            (2, Err(reason)) => Verdict::Defect(format!(
                "Git accepted a delete whose client omitted delete-refs and our machine refused it: {reason}. \
                 This is the ee5663e compatibility fix regressing"
            )),
            (count, _) => Verdict::Defect(format!(
                "the oracle did not answer the unnegotiated push: {count} report lines"
            )),
        },
    ));

    // ---- the pack-carrying create ---------------------------------------
    // Deletes prove the no-pack path. This is the only case that carries real
    // objects, and it is the one that says something about interoperability
    // rather than only about framing.
    let created_payload = fs::read(corpus.join("push-created.pkt")).expect("created payload");
    let created_response =
        fs::read(corpus.join("oracle-created.bin")).expect("oracle created response");
    let oracle_created = report_section(&created_response);

    cells.push((
        "git_accepts_a_pack_our_writer_produced",
        match oracle_created.get(1) {
            Some(line) if line.starts_with(b"ok ") => Verdict::Match,
            Some(line) => Verdict::Defect(format!(
                "pinned Git refused a pack fgit-pack wrote: {}",
                show(line)
            )),
            None => Verdict::Defect(
                "the oracle produced no command line for the pack-carrying push".to_owned(),
            ),
        },
    ));

    if oracle_created.len() == 2 {
        let ours_created = ours(&created_payload, ReceiveCommandStatus::Ok);
        cells.push((
            "created_command_line",
            compare_lines(&oracle_created[1], &ours_created[1], "created command line"),
        ));
    } else {
        cells.push((
            "created_command_line",
            Verdict::Defect("the oracle transcript has no created command line".to_owned()),
        ));
    }

    // The two-sided half: our own machine must accept the same bytes Git
    // accepted, pack included, and surface the whole closure.
    cells.push((
        "our_machine_accepts_the_same_push",
        match drive_full_push(&created_payload) {
            Ok(3) => Verdict::Match,
            Ok(count) => Verdict::Defect(format!(
                "our quarantine surfaced {count} pack entries, not the 3 in the pushed closure"
            )),
            Err(reason) => Verdict::Defect(format!(
                "Git accepted this push and our machine refused it: {reason}"
            )),
        },
    ));

    write_verdict(&output, &cells);

    let defects: Vec<&str> = cells
        .iter()
        .filter(|(_, verdict)| matches!(verdict, Verdict::Defect(_)))
        .map(|(name, _)| *name)
        .collect();
    assert!(
        defects.is_empty(),
        "report-status diverges from pinned Git in: {defects:?}"
    );
    assert!(
        cells.len() >= 11,
        "only {} cells were classified",
        cells.len()
    );
}

fn write_verdict(output: &Path, cells: &[(&str, Verdict)]) {
    let mut rendered = String::new();
    for (name, verdict) in cells {
        rendered.push_str(name);
        rendered.push('=');
        rendered.push_str(&verdict.render());
        rendered.push('\n');
    }
    fs::write(output.join("verdict.tsv"), rendered).expect("write verdict");
}

// ---------------------------------------------------------------------------
// Guards that need no oracle
// ---------------------------------------------------------------------------

/// The payload builder emits a NUL, and the wire machine reads the ref name we
/// meant rather than one fused with the capability list.
///
/// This is the bug that made the first shell-built corpus useless, caught here
/// so it cannot come back silently. It needs no oracle and therefore runs on
/// every ordinary `cargo test`.
#[test]
fn a_built_push_payload_keeps_its_capability_nul() {
    let payload = delete_push(
        "9a424f83631ce6caa64d60bf266d58bc8a4ed8a5",
        "refs/heads/doomed",
    );
    assert!(payload.contains(&0), "the payload must carry a NUL");

    let request = request_from(&payload);
    assert_eq!(
        request.commands.len(),
        1,
        "one command line must parse to one command"
    );
    assert_eq!(
        request.commands[0].ref_name, b"refs/heads/doomed",
        "the ref name must not absorb the capability section"
    );
    assert!(
        request.has_capability(b"report-status"),
        "the capabilities after the NUL must be read as capabilities"
    );
}

/// The comparator reports a defect when the two sides disagree.
///
/// Every comparison cell above is expected to report `match`, which is exactly
/// the outcome that needs evidence the comparator can say something else.
#[test]
fn the_comparator_reports_a_defect_on_disagreement() {
    assert!(matches!(
        compare_lines(b"ok refs/heads/a\n", b"ok refs/heads/b\n", "probe"),
        Verdict::Defect(_)
    ));
    assert!(matches!(
        compare_lines(b"ok refs/heads/a\n", b"ok refs/heads/a\n", "probe"),
        Verdict::Match
    ));
}
