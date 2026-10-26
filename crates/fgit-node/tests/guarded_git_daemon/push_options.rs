//! Push options through the guarded receiver (frankengit-321s): advertised,
//! parsed within the bounds one sealed request can carry, and bound into the
//! sealed request exactly and in client order. The seal is read back from the
//! reopened authority store and compared with the canonical digest of the
//! request the client meant, never with a value the node reports about itself.

use super::*;
use fgit_authority::{
    AuthorityLimits, ExpectedOld, MAX_PUSH_OPTION_BYTES, MAX_PUSH_OPTIONS, ProposedNew, PushOption,
    RECEIVE_ADMISSION_SCHEMA, RefCommand, SemanticRequest, StoreInstanceId,
    canonical_request_digest, read_seal_async,
};
use fgit_authority_fsqlite::FsqliteAuthorityStore;
use fgit_runtime::{BudgetClass, RuntimeProfile};
use fgit_types::{Digest, TxId};
use fsqlite_types::cx::Cx as FsqliteCx;

/// The node keeps its authority database under its storage root.
const AUTHORITY_DATABASE_FILE: &str = "authority.fsqlite";

fn option_prefix(
    format: GitHashAlgorithm,
    old: GitOid,
    new: GitOid,
    name: &str,
    options: &[Vec<u8>],
) -> Vec<u8> {
    let mut packets = vec![
        Packet::Data(
            format!(
                "{old} {new} {name}\0report-status delete-refs push-options object-format={}",
                format.as_str()
            )
            .into_bytes(),
        ),
        Packet::Flush,
    ];
    packets.extend(options.iter().cloned().map(Packet::Data));
    packets.push(Packet::Flush);
    encode_packets(&packets, &WireLimits::default()).unwrap()
}

fn advertises_push_options(first_ref: &[u8]) -> bool {
    let line = first_ref.strip_suffix(b"\n").unwrap_or(first_ref);
    line.split(|byte| *byte == 0)
        .nth(1)
        .is_some_and(|capabilities| {
            capabilities
                .split(|byte| *byte == b' ')
                .any(|c| c == b"push-options")
        })
}

/// The first advertised record, the node, the server's result and the
/// client's response records of one raw session.
pub type Served = (
    Vec<u8>,
    OneNode,
    Result<Option<AdmissionResult>, NodeSmartHttpRefusal>,
    Vec<Vec<u8>>,
);

/// A refused option list, the parse refusal that names it, the cause the
/// client reads, and its permitted twin, under one label.
type BoundCase = (
    &'static str,
    Vec<Vec<u8>>,
    &'static str,
    &'static str,
    Vec<Vec<u8>>,
);

/// Serves one raw receive session carrying `body`.
pub fn serve(node: OneNode, body: &[u8]) -> Served {
    let (address, route, worker) = launch(node);
    let mut socket = connect(address, &route);
    let advertised = records(&mut socket);
    assert!(!advertised.is_empty() && !advertised[0].starts_with(b"ERR "));
    socket.write_all(body).unwrap();
    let response = records(&mut socket);
    let _ = socket.shutdown(Shutdown::Write);
    let (node, result) = worker.join().unwrap();
    (advertised[0].clone(), node, result, response)
}

/// The canonical digest of the one-command, non-atomic request a stock client
/// sends when it creates `name` at `oid` with these options.
fn expected_digest(
    format: GitHashAlgorithm,
    oid: GitOid,
    name: &str,
    options: &[Vec<u8>],
) -> Digest {
    let request = SemanticRequest::build(
        RECEIVE_ADMISSION_SCHEMA,
        format,
        false,
        vec![RefCommand {
            name: RefName::try_new(name.as_bytes()).unwrap(),
            expected_old: ExpectedOld::Absent,
            proposed_new: ProposedNew::Update(oid),
            force: false,
        }],
        options
            .iter()
            .cloned()
            .map(|option| PushOption::new(option).unwrap())
            .collect(),
        Vec::new(),
    )
    .unwrap();
    canonical_request_digest(&request).unwrap()
}

/// Reads the sealed transaction back from the stopped node's authority store.
fn sealed_digest(root: &Scratch, tx_id: TxId) -> Digest {
    let runtime = RuntimeProfile::production(1).build().unwrap();
    let cx = FsqliteCx::new();
    cx.set_native_cx(runtime.request_cx(BudgetClass::Database));
    let path = root.0.join("node").join(AUTHORITY_DATABASE_FILE);
    let mut store = runtime
        .block_on(FsqliteAuthorityStore::open(
            &cx,
            path.to_str().unwrap().to_owned(),
            StoreInstanceId::from_raw(1),
            AuthorityLimits::default(),
        ))
        .unwrap();
    let seal = runtime
        .block_on(read_seal_async(
            &store,
            &cx,
            TenantId::from_bytes([0xb1; 16]),
            RepositoryId::from_bytes([0xb2; 16]),
            tx_id,
        ))
        .unwrap()
        .expect("a committed push leaves its seal");
    runtime.block_on(store.close(&cx)).unwrap();
    seal.canonical_request_digest
}

#[test]
fn advertised_push_options_are_sealed_exactly_and_in_client_order() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let node = start(root.config(format, true), false);
        let before = state(&node).0;
        let (oid, zero, pack) = pack(format);
        let options = vec![b"ci.skip".to_vec(), b"key=value".to_vec()];
        let body = [
            option_prefix(format, zero, oid, "refs/tags/opt", &options),
            pack,
        ]
        .concat();
        let (advertised, node, result, rows) = serve(node, &body);
        assert!(
            advertises_push_options(&advertised),
            "{}",
            String::from_utf8_lossy(&advertised)
        );
        assert_eq!(
            rows,
            [b"unpack ok\n".to_vec(), b"ok refs/tags/opt\n".to_vec()]
        );
        let result = result.unwrap().unwrap();
        assert!(matches!(
            result.commands[0].terminal.outcome,
            DecisionOutcome::Committed { .. }
        ));
        assert_eq!(state(&node).0, before + 1);
        let tx_id = result.commands[0].tx_id;
        node.shutdown().unwrap();

        let sealed = sealed_digest(&root, tx_id);
        assert_eq!(
            sealed,
            expected_digest(format, oid, "refs/tags/opt", &options)
        );
        // The seal distinguishes the order and the presence of the options, so
        // the equality above is not one every push would satisfy.
        let reversed: Vec<Vec<u8>> = options.iter().rev().cloned().collect();
        assert_ne!(
            sealed,
            expected_digest(format, oid, "refs/tags/opt", &reversed)
        );
        assert_ne!(sealed, expected_digest(format, oid, "refs/tags/opt", &[]));
    }
}

#[test]
fn options_past_the_sealable_bounds_are_refused_while_parsing_and_their_twins_publish() {
    let long = |bytes: usize| vec![vec![b'o'; bytes]];
    let many = |count: usize| {
        (0..count)
            .map(|i| format!("o{i}").into_bytes())
            .collect::<Vec<_>>()
    };
    // The newline is refused by the pkt-line request grammar, one layer below
    // the push-option validator; it is here so that path stays covered too.
    let cases: [BoundCase; 3] = [
        (
            "long",
            long(MAX_PUSH_OPTION_BYTES + 1),
            "InvalidPushOption",
            "a push option is empty, longer than this server accepts, or contains NUL, CR or LF",
            long(MAX_PUSH_OPTION_BYTES),
        ),
        (
            "many",
            many(MAX_PUSH_OPTIONS + 1),
            "TooManyPushOptions",
            "push carries more than 256 push options",
            many(MAX_PUSH_OPTIONS),
        ),
        (
            "newline",
            vec![b"key=two\nlines".to_vec()],
            "MalformedRequestLine",
            "malformed pkt-line request",
            vec![b"key=two lines".to_vec()],
        ),
    ];
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let root = Scratch::new();
        let mut node = start(root.config(format, true), false);
        let (oid, zero, pack) = pack(format);
        for (label, refused, refusal, cause, permitted) in &cases {
            let name = format!("refs/tags/{label}");
            let before = state(&node);
            let body = [
                option_prefix(format, zero, oid, &name, refused),
                pack.clone(),
            ]
            .concat();
            let (_, after, result, rows) = serve(node, &body);
            node = after;
            // The parser refuses the option itself, before any pack byte: an
            // option the seal could not carry never reaches quarantine.
            let error = result.expect_err(label);
            assert!(
                format!("{error:?}").contains(refusal),
                "{label}: expected {refusal}, refused for another reason: {error:?}"
            );
            // The client reads the typed cause, not the generic line
            // (frankengit-yrff).
            assert_eq!(
                rows.last()
                    .map(|row| String::from_utf8_lossy(row).into_owned()),
                Some(format!("ERR {cause}; no ref decision was attempted\n")),
                "{label}"
            );
            assert_eq!(
                state(&node),
                before,
                "{label}: a refused push publishes nothing"
            );

            let body = [
                option_prefix(format, zero, oid, &name, permitted),
                pack.clone(),
            ]
            .concat();
            let (_, after, result, rows) = serve(node, &body);
            node = after;
            assert_eq!(
                rows.last().unwrap(),
                &format!("ok {name}\n").into_bytes(),
                "{label}"
            );
            assert!(matches!(
                result.unwrap().unwrap().commands[0].terminal.outcome,
                DecisionOutcome::Committed { .. }
            ));
        }
        node.shutdown().unwrap();
    }
}
