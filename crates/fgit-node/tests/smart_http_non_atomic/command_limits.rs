//! Command-bound refusals remain Git service results over both HTTP framings.

use super::*;
use fgit_wire::receive::{ReceiveError, ReceiveLimits};
use fgit_wire::smart_http::rpc::RpcError;

pub(super) fn assert_limit_report(output: &[u8], limit: usize) {
    let boundary = output
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    let head = std::str::from_utf8(&output[..boundary]).unwrap();
    assert!(head.contains("Content-Type: application/x-git-receive-pack-result\r\n"));
    let length = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .unwrap()
        .trim()
        .parse::<usize>()
        .unwrap();
    assert_eq!(length, output.len() - boundary);
    let rows = reports(output);
    assert_eq!(rows.len(), 1);
    let message = std::str::from_utf8(&rows[0]).unwrap();
    assert!(message.starts_with(&format!(
        "ERR receive command count exceeded: observed at least {}; maximum {limit};",
        limit + 1
    )));
    assert!(message.contains(&format!(
        "split the push into batches of at most {limit} commands"
    )));
    assert!(message.ends_with("no ref decision was attempted\n"));
    assert!(output.ends_with(b"0000"));
}

#[test]
fn parser_command_limit_reports_counts_before_admission_with_a_permitted_twin() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for streaming in [false, true] {
            let scratch = Scratch::new();
            let node = start(
                config(&scratch, format).with_git_daemon_receive_limits(ReceiveLimits {
                    max_commands: 2,
                    ..ReceiveLimits::default()
                }),
                false,
            );
            let (oid, zero, pack) = blob_pack(format);
            let commands = [
                (zero, oid, "refs/tags/a"),
                (zero, oid, "refs/tags/b"),
                (zero, oid, "refs/tags/c"),
            ];
            let before = state(&node);
            let mut output = Vec::new();
            let error = perform(
                &node,
                b"parser-over-limit",
                &commands,
                &pack,
                false,
                streaming,
                &mut output,
            )
            .unwrap_err();
            assert!(
                matches!(error, NodeSmartHttpRefusal::Rpc(error) if matches!(*error, RpcError::Receive(ReceiveError::TooManyCommands { limit: 2 })))
            );
            assert_limit_report(&output, 2);
            assert_eq!(state(&node), before);

            let allowed = perform(
                &node,
                b"parser-at-limit",
                &commands[..2],
                &pack,
                false,
                streaming,
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(allowed.commands.len(), 2);
            committed(&allowed, 0);
            committed(&allowed, 1);
            assert_eq!(state(&node).1.len(), 2);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn admission_command_limit_reports_counts_with_a_permitted_atomic_and_non_atomic_twin() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        for atomic in [false, true] {
            let scratch = Scratch::new();
            let node = start(config(&scratch, format), false);
            let (oid, zero, pack) = blob_pack(format);
            let commands = [
                (zero, oid, "refs/tags/a"),
                (zero, oid, "refs/tags/b"),
                (zero, oid, "refs/tags/c"),
            ];
            let limits = AdmissionLimits {
                max_commands: 2,
                ..AdmissionLimits::default()
            };
            let before = state(&node);
            let mut output = Vec::new();
            let error = perform_with_limits(
                &node,
                b"admission-over-limit",
                &commands,
                &pack,
                atomic,
                true,
                limits,
                &mut output,
            )
            .unwrap_err();
            let NodeSmartHttpRefusal::ReceiveInterrupted(error) = error else {
                panic!(
                    "the parser permits this request; session planning applies the narrower bound"
                );
            };
            assert!(error.session().is_none());
            assert!(error.completed_commands().is_empty());
            assert!(matches!(
                error.admission_error(),
                fgit_admission::AdmissionError::CommandLimitExceeded { limit: 2 }
            ));
            assert_limit_report(&output, 2);
            assert_eq!(state(&node), before);

            let allowed = perform_with_limits(
                &node,
                b"admission-at-limit",
                &commands[..2],
                &pack,
                atomic,
                true,
                limits,
                &mut Vec::new(),
            )
            .unwrap();
            assert_eq!(allowed.commands.len(), 2);
            committed(&allowed, 0);
            committed(&allowed, 1);
            assert_eq!(state(&node).1.len(), 2);
            node.shutdown().unwrap();
        }
    }
}

#[test]
fn parser_limit_does_not_drain_an_unbounded_unread_pack_before_replying() {
    struct PrefixOnly(Option<Vec<u8>>);
    impl io::Read for PrefixOnly {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let prefix = self
                .0
                .take()
                .expect("a refused request must not pull more input");
            assert!(buffer.len() >= prefix.len());
            buffer[..prefix.len()].copy_from_slice(&prefix);
            Ok(prefix.len())
        }
    }
    let scratch = Scratch::new();
    let node = start(
        config(&scratch, GitHashAlgorithm::Sha1).with_git_daemon_receive_limits(ReceiveLimits {
            max_commands: 2,
            ..ReceiveLimits::default()
        }),
        false,
    );
    let (oid, zero, _) = blob_pack(GitHashAlgorithm::Sha1);
    let prefix = encode_packets(
        &[
            Packet::Data(
                format!("{zero} {oid} refs/tags/a\0report-status object-format=sha1").into_bytes(),
            ),
            Packet::Data(format!("{zero} {oid} refs/tags/b").into_bytes()),
            Packet::Data(format!("{zero} {oid} refs/tags/c").into_bytes()),
        ],
        &WireLimits::default(),
    )
    .unwrap();
    let route = std::str::from_utf8(node.git_daemon_repository_path().as_bytes()).unwrap();
    let head = format!(
        "POST {route}/git-receive-pack HTTP/1.1\r\nHost: loopback\r\nContent-Type: application/x-git-receive-pack-request\r\nContent-Length: 1000000\r\n\r\n"
    );
    let request = parse_head(head.as_bytes(), HttpLimits::default())
        .unwrap()
        .unwrap();
    let session = LoopbackReceiveSession::authenticated(
        PrincipalId::from_bytes([0xd3; 16]),
        IdempotencyKey::new(b"early-command-limit".to_vec()).unwrap(),
    );
    let before = state(&node);
    let mut output = Vec::new();
    let error = node
        .smart_http_receive_stream_in(
            &request,
            &session,
            &mut PrefixOnly(Some(prefix)),
            HttpLimits::default(),
            AdmissionLimits::default(),
            &mut || true,
            &mut output,
        )
        .unwrap_err();
    assert!(
        matches!(error, NodeSmartHttpRefusal::Rpc(error) if matches!(*error, RpcError::Receive(ReceiveError::TooManyCommands { limit: 2 })))
    );
    assert_limit_report(&output, 2);
    assert_eq!(state(&node), before);
    node.shutdown().unwrap();
}
