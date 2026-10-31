use super::*;
use crate::{GitDaemonTransportRefusal, NodePackMaterializationRefusal};
use fgit_pack::{PackError, PackWriteError};
use fgit_runtime::{BudgetClass, Exhaustion};
use fgit_types::{GitHashAlgorithm, GitOid};
use fgit_wire::smart_http::{HttpLimits, parse_head};
use fgit_wire::{Packet, WireLimits, encode_packets};

fn envelope_refusal() -> NodePackMaterializationRefusal {
    PackWriteError::Pack(PackError::TotalExpandedLimit {
        actual: 8192,
        limit: 4096,
    })
    .into()
}

#[test]
fn only_public_resource_causes_are_exposed_in_git_errors() {
    let direct = line(&NodeSmartHttpRefusal::from(envelope_refusal())).unwrap();
    let nested = line(&NodeSmartHttpRefusal::from(
        NodeGitDaemonServeRefusal::from(envelope_refusal()),
    ))
    .unwrap();
    assert_eq!(direct, nested);
    let text = std::str::from_utf8(&direct).unwrap();
    assert!(text.starts_with("ERR pack needs "));
    assert!(text.contains("--pack-max-expanded-mib"));
    assert!(text.ends_with('\n'));

    for error in [
        PackWriteError::Pack(PackError::ObjectSizeLimit {
            actual: 8192,
            limit: 4096,
        }),
        PackWriteError::OutputLimit {
            attempted: 8192,
            limit: 4096,
        },
        PackWriteError::WindowCacheLimit {
            resident: 8192,
            limit: 4096,
        },
    ] {
        assert!(
            line(&NodeSmartHttpRefusal::from(
                NodePackMaterializationRefusal::from(error)
            ))
            .is_some()
        );
    }
    let hidden = GitOid::from_hex(
        GitHashAlgorithm::Sha1,
        "1234567890123456789012345678901234567890",
    )
    .unwrap();
    for refusal in [
        NodeSmartHttpRefusal::RepositoryRouteMismatch,
        NodePackMaterializationRefusal::RequestedWantOutsideClosure(hidden).into(),
        NodePackMaterializationRefusal::UnsupportedFetch("private implementation detail").into(),
        NodePackMaterializationRefusal::from(PackWriteError::TemporaryReadRefused).into(),
    ] {
        assert!(line(&refusal).is_none());
    }
}

#[test]
fn work_timeout_has_a_bounded_operator_actionable_git_diagnostic() {
    let refusal =
        NodeGitDaemonServeRefusal::from(GitDaemonTransportRefusal::SessionDeadlineExceeded {
            operation: "selected pack materialization",
        });
    let bytes = line(&NodeSmartHttpRefusal::from(refusal)).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    for option in [
        "--session-timeout-secs",
        "--session-secs-per-mib",
        "--session-max-extension-secs",
    ] {
        assert!(text.contains(option));
    }
    assert!(bytes.len() <= 517);
    assert_eq!(bytes.split(|byte| *byte == b'\n').count(), 2);
}

#[test]
fn diagnostic_truncation_preserves_utf8_and_cannot_inject_pkt_lines() {
    let operation = concat!(
        "operation\0\r\n",
        "éééééééééééééééééééééééééééééééééééééééééééééééééé",
        "éééééééééééééééééééééééééééééééééééééééééééééééééé",
        "éééééééééééééééééééééééééééééééééééééééééééééééééé",
        "éééééééééééééééééééééééééééééééééééééééééééééééééé",
        "éééééééééééééééééééééééééééééééééééééééééééééééééé",
        "éééééééééééééééééééééééééééééééééééééééééééééééééé",
    );
    let bytes = line(&NodeSmartHttpRefusal::from(
        NodePackMaterializationRefusal::BudgetClassExhausted {
            class: BudgetClass::Transfer,
            dimension: Exhaustion::PollQuota,
            operation,
        },
    ))
    .unwrap();
    assert!(bytes.len() <= 517);
    assert!(std::str::from_utf8(&bytes).is_ok());
    assert!(bytes.starts_with(b"ERR operation   "));
    assert_eq!(bytes.last(), Some(&b'\n'));
    assert!(
        !bytes[..bytes.len() - 1]
            .iter()
            .any(|byte| matches!(*byte, 0 | b'\r' | b'\n'))
    );
}

#[test]
fn git_error_is_fully_bounded_before_an_http_success_head_is_written() {
    let head = b"POST /repo.git/git-upload-pack HTTP/1.1\r\nHost: local\r\nContent-Type: application/x-git-upload-pack-request\r\nContent-Length: 0\r\n\r\n";
    let request = parse_head(head, HttpLimits::default()).unwrap().unwrap();
    let wire_limits = WireLimits::default();
    let line = line(&NodeSmartHttpRefusal::from(envelope_refusal())).unwrap();
    let expected = encode_packets(&[Packet::Data(line.clone())], &wire_limits).unwrap();
    let mut response = Vec::new();
    assert!(
        super::super::write_upload_rpc_error(
            &mut response,
            &request,
            line.clone(),
            &wire_limits,
            1,
        )
        .is_err()
    );
    assert!(response.is_empty());
    super::super::write_upload_rpc_error(&mut response, &request, line, &wire_limits, 1024)
        .unwrap();
    let split = response
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap();
    let header = std::str::from_utf8(&response[..split]).unwrap();
    assert!(header.starts_with("HTTP/1.1 200 OK"));
    assert!(header.contains("application/x-git-upload-pack-result"));
    let mut body = format!("{:x}\r\n", expected.len()).into_bytes();
    body.extend_from_slice(&expected);
    body.extend_from_slice(b"\r\n0\r\n\r\n");
    assert_eq!(&response[split + 4..], body);
}
