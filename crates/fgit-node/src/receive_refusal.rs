//! The one client-visible text for a push refused before any ref decision
//! (frankengit-yrff).
//!
//! Every receive transport (git://, SSH, smart HTTP) refuses some pushes before
//! admission starts: a quota, a cell that takes no receive work, a command or
//! push-option bound, a request the grammar rejects. The node knows the typed
//! cause; a client, a CI job or a person can only act on it if it reaches them.
//! This module names a CLOSED set of causes that are safe to describe to the
//! peer that sent the request: they describe the request itself, a bound the
//! operator chose, the cell's service state, or the one class "this node could
//! not durably store the verified objects" (frankengit-vp29), which names no
//! path or OS error. Everything else (other I/O, internal invariants, anything
//! reached after admission started) maps to `None`, and the transport keeps its
//! generic line, so no internal state leaks. Client bytes are never echoed
//! except a ref name the request already carried, bounded and lossily
//! decoded. The command-count bound keeps its own
//! operator text, written by `smart_http::command_limit` (frankengit-p9b5), and
//! is deliberately absent here so each cause has one text.

use fgit_admission::AdmissionError;
use fgit_pack::PackError;
use fgit_types::RefusalCode;
use fgit_wire::WireError;
use fgit_wire::receive::ReceiveError;
use fgit_wire::smart_http::rpc::RpcError;

use crate::smart_http::NodeSmartHttpRefusal;
use crate::{GitDaemonTransportRefusal, NodeGitDaemonServeRefusal, NodeReceiveTransportRefusal};

/// Longest echoed client-supplied ref name, in bytes.
const MAX_ECHOED_REF_BYTES: usize = 256;

/// The cause of a refusal that happened before admission, as the text of one
/// ERR line (without the `ERR ` prefix or the trailing "no ref decision" note),
/// or `None` when only the generic line may be sent.
pub fn client_cause(error: &NodeSmartHttpRefusal) -> Option<String> {
    match error {
        NodeSmartHttpRefusal::Receive(error) => receive_cause(error),
        NodeSmartHttpRefusal::Rpc(error) => match error.as_ref() {
            RpcError::Receive(error) => receive_cause(error),
            RpcError::Wire(error) => Some(wire_cause(error)),
            _ => None,
        },
        NodeSmartHttpRefusal::Wire(error) => Some(wire_cause(error)),
        NodeSmartHttpRefusal::ReceiveTransport(error) => transport_cause(error),
        NodeSmartHttpRefusal::UnauthenticatedReceive => {
            Some("push refused: the receive transport authenticated no principal".to_owned())
        }
        NodeSmartHttpRefusal::RefWriteScopeDenied => {
            Some("push refused: credential does not permit writing every requested reference in this attempt; any prior outcome remains recoverable using the original key".to_owned())
        }
        // git:// and SSH find the pack's end with a bounded scan before the
        // receive machine sees it; its bound refusals are the same envelope.
        NodeSmartHttpRefusal::Serve(serve) => match serve.as_ref() {
            NodeGitDaemonServeRefusal::Transport(transport) => match transport.as_ref() {
                GitDaemonTransportRefusal::ReceivePackFraming(error) => pack_cause(error),
                _ => None,
            },
            _ => None,
        },
        _ => None,
    }
}

/// The subset of [`client_cause`] that smart HTTP answers in a 200
/// receive-pack body, as git-http-backend delivers a fatal error: a
/// well-formed request that a server bound or policy refuses, which a stock
/// client can send and must be told about, while a 4xx/5xx body is discarded
/// by the client. A node that could not durably store the verified objects
/// is told the same way (frankengit-vp29). A request the grammar rejects keeps
/// its 400 (no stock client sends one, and Bad Request is the honest status
/// for it), and the
/// transport-state causes keep their status, which clients act on: 401
/// (credentials), 429 (quota) and 503 (a cell not taking receive work).
pub fn request_cause(error: &NodeSmartHttpRefusal) -> Option<String> {
    if matches!(error, NodeSmartHttpRefusal::RefWriteScopeDenied) {
        return client_cause(error);
    }
    let receive = match error {
        NodeSmartHttpRefusal::Receive(error) => error.as_ref(),
        NodeSmartHttpRefusal::Rpc(rpc) => match rpc.as_ref() {
            RpcError::Receive(error) => error,
            _ => return None,
        },
        // A 5xx body is discarded and the client reports a hang-up followed by
        // "Everything up-to-date"; a storage failure is told in the 200 body,
        // as git-http-backend reports a receive-pack write failure.
        NodeSmartHttpRefusal::ReceiveTransport(transport) => match transport.as_ref() {
            NodeReceiveTransportRefusal::Admission(admission) => match admission.as_ref() {
                AdmissionError::Receive(error) => return storage_cause(error),
                _ => return None,
            },
            _ => return None,
        },
        _ => return None,
    };
    let bound_or_policy = matches!(
        receive,
        ReceiveError::TooManyPushOptions { .. }
            | ReceiveError::InvalidPushOption
            | ReceiveError::QuarantineBytesExceeded { .. }
            | ReceiveError::CertificateTooLarge { .. }
            | ReceiveError::SignedPushUnsupported
            | ReceiveError::SignedPushCapabilityMissing
            | ReceiveError::ObjectFormatMismatch { .. }
            | ReceiveError::AuthoritativeRefusal(
                RefusalCode::ResourceBudgetExceeded | RefusalCode::DeltaBudgetExceeded
            )
    ) || matches!(receive, ReceiveError::Pack(error) if pack_cause(error).is_some());
    if bound_or_policy {
        client_cause(error)
    } else {
        storage_cause(receive)
    }
}

fn transport_cause(error: &NodeReceiveTransportRefusal) -> Option<String> {
    match error {
        NodeReceiveTransportRefusal::QuotaContained { code, expires_secs } => Some(format!(
            "push rate limit exceeded ({code}); retry after {expires_secs}s"
        )),
        NodeReceiveTransportRefusal::Unauthenticated => {
            Some("push refused: the receive transport authenticated no principal".to_owned())
        }
        NodeReceiveTransportRefusal::CellState(refusal) => {
            Some(format!("this server is not accepting pushes: {refusal}"))
        }
        NodeReceiveTransportRefusal::Admission(error) => match error.as_ref() {
            AdmissionError::Receive(error) => storage_cause(error),
            _ => None,
        },
        _ => None,
    }
}

/// Verified objects that this node could not write or sync (a full disk, a
/// descriptor or quota limit, an I/O error) are its own durability failure.
/// The pusher is told so rather than that its objects failed validation; the
/// failure names no path (frankengit-vp29).
fn storage_cause(error: &ReceiveError) -> Option<String> {
    matches!(
        error,
        ReceiveError::AuthoritativeRefusal(RefusalCode::DurabilityProfileUnavailable)
    )
    .then(|| {
        "this server could not durably store the pushed objects \
         (DurabilityProfileUnavailable); retry later"
            .to_owned()
    })
}

fn receive_cause(error: &ReceiveError) -> Option<String> {
    Some(match error {
        ReceiveError::TooManyPushOptions { limit } => {
            format!("push carries more than {limit} push options")
        }
        ReceiveError::InvalidPushOption => {
            "a push option is empty, longer than this server accepts, or contains NUL, CR or LF"
                .to_owned()
        }
        ReceiveError::DuplicateRefCommand { ref_name } => {
            format!("push names ref {} more than once", echoed_ref(ref_name))
        }
        ReceiveError::MalformedCommand { .. } => "malformed ref command line".to_owned(),
        ReceiveError::DeleteRefsNotNegotiated => {
            "a delete command was sent without the delete-refs capability".to_owned()
        }
        ReceiveError::CapabilitiesNotFirstCommand => {
            "capabilities appear after the first ref command".to_owned()
        }
        ReceiveError::MissingCommands => "push carries no ref commands".to_owned(),
        ReceiveError::UnsupportedCapability { .. }
        | ReceiveError::CapabilityNotAdvertised { .. } => {
            "push requests a capability this server did not advertise".to_owned()
        }
        ReceiveError::CapabilityValueRequired { .. }
        | ReceiveError::CapabilityValueForbidden { .. } => {
            "push sends a malformed capability value".to_owned()
        }
        ReceiveError::ObjectFormatMismatch { expected, .. } => {
            format!(
                "push uses another object format; this repository is {}",
                expected.as_str()
            )
        }
        ReceiveError::QuarantineBytesExceeded { limit } => format!(
            "push exceeds this server's receive limit of {limit} bytes (fg serve --receive-max-input-mib)"
        ),
        ReceiveError::SignedPushUnsupported | ReceiveError::SignedPushCapabilityMissing => {
            "signed pushes are not supported by this server".to_owned()
        }
        ReceiveError::CertificateTooLarge { limit } => {
            format!("push certificate exceeds {limit} bytes")
        }
        ReceiveError::MalformedCertificate
        | ReceiveError::CertificateTruncated
        | ReceiveError::CertificateNonceMismatch => "malformed push certificate".to_owned(),
        ReceiveError::Wire(error) => wire_cause(error),
        ReceiveError::Pack(error) => return pack_cause(error),
        ReceiveError::AuthoritativeRefusal(RefusalCode::ResourceBudgetExceeded) => {
            "push exceeds a receive resource limit of this server (pack size, expanded \
             content, object count or work; fg serve --receive-max-input-mib, \
             --receive-max-expanded-mib)"
                .to_owned()
        }
        ReceiveError::AuthoritativeRefusal(RefusalCode::DeltaBudgetExceeded) => {
            "push deltas exceed this server's receive delta limits (depth, fanout or \
             reconstruction work; fg serve --receive-max-expanded-mib raises the work \
             limit) or are malformed"
                .to_owned()
        }
        error => return storage_cause(error),
    })
}

/// A pack that exceeds a receive bound this server's operator chose, named
/// with the flag that raises it (frankengit-88fk). A malformed pack keeps the
/// generic line.
fn pack_cause(error: &PackError) -> Option<String> {
    Some(match error {
        PackError::InputLimit { limit, .. } => format!(
            "push pack exceeds this server's receive limit of {limit} bytes \
             (fg serve --receive-max-input-mib)"
        ),
        PackError::TotalExpandedLimit { limit, .. } => format!(
            "push expands to more than this server's receive limit of {limit} bytes \
             (fg serve --receive-max-expanded-mib)"
        ),
        PackError::DeltaWorkLimit { limit, .. } => format!(
            "push deltas need more reconstruction work than this server's receive limit \
             of {limit} (fg serve --receive-max-expanded-mib)"
        ),
        PackError::EntryCountLimit { limit, .. } => {
            format!("push carries more than {limit} objects, this server's receive limit")
        }
        PackError::ObjectSizeLimit { limit, .. } => format!(
            "push carries an object larger than this server's receive limit of {limit} bytes"
        ),
        PackError::DeltaDepthLimit { limit, .. } => {
            format!("push carries a delta chain deeper than this server's limit of {limit}")
        }
        PackError::DeltaFanoutLimit { limit, .. } => {
            format!("push carries a delta base with more than {limit} deltas, this server's limit")
        }
        _ => return None,
    })
}

/// A request line the pkt-line grammar refused. The line itself is not echoed.
fn wire_cause(_error: &WireError) -> String {
    "malformed pkt-line request".to_owned()
}

fn echoed_ref(name: &[u8]) -> String {
    let bounded = &name[..name.len().min(MAX_ECHOED_REF_BYTES)];
    String::from_utf8_lossy(bounded)
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::cell::{CellRefusal, CellState};

    fn receive(error: ReceiveError) -> NodeSmartHttpRefusal {
        NodeSmartHttpRefusal::Receive(Box::new(error))
    }

    #[test]
    fn each_client_safe_cause_names_itself() {
        let cases = [
            (
                receive(ReceiveError::TooManyPushOptions { limit: 256 }),
                "push carries more than 256 push options",
            ),
            (
                receive(ReceiveError::InvalidPushOption),
                "a push option is empty, longer than this server accepts, or contains NUL, CR or LF",
            ),
            (
                NodeSmartHttpRefusal::Rpc(Box::new(RpcError::Receive(
                    ReceiveError::TooManyPushOptions { limit: 2 },
                ))),
                "push carries more than 2 push options",
            ),
            (
                NodeSmartHttpRefusal::ReceiveTransport(Box::new(
                    NodeReceiveTransportRefusal::QuotaContained {
                        code: "rate_exceeded",
                        expires_secs: 60,
                    },
                )),
                "push rate limit exceeded (rate_exceeded); retry after 60s",
            ),
            (
                receive(ReceiveError::DuplicateRefCommand {
                    ref_name: b"refs/heads/a\x07b".to_vec(),
                }),
                "push names ref refs/heads/a?b more than once",
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(client_cause(&error).as_deref(), Some(expected), "{error:?}");
        }
        let cell = NodeSmartHttpRefusal::ReceiveTransport(Box::new(
            NodeReceiveTransportRefusal::CellState(CellRefusal::StateAdmitsNoStaging {
                state: CellState::Draining,
            }),
        ));
        assert!(
            client_cause(&cell)
                .is_some_and(|text| text.starts_with("this server is not accepting pushes: "))
        );
    }

    /// A node that could not durably store verified objects says so on every
    /// transport, including the 200 body of smart HTTP; an authoritative
    /// verdict on the evidence itself keeps the generic line (frankengit-vp29).
    #[test]
    fn a_storage_failure_is_named_and_an_evidence_verdict_is_not() {
        let storage = ReceiveError::AuthoritativeRefusal(RefusalCode::DurabilityProfileUnavailable);
        let expected = "this server could not durably store the pushed objects \
                        (DurabilityProfileUnavailable); retry later";
        let admission = |error: ReceiveError| {
            NodeSmartHttpRefusal::ReceiveTransport(Box::new(
                NodeReceiveTransportRefusal::Admission(Box::new(AdmissionError::Receive(error))),
            ))
        };
        for error in [receive(storage.clone()), admission(storage)] {
            assert_eq!(client_cause(&error).as_deref(), Some(expected), "{error:?}");
            assert_eq!(
                request_cause(&error).as_deref(),
                Some(expected),
                "{error:?}"
            );
        }
        let verdict = ReceiveError::AuthoritativeRefusal(RefusalCode::EvidenceInvalid);
        for error in [receive(verdict.clone()), admission(verdict)] {
            assert_eq!(client_cause(&error), None, "{error:?}");
            assert_eq!(request_cause(&error), None, "{error:?}");
        }
    }

    /// Every receive envelope bound is named with its operator flag on git://
    /// and SSH (the framing scan) and on smart HTTP's 200 body; a malformed
    /// pack keeps the generic line (frankengit-88fk).
    #[test]
    fn receive_envelope_bounds_name_their_flag_and_a_malformed_pack_does_not() {
        let framing = |error: PackError| {
            NodeSmartHttpRefusal::Serve(Box::new(NodeGitDaemonServeRefusal::Transport(Box::new(
                GitDaemonTransportRefusal::ReceivePackFraming(error),
            ))))
        };
        let expanded = PackError::TotalExpandedLimit {
            actual: 139_288_771,
            limit: 134_217_728,
        };
        let text = "push expands to more than this server's receive limit of 134217728 bytes \
                    (fg serve --receive-max-expanded-mib)";
        assert_eq!(
            client_cause(&framing(expanded.clone())).as_deref(),
            Some(text)
        );
        let http = receive(ReceiveError::Pack(expanded));
        assert_eq!(client_cause(&http).as_deref(), Some(text));
        assert_eq!(request_cause(&http).as_deref(), Some(text));
        let input = receive(ReceiveError::Pack(PackError::InputLimit {
            actual: 2,
            limit: 1,
        }));
        assert!(
            request_cause(&input)
                .is_some_and(|text| text.ends_with("(fg serve --receive-max-input-mib)"))
        );
        let work = receive(ReceiveError::Pack(PackError::DeltaWorkLimit {
            attempted: 2,
            limit: 1,
        }));
        assert!(
            request_cause(&work).is_some_and(|text| text.contains("--receive-max-expanded-mib"))
        );
        for code in [
            RefusalCode::ResourceBudgetExceeded,
            RefusalCode::DeltaBudgetExceeded,
        ] {
            let handoff = receive(ReceiveError::AuthoritativeRefusal(code));
            assert!(
                request_cause(&handoff)
                    .is_some_and(|text| text.contains("--receive-max-expanded-mib"))
            );
        }
        for malformed in [PackError::DeltaCycle, PackError::TrailerChecksumMismatch] {
            assert_eq!(client_cause(&framing(malformed.clone())), None);
            assert_eq!(request_cause(&receive(ReceiveError::Pack(malformed))), None);
        }
    }

    #[test]
    fn the_command_count_bound_is_left_to_its_own_operator_text() {
        // smart_http::command_limit writes it on every transport; a second
        // text here would give one cause two wordings.
        let bound = receive(ReceiveError::TooManyCommands { limit: 4096 });
        assert_eq!(client_cause(&bound), None);
        assert_eq!(request_cause(&bound), None);
    }

    #[test]
    fn internal_failures_and_post_admission_errors_keep_the_generic_line() {
        let internal = [
            receive(ReceiveError::AllocationFailure),
            receive(ReceiveError::HandoffProofMissing),
            receive(ReceiveError::Cancelled),
            NodeSmartHttpRefusal::Io {
                operation: "read guarded receive",
                source: std::io::Error::other("disk"),
            },
            NodeSmartHttpRefusal::UnsupportedOperation,
        ];
        for error in internal {
            assert_eq!(client_cause(&error), None, "{error:?}");
        }
    }

    #[test]
    fn http_keeps_its_status_for_transport_state_causes() {
        let quota = NodeSmartHttpRefusal::ReceiveTransport(Box::new(
            NodeReceiveTransportRefusal::QuotaContained {
                code: "rate_exceeded",
                expires_secs: 60,
            },
        ));
        assert!(client_cause(&quota).is_some());
        assert_eq!(request_cause(&quota), None);
        assert_eq!(
            request_cause(&NodeSmartHttpRefusal::UnauthenticatedReceive),
            None
        );
        let bound = receive(ReceiveError::TooManyPushOptions { limit: 256 });
        assert_eq!(request_cause(&bound), client_cause(&bound));
        // A request the grammar rejects keeps HTTP 400; git:// and SSH, which
        // have no status line, still name it.
        let malformed = NodeSmartHttpRefusal::Rpc(Box::new(RpcError::Receive(
            ReceiveError::MalformedCommand {
                line: b"zz".to_vec(),
            },
        )));
        assert!(client_cause(&malformed).is_some());
        assert_eq!(request_cause(&malformed), None);
    }

    #[test]
    fn an_echoed_ref_name_is_bounded() {
        let long = vec![b'r'; MAX_ECHOED_REF_BYTES * 4];
        let text = client_cause(&receive(ReceiveError::DuplicateRefCommand {
            ref_name: long,
        }))
        .unwrap();
        assert!(text.len() < MAX_ECHOED_REF_BYTES + 64, "{}", text.len());
    }
}
