//! The one client-visible text for a push refused before any ref decision
//! (frankengit-yrff).
//!
//! Every receive transport (git://, SSH, smart HTTP) refuses some pushes before
//! admission starts: a quota, a cell that takes no receive work, a command or
//! push-option bound, a request the grammar rejects. The node knows the typed
//! cause; a client, a CI job or a person can only act on it if it reaches them.
//! This module names a CLOSED set of causes that are safe to describe to the
//! peer that sent the request: they describe the request itself, a bound the
//! operator chose, or the cell's service state. Everything else (storage, I/O,
//! internal invariants, anything reached after admission started) maps to
//! `None`, and the transport keeps its generic line, so no internal state
//! leaks. Client bytes are never echoed except a ref name the request already
//! carried, bounded and lossily decoded. The command-count bound keeps its own
//! operator text, written by `smart_http::command_limit` (frankengit-p9b5), and
//! is deliberately absent here so each cause has one text.

use fgit_wire::WireError;
use fgit_wire::receive::ReceiveError;
use fgit_wire::smart_http::rpc::RpcError;

use crate::NodeReceiveTransportRefusal;
use crate::smart_http::NodeSmartHttpRefusal;

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
        _ => None,
    }
}

/// The subset of [`client_cause`] that smart HTTP answers in a 200
/// receive-pack body, as git-http-backend delivers a fatal error: a
/// well-formed request that a server bound or policy refuses, which a stock
/// client can send and must be told about, while a 4xx/5xx body is discarded
/// by the client. A request the grammar rejects keeps its 400 (no stock client
/// sends one, and Bad Request is the honest status for it), and the
/// transport-state causes keep their status, which clients act on: 401
/// (credentials), 429 (quota) and 503 (a cell not taking receive work).
pub fn request_cause(error: &NodeSmartHttpRefusal) -> Option<String> {
    let receive = match error {
        NodeSmartHttpRefusal::Receive(error) => error.as_ref(),
        NodeSmartHttpRefusal::Rpc(rpc) => match rpc.as_ref() {
            RpcError::Receive(error) => error,
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
    );
    if bound_or_policy {
        client_cause(error)
    } else {
        None
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
        _ => None,
    }
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
