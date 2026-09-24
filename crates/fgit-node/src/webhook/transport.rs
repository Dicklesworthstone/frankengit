//! Transport capability checks performed before DNS, signing or socket I/O.
//!
//! The current blocking destination writes to a plain `TcpStream`. A valid
//! HTTPS URL does not make that socket TLS: refuse rather than disclose a
//! signed delivery in cleartext. Replace this guard only when the destination
//! owns a certificate- and hostname-verified TLS transport.

use fgit_forge::webhook::ValidatedWebhookUrl;

pub(super) fn require_plain_http(url: &ValidatedWebhookUrl) -> Result<(), &'static str> {
    match url.scheme() {
        "http" => Ok(()),
        "https" => {
            Err("HTTPS webhook delivery requires verified TLS; plaintext fallback is forbidden")
        }
        _ => Err("unsupported webhook transport scheme"),
    }
}

#[cfg(test)]
mod tests {
    use super::require_plain_http;
    use fgit_forge::webhook::{SsrfPolicy, ValidatedWebhookUrl};

    #[test]
    fn https_never_falls_back_to_plaintext_on_any_port() {
        for raw in [
            "https://example.com/hook",
            "https://example.com:80/hook",
            "https://example.com:8443/hook",
        ] {
            let url = SsrfPolicy::STRICT
                .validate_url(raw)
                .expect("valid HTTPS URL");
            assert!(require_plain_http(&url).is_err(), "{raw}");
        }
    }

    #[test]
    fn plain_http_remains_an_explicit_supported_transport() {
        for raw in ["http://example.com/hook", "http://example.com:8080/hook"] {
            let url = SsrfPolicy::STRICT
                .validate_url(raw)
                .expect("valid HTTP URL");
            assert_eq!(require_plain_http(&url), Ok(()));
        }
    }

    #[test]
    fn unsupported_schemes_fail_closed_even_for_an_unchecked_test_value() {
        let url = ValidatedWebhookUrl::new_unchecked_for_testing(
            "ftp://example.com/hook",
            "ftp",
            "example.com",
            21,
            "/hook",
            None,
        );
        assert!(require_plain_http(&url).is_err());
    }
}
