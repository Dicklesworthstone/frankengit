//! Derived, sanitized Markdown rendering for canonical issue text.
//!
//! The raw body stays canonical and is always returned unchanged. When a
//! reader asks for `render=html_safe`, each Markdown-bearing body also carries
//! a `body_rendered` object produced by `fgit-doc` (`RenderProfile::HtmlSafe`):
//! raw markup is escaped rather than passed through, link destinations are
//! policy-checked at parse time, and the output is a pure function of the
//! source bytes and the profile. The object is keyed by the source SHA-256 and
//! the parse-profile SHA-256, so a renderer profile bump changes the key. A
//! renderer ceiling is reported as a typed refusal inside the object; it never
//! fails the canonical read.
use fgit_crypto::sha256_digest;
use fgit_doc::{Limits, ParseProfile, RenderProfile, parse_with, render};

use super::output::quote;

impl crate::OneNode {
    /// Render already-selected Markdown with the same source-bound document
    /// presentation used by native HTTP reads. This pure adapter performs no
    /// repository lookup and grants no read, execution, review or merge right.
    /// A caller must authorize and select the raw source before calling it.
    ///
    /// Supported profiles are `html_safe`, `plain_text`, `compact_machine` and
    /// `api_json`. HTML retains the native `html` field; the other profiles use
    /// `content` (the API tree is JSON text with byte/codepoint spans). All
    /// profiles bind the original source and the same parse-profile SHA-256.
    /// The returned JSON is a presentation, not a canonical event or proof of
    /// authorization. Rendered text remains untrusted repository content.
    ///
    /// The output ceiling bounds unescaped renderer bytes, not JSON framing;
    /// the caller must additionally enforce its complete response envelope.
    /// Parser/output refusals are returned inside the presentation, allowing
    /// the caller to retain its unchanged canonical body. Unknown profiles and
    /// input beyond the parser's source envelope are rejected before parsing.
    pub fn render_markdown_presentation(
        source: &str,
        profile: &str,
        maximum_output_bytes: u32,
    ) -> Result<String, &'static str> {
        let profile = match profile {
            "html_safe" => RenderProfile::HtmlSafe,
            "plain_text" => RenderProfile::PlainText,
            "compact_machine" => RenderProfile::CompactMachine,
            "api_json" => RenderProfile::ApiJson,
            _ => return Err("unsupported_rendering"),
        };
        if source.len() > Limits::DEFAULT.max_input_bytes as usize {
            return Err("document_source_limit");
        }
        Ok(presentation(source, profile, maximum_output_bytes))
    }
}

/// The historical HTTP shape and default output envelope remain unchanged.
pub(super) fn body(source: &str) -> String {
    presentation(source, RenderProfile::HtmlSafe, Limits::DEFAULT.max_output_bytes)
}

fn presentation(source: &str, surface: RenderProfile, maximum_output_bytes: u32) -> String {
    let profile = ParseProfile::DEFAULT;
    let field = if surface == RenderProfile::HtmlSafe { "html" } else { "content" };
    let key = format!(
        "\"renderer\":\"fgit-doc\",\"profile\":{},\"parse_profile_sha256\":{},\"source_sha256\":{}",
        quote(surface.tag()),
        quote(&hex(&sha256_digest(&profile.id().canonical_bytes()))),
        quote(&hex(&sha256_digest(source.as_bytes())))
    );
    let limits = Limits {
        max_output_bytes: maximum_output_bytes.min(Limits::DEFAULT.max_output_bytes),
        ..Limits::DEFAULT
    };
    match parse_with(source, profile)
        .and_then(|parsed| render(parsed.document(), surface, limits))
    {
        Ok(output) => format!("{{{key},\"{field}\":{}}}", quote(output.as_str())),
        Err(refusal) => format!(
            "{{{key},\"{field}\":null,\"refusal\":{}}}",
            quote(refusal.kind().tag())
        ),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|byte| {
            [
                DIGITS[usize::from(byte >> 4)],
                DIGITS[usize::from(byte & 15)],
            ]
        })
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rendered HTML, unescaped from its JSON string.
    fn html(source: &str) -> String {
        let rendered = body(source);
        let start = rendered.find("\"html\":\"").expect("rendered html") + 8;
        rendered[start..rendered.rfind("\"}").expect("closed object")]
            .replace("\\u000a", "\n")
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    }

    /// Active content in REAL markup only: escaped text (`&lt;...`) cannot
    /// open a tag, so each `<...>` here is an element the browser would build.
    fn active_content(html: &str) -> Option<String> {
        let mut rest = html;
        while let Some(open) = rest.find('<') {
            let close = rest[open..].find('>').map_or(rest.len(), |at| open + at);
            let tag = rest[open + 1..close].to_ascii_lowercase();
            let name = tag
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or("");
            if ["script", "svg", "img", "iframe", "object", "embed", "style"].contains(&name) {
                return Some(format!("element <{name}>"));
            }
            for attribute in tag.split_whitespace().skip(1) {
                let (key, value) = attribute.split_once('=').unwrap_or((attribute, ""));
                let value = value.trim_matches('"');
                if key.starts_with("on") {
                    return Some(format!("event handler {key}"));
                }
                if matches!(key, "href" | "src")
                    && (value.starts_with("javascript:") || value.starts_with("data:"))
                {
                    return Some(format!("{key}={value}"));
                }
            }
            rest = &rest[close.min(rest.len())..];
            if rest.starts_with('>') {
                rest = &rest[1..];
            }
        }
        None
    }

    #[test]
    fn the_active_content_inspector_catches_planted_violations() {
        for planted in [
            "<p><script>x</script></p>",
            "<p onclick=\"x\">y</p>",
            "<a href=\"javascript:x\">y</a>",
            "<img src=\"data:image/png,x\">",
            "<svg></svg>",
        ] {
            assert!(active_content(planted).is_some(), "{planted}");
        }
        assert_eq!(
            active_content("<pre><code>&lt;script onerror=x&gt;</code></pre>"),
            None
        );
    }

    #[test]
    fn hostile_inputs_render_inert_and_their_benign_twins_keep_structure() {
        // Each hostile case sits next to a near-identical benign twin, so an
        // over-eager filter that strips everything cannot pass.
        for (hostile, benign, structure) in [
            (
                "<script>alert(1)</script>",
                "*alert(1)*",
                "<em>alert(1)</em>",
            ),
            (
                "[x](javascript:alert(1))",
                "[x](https://example.invalid/)",
                "href=\"https://example.invalid/\"",
            ),
            (
                "<img src=x onerror=alert(1)>",
                "**img**",
                "<strong>img</strong>",
            ),
            (
                "<svg><script>alert(1)</script></svg>",
                "`svg`",
                "<code>svg</code>",
            ),
            (
                "[x](data:text/html,<script>alert(1)</script>)",
                "[x](https://example.invalid/data)",
                "href=\"https://example.invalid/data\"",
            ),
        ] {
            let rendered = html(hostile);
            assert_eq!(
                active_content(&rendered),
                None,
                "{hostile:?} rendered active content: {rendered}"
            );
            assert!(
                html(benign).contains(structure),
                "{benign:?} lost its structure: {}",
                html(benign)
            );
        }
    }

    #[test]
    fn rendering_is_deterministic_and_keyed_by_source_and_profile() {
        let source = "# Title\n\nSome *text* and a [link](https://example.invalid/).\n";
        assert_eq!(body(source), body(source));
        assert!(body(source).contains(&format!(
            "\"source_sha256\":\"{}\"",
            hex(&sha256_digest(source.as_bytes()))
        )));
        assert_ne!(body(source), body("# Title\n"));
        assert!(body(source).contains("\"profile\":\"html_safe\""));
    }

    #[test]
    fn a_renderer_ceiling_is_a_typed_refusal_not_a_failed_read() {
        let deep = ">".repeat(10_000);
        let rendered = body(&deep);
        assert!(rendered.contains("\"html\":null"), "{rendered}");
        assert!(rendered.contains("\"refusal\":"), "{rendered}");
    }
}

#[cfg(test)]
mod shared_profile_tests {
    use super::*;
    use crate::OneNode;

    #[test]
    fn the_public_html_profile_preserves_the_existing_http_representation() {
        for source in ["", "# Header\n\n**Body**", "<script>x</script>", "é 🦀\n", "[x](javascript:x)"] {
            assert_eq!(OneNode::render_markdown_presentation(source, "html_safe", Limits::DEFAULT.max_output_bytes).unwrap(), body(source));
        }
    }

    #[test]
    fn every_surface_is_the_real_document_renderer_with_the_same_source_binding() {
        let source = "# Unicode 🦀\n\nSome **text**.\n";
        let parsed = parse_with(source, ParseProfile::DEFAULT).unwrap();
        for profile in RenderProfile::all() {
            let expected = render(parsed.document(), profile, Limits::DEFAULT).unwrap();
            let result = OneNode::render_markdown_presentation(source, profile.tag(), Limits::DEFAULT.max_output_bytes).unwrap();
            let field = if profile == RenderProfile::HtmlSafe { "html" } else { "content" };
            assert!(result.contains(&format!("\"{field}\":{}", quote(expected.as_str()))));
            assert!(result.contains(&format!("\"source_sha256\":\"{}\"", hex(&sha256_digest(source.as_bytes())))));
        }
    }

    #[test]
    fn unsupported_profiles_and_output_exhaustion_do_not_fabricate_a_document() {
        assert_eq!(OneNode::render_markdown_presentation("text", "shell", 1024), Err("unsupported_rendering"));
        for profile in RenderProfile::all() {
            let refused = OneNode::render_markdown_presentation("some text", profile.tag(), 0).unwrap();
            assert!(refused.contains("\"refusal\":"));
            let permitted = OneNode::render_markdown_presentation("some text", profile.tag(), 4096).unwrap();
            assert!(!permitted.contains("\"refusal\":"));
        }
    }

    #[test]
    fn the_public_source_envelope_is_enforced_before_parsing() {
        let oversized = "x".repeat(Limits::DEFAULT.max_input_bytes as usize + 1);
        assert_eq!(OneNode::render_markdown_presentation(&oversized, "plain_text", 1024), Err("document_source_limit"));
    }
}
