//! Golden-corpus export of the cryptographic registry.
//!
//! FG-002c builds an independent verifier over the canonical codec and its
//! identities. That verifier needs the algorithm and domain rows as data, not
//! as Rust it would have to re-parse, so the closed enumerations are exported
//! into checked-in tab-separated rows using the same `franken-registry-v1`
//! shape as `registries/*.tsv`.
//!
//! The exported files are a drift guard, not a second source of truth: the
//! enumerations in [`crate::registry`] remain authoritative, and the corpus
//! test fails when they move without the corpus moving with them.

use crate::registry::{ALGORITHM_REGISTRY, DOMAIN_REGISTRY};

/// Marker line every `FrankenGit` registry-shaped file begins with.
pub const REGISTRY_MARKER: &str = "# franken-registry-v1";

/// Header row of the exported algorithm registry.
pub const ALGORITHM_HEADER: &str = "id\tname\tdigest_bytes\tusage\tstatus";

/// Header row of the exported domain registry.
pub const DOMAIN_HEADER: &str = "id\tdomain_tag\talgorithm\tdurable_object_row\tstatus";

/// Serialise the algorithm registry into golden-corpus rows.
#[must_use]
pub fn export_algorithm_registry() -> String {
    let mut text = String::new();
    text.push_str(REGISTRY_MARKER);
    text.push('\n');
    text.push_str(ALGORITHM_HEADER);
    text.push('\n');
    for row in ALGORITHM_REGISTRY {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            row.registry_id,
            row.name,
            row.digest_len,
            row.usage.token(),
            row.status.token()
        ));
    }
    text
}

/// Serialise the identity-domain registry into golden-corpus rows.
#[must_use]
pub fn export_domain_registry() -> String {
    let mut text = String::new();
    text.push_str(REGISTRY_MARKER);
    text.push('\n');
    text.push_str(DOMAIN_HEADER);
    text.push('\n');
    for row in DOMAIN_REGISTRY {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            row.registry_id,
            row.tag,
            row.algorithm.digest_algorithm().name(),
            row.durable_object_row.unwrap_or("-"),
            row.status.token()
        ));
    }
    text
}
