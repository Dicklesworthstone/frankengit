use super::options::Options;
use crate::publication_support::quote;
use fgit_object_fabric::ArtifactIdentity;
use fgit_types::Digest;
use std::io::Write;

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(super) fn hash(value: &Digest) -> String {
    hex(value.bytes().as_bytes())
}
fn optional(value: Option<&Digest>) -> String {
    value.map_or_else(|| "null".into(), |value| quote(&hash(value)))
}
pub(super) fn receipt(
    options: &Options,
    scope: &Digest,
    identity: &ArtifactIdentity,
    operation: &str,
    disposition: &str,
) -> String {
    format!(
        concat!(
            "{{\"type\":\"artifact_custody_result\",\"schema_version\":1,\"operation\":{},\"disposition\":{},",
            "\"tenant_id\":{},\"repository_id\":{},\"repository_incarnation_id\":{},\"trust_domain\":{},\"scope_sha256\":{},",
            "\"artifact_id\":{},\"payload_sha256\":{},\"payload_bytes\":{},\"media_type\":{},\"kind\":{},",
            "\"build_capsule_sha256\":{},\"check_receipt_sha256\":{},\"source_rcr_sha256\":{},\"retention_canonical_hex\":{},",
            "\"payload_verified\":true,\"trusted_local\":true,\"provenance_authenticated\":false,",
            "\"canonical_repository_published\":false,\"refs_changed\":false,\"retention_enforced\":false}}"
        ),
        quote(operation),
        quote(disposition),
        quote(&hex(options.tenant.as_bytes())),
        quote(&hex(options.repository.as_bytes())),
        quote(&hex(options.incarnation.as_bytes())),
        quote(&options.trust),
        quote(&hash(scope)),
        quote(&hash(identity.artifact_id())),
        quote(&hash(identity.payload_digest())),
        identity.payload_len(),
        quote(identity.media_type().as_str()),
        quote(identity.payload_kind().label()),
        optional(identity.build_capsule_id()),
        optional(identity.check_receipt_id()),
        optional(identity.source_rcr()),
        quote(&hex(&identity.retention_profile().encode_canonical()))
    )
}
pub(super) fn error(err: &mut dyn Write, kind: &str, detail: &str, code: u8) -> u8 {
    let _ = writeln!(err, "{{\"type\":\"artifact_custody_error\",\"schema_version\":1,\"kind\":{},\"detail\":{},\"absence_proven\":false}}", quote(kind), quote(detail))
        .and_then(|()| err.flush());
    code
}
pub(super) fn completed(out: &mut dyn Write, err: &mut dyn Write, receipt: &str) -> u8 {
    match writeln!(out, "{receipt}").and_then(|()| out.flush()) {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(err, "{{\"type\":\"artifact_custody_error\",\"schema_version\":1,\"kind\":\"output_failed\",\"detail\":{},\"retained_result\":{receipt},\"absence_proven\":false}}", quote(&error.to_string())).and_then(|()| err.flush());
            4
        }
    }
}
