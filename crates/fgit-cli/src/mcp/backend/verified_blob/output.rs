//! Complete-only canonical proof and byte rendering. No content is returned
//! until the native verifier, all byte limits and cancellation checks succeed.
use super::*;
use fgit_crypto::{DigestHasher, Sha256Hasher};

pub(super) fn render(
    backend: &NodeTools,
    query: &Query,
    envelope: &VerifiedBlobEnvelope,
    live: &dyn Fn() -> bool,
) -> Result<Value, ToolError> {
    checkpoint(live)?;
    if envelope.head().repository_id != backend.options.repository {
        return Err(ToolError::failed("verified_blob_namespace_mismatch"));
    }
    // Reuse the canonical verifier to obtain the exact verified bytes. There
    // is no second unverified source read or separately interpreted Git path.
    let verified = verify_blob_against_head_while(
        query.expected_head,
        &query.reference,
        &query.path,
        envelope,
        live,
    )
    .map_err(proof_refusal)?;
    checkpoint(live)?;
    if verified.source_commit.algorithm() != backend.options.format
        || verified.object_id.algorithm() != backend.options.format
    {
        return Err(ToolError::failed("verified_blob_namespace_mismatch"));
    }
    if verified.bytes.len() > query.max_blob_bytes {
        return Err(ToolError::failed("verified_blob_byte_limit"));
    }
    // The native constructor and codec retain their fixed finite v1 budgets
    // (32 MiB + 128 KiB frame). These narrower MCP bounds are post-construction
    // transport bounds, not a claim that native proof construction costs 256 KiB.
    let proof = encode_verified_blob_envelope(envelope).map_err(proof_refusal)?;
    checkpoint(live)?;
    if proof.len() > MAX_PROOF_BYTES {
        return Err(ToolError::failed("verified_blob_proof_limit"));
    }
    // Both complete byte limits have now passed, before any hex expansion.
    let proof_hex_chunks = chunks(&proof, live)?;
    let bytes_hex_chunks = chunks(verified.bytes, live)?;
    let digest = digest(&proof, live)?;
    checkpoint(live)?;
    let mut fields = backend.header(verified.source_head);
    for (name, value) in [
        ("schema_version", json::number(1)),
        ("type", text("source_verified_blob")),
        ("profile", text(PROFILE)),
        ("proof_format", text(PROOF_FORMAT)),
        ("source_head", text(head_token(verified.source_head))),
        (
            "source_commit",
            text(hex(verified.source_commit.as_bytes())),
        ),
        ("reference_hex", text(hex(query.reference.as_bytes()))),
        ("path_hex", text(hex(&query.path))),
        ("object_id", text(hex(verified.object_id.as_bytes()))),
        ("kind", text(verified.kind.as_str())),
        ("counter_encoding", text("decimal-strings-v1")),
        ("blob_bytes", text(verified.bytes.len().to_string())),
        ("proof_bytes", text(proof.len().to_string())),
        ("chunk_bytes", text(CHUNK_BYTES.to_string())),
        ("bytes_hex_chunks", bytes_hex_chunks),
        ("proof_hex_chunks", proof_hex_chunks),
        ("proof_sha256", text(digest)),
        ("complete", Value::Bool(true)),
        ("content_complete", Value::Bool(true)),
        ("proof_complete", Value::Bool(true)),
        ("server_verification_performed", Value::Bool(true)),
        ("independent_verification_required", Value::Bool(true)),
        ("repository_changed", Value::Bool(false)),
        ("objects_staged", Value::Bool(false)),
        ("transaction_created", Value::Bool(false)),
        ("published", Value::Bool(false)),
        ("approval_granted", Value::Bool(false)),
    ] {
        fields.insert(name.to_owned(), value);
    }
    let result = Value::Object(fields);
    result
        .encode(MAX_RESULT_BYTES)
        .map_err(|_| ToolError::failed("verified_blob_result_limit"))?;
    checkpoint(live)?;
    Ok(result)
}

fn chunks(bytes: &[u8], live: &dyn Fn() -> bool) -> Result<Value, ToolError> {
    let mut result = Vec::with_capacity(bytes.len().div_ceil(CHUNK_BYTES));
    for chunk in bytes.chunks(CHUNK_BYTES) {
        checkpoint(live)?;
        result.push(text(hex(chunk)));
    }
    checkpoint(live)?;
    Ok(Value::Array(result))
}

fn digest(bytes: &[u8], live: &dyn Fn() -> bool) -> Result<String, ToolError> {
    let mut hash = Sha256Hasher::new();
    for chunk in bytes.chunks(64 * 1024) {
        checkpoint(live)?;
        hash.update(chunk);
    }
    checkpoint(live)?;
    Ok(hex(&hash.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn complete_chunks_preserve_binary_and_empty_content() {
        let bytes: Vec<u8> = (0..(CHUNK_BYTES * 2 + 1)).map(|n| n as u8).collect();
        let Value::Array(rows) = chunks(&bytes, &|| true).unwrap() else {
            unreachable!()
        };
        assert_eq!(rows.len(), 3);
        let decoded: Vec<u8> = rows
            .iter()
            .flat_map(|row| unhex(row.text().unwrap(), CHUNK_BYTES).unwrap())
            .collect();
        assert_eq!(decoded, bytes);
        assert_eq!(chunks(&[], &|| true).unwrap(), Value::Array(vec![]));
    }

    #[test]
    fn cancellation_after_a_chunk_refuses_the_entire_result() {
        let checks = Cell::new(0);
        let live = || {
            checks.set(checks.get() + 1);
            checks.get() < 2
        };
        assert_eq!(
            chunks(&vec![0xff; CHUNK_BYTES * 2], &live)
                .unwrap_err()
                .code,
            "verified_blob_cancelled"
        );
        assert_eq!(
            chunks(&[], &|| false).unwrap_err().code,
            "verified_blob_cancelled"
        );
    }

    #[test]
    fn frame_digest_preserves_native_sha256_and_observes_hash_checkpoints() {
        let bytes = vec![0xa5; MAX_PROOF_BYTES];
        assert_eq!(
            digest(&bytes, &|| true).unwrap(),
            hex(&fgit_crypto::sha256_digest(&bytes))
        );
        let checks = Cell::new(0);
        let live = || {
            checks.set(checks.get() + 1);
            checks.get() < 3
        };
        assert_eq!(
            digest(&bytes, &live).unwrap_err().code,
            "verified_blob_cancelled"
        );
        assert_eq!(checks.get(), 3);
    }
}
