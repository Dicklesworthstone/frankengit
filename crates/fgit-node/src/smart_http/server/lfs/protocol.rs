//! The bounded Git LFS Batch API schema. Unknown semantics fail explicitly;
//! duplicate decoded JSON keys and inexact numeric sizes never reach custody.

use fgit_object_fabric::artifact::storage::lfs::LfsObject;
use fgit_schema::json::{self, Value};
use fgit_types::RefName;

pub(super) const MAX_JSON_BYTES: usize = 64 * 1024;
pub(super) const MAX_BATCH_OBJECTS: usize = 100;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Operation {
    Upload,
    Download,
}

#[derive(Debug)]
pub(super) struct Batch {
    pub operation: Operation,
    pub objects: Vec<LfsObject>,
}

impl Batch {
    pub(super) fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let value = json::parse(bytes)?;
        let fields = value.object().ok_or("invalid_lfs_batch")?;
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "operation" | "transfers" | "ref" | "objects" | "hash_algo"
            )
        }) {
            return Err("unsupported_lfs_batch_field");
        }
        let operation = match fields.get("operation").and_then(Value::text) {
            Some("upload") => Operation::Upload,
            Some("download") => Operation::Download,
            _ => return Err("unsupported_lfs_operation"),
        };
        if let Some(transfers) = fields.get("transfers") {
            let Value::Array(transfers) = transfers else {
                return Err("invalid_lfs_transfers");
            };
            if transfers.is_empty()
                || transfers.len() > 16
                || transfers.iter().any(|entry| entry.text().is_none())
                || !transfers.iter().any(|entry| entry.text() == Some("basic"))
            {
                return Err("unsupported_lfs_transfer");
            }
        }
        if fields
            .get("hash_algo")
            .is_some_and(|value| value.text() != Some("sha256"))
        {
            return Err("unsupported_lfs_hash");
        }
        if let Some(reference) = fields.get("ref") {
            if *reference != Value::Null {
                let reference = reference.object().ok_or("invalid_lfs_ref")?;
                let name = reference
                    .get("name")
                    .and_then(Value::text)
                    .ok_or("invalid_lfs_ref")?;
                if reference.len() != 1 || !name.starts_with("refs/") {
                    return Err("invalid_lfs_ref");
                }
                RefName::try_new(name.as_bytes()).map_err(|_| "invalid_lfs_ref")?;
                // This optional name is context only. It neither authorizes
                // access nor becomes a mutable alias or a retention decision.
            }
        }
        let Some(Value::Array(objects)) = fields.get("objects") else {
            return Err("invalid_lfs_objects");
        };
        if objects.len() > MAX_BATCH_OBJECTS {
            return Err("lfs_batch_object_limit");
        }
        let mut selected = Vec::new();
        selected
            .try_reserve_exact(objects.len())
            .map_err(|_| "lfs_allocation_limit")?;
        for object in objects {
            selected.push(parse_object(object)?);
        }
        Ok(Self {
            operation,
            objects: selected,
        })
    }
}

pub(super) fn verify(bytes: &[u8]) -> Result<LfsObject, &'static str> {
    parse_object(&json::parse(bytes)?)
}

fn parse_object(value: &Value) -> Result<LfsObject, &'static str> {
    let fields = value.object().ok_or("invalid_lfs_object")?;
    if fields.len() != 2 {
        return Err("invalid_lfs_object_fields");
    }
    let oid = fields
        .get("oid")
        .and_then(Value::text)
        .ok_or("invalid_lfs_oid")?;
    let Some(Value::Number(size)) = fields.get("size") else {
        return Err("invalid_lfs_size");
    };
    LfsObject::parse(oid, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object() -> String {
        format!("{{\"oid\":\"{}\",\"size\":0}}", "a".repeat(64))
    }

    #[test]
    fn stock_batch_optional_fields_and_exact_sizes_are_supported() {
        for extra in [
            "",
            ",\"ref\":null",
            ",\"ref\":{\"name\":\"refs/heads/main\"}",
            ",\"transfers\":[\"basic\"],\"hash_algo\":\"sha256\"",
            ",\"transfers\":[\"ssh\",\"basic\"]",
        ] {
            for operation in ["upload", "download"] {
                let body = format!(
                    "{{\"operation\":\"{operation}\",\"objects\":[{}]{extra}}}",
                    object()
                );
                let parsed = Batch::parse(body.as_bytes()).unwrap();
                assert_eq!(parsed.objects.len(), 1);
                assert_eq!(parsed.objects[0].size, 0);
                assert_eq!(
                    parsed.operation,
                    if operation == "upload" {
                        Operation::Upload
                    } else {
                        Operation::Download
                    }
                );
            }
        }
        let greatest = object().replace(":0", ":18446744073709551615");
        assert_eq!(verify(greatest.as_bytes()).unwrap().size, u64::MAX);
    }

    #[test]
    fn schema_ambiguities_unsupported_semantics_and_numeric_coercion_refuse() {
        for extra in [
            ",\"transfers\":[]",
            ",\"transfers\":[\"ssh\"]",
            ",\"transfers\":[\"basic\",null]",
            ",\"hash_algo\":\"sha1\"",
            ",\"hash_algo\":null",
            ",\"ref\":{\"name\":\"main\"}",
            ",\"ref\":{\"name\":\"refs/../secret\"}",
            ",\"ref\":{\"name\":\"refs/heads/main\",\"grant\":true}",
            ",\"operation\":\"download\"",
            ",\"principal\":\"admin\"",
        ] {
            let body = format!(
                "{{\"operation\":\"upload\",\"objects\":[{}]{extra}}}",
                object()
            );
            assert!(Batch::parse(body.as_bytes()).is_err(), "{body}");
        }
        for size in ["-1", "0.0", "1e3", "\"0\"", "18446744073709551616", "null"] {
            assert!(verify(object().replace(":0", &format!(":{size}")).as_bytes()).is_err());
        }
        let duplicate = object().replace("\"size\":0", "\"size\":0,\"s\\u0069ze\":0");
        assert!(verify(duplicate.as_bytes()).is_err());
        let oversized = format!(
            "{{\"operation\":\"upload\",\"objects\":[{}]}}",
            vec![object(); MAX_BATCH_OBJECTS + 1].join(",")
        );
        assert!(Batch::parse(oversized.as_bytes()).is_err());
    }
}
