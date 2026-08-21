#![forbid(unsafe_code)]
//! Pinned-oracle E2E worker for RFC 1950 interoperability with Git loose objects.
//!
//! The surrounding shell suite creates this manifest only through the pinned
//! upstream-Git oracle. Keeping the parser here lets the test exercise the
//! public codec surface rather than reaching into implementation details.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use fgit_deflate::{
    DeflateLimits, DeflateProfile, InflateLimits, InflateRefusal, Resource, deflate_zlib,
    inflate_zlib,
};

const MANIFEST_ENV: &str = "FGIT_DEFLATE_LOOSE_MANIFEST";
const ARTIFACT_ENV: &str = "FGIT_DEFLATE_DIFFERENTIAL_ARTIFACT_DIR";

#[derive(Debug)]
struct LooseObject {
    label: String,
    object_type: String,
    oid: String,
    body_path: PathBuf,
    compressed_path: PathBuf,
}

fn required_path(name: &str) -> PathBuf {
    env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| panic!("ignored oracle test requires {name}"))
}

fn parse_manifest(path: &Path) -> Vec<LooseObject> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read loose-object manifest {}: {error}", path.display()));
    let mut entries = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t');
        let label = fields
            .next()
            .unwrap_or_else(|| panic!("manifest line {} lacks a label", line_number + 1));
        let object_type = fields
            .next()
            .unwrap_or_else(|| panic!("manifest line {} lacks an object type", line_number + 1));
        let oid = fields
            .next()
            .unwrap_or_else(|| panic!("manifest line {} lacks an object id", line_number + 1));
        let body_path = fields
            .next()
            .unwrap_or_else(|| panic!("manifest line {} lacks a body path", line_number + 1));
        let compressed_path = fields.next().unwrap_or_else(|| {
            panic!(
                "manifest line {} lacks a compressed loose-object path",
                line_number + 1
            )
        });
        assert!(
            fields.next().is_none(),
            "manifest line {} has unexpected fields",
            line_number + 1
        );
        assert!(
            matches!(object_type, "blob" | "tree" | "commit" | "tag"),
            "manifest line {} has an unsupported object type",
            line_number + 1
        );
        assert!(
            oid.len() == 40 && oid.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "manifest line {} has an invalid SHA-1 object id",
            line_number + 1
        );
        assert!(
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "manifest line {} has an unsafe label",
            line_number + 1
        );
        entries.push(LooseObject {
            label: label.to_owned(),
            object_type: object_type.to_owned(),
            oid: oid.to_owned(),
            body_path: PathBuf::from(body_path),
            compressed_path: PathBuf::from(compressed_path),
        });
    }
    assert!(!entries.is_empty(), "oracle loose-object manifest is empty");
    entries
}

fn read_file(path: &Path, description: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("read {description} {}: {error}", path.display()))
}

fn decode_or_panic(compressed: &[u8], label: &str) -> Vec<u8> {
    inflate_zlib(compressed, InflateLimits::GIT_OBJECT)
        .unwrap_or_else(|error| panic!("inflate pinned-oracle loose object {label}: {error}"))
}

#[test]
#[ignore = "requires a verified pinned upstream-Git oracle and its generated loose-object corpus"]
fn pinned_oracle_loose_objects_round_trip_and_refuse_bomb() {
    let manifest_path = required_path(MANIFEST_ENV);
    let artifact_directory = required_path(ARTIFACT_ENV);
    let encoded_directory = artifact_directory.join("encoded");
    fs::create_dir_all(&encoded_directory).unwrap_or_else(|error| {
        panic!(
            "create encoded artifact directory {}: {error}",
            encoded_directory.display()
        )
    });

    let entries = parse_manifest(&manifest_path);
    for entry in &entries {
        let body = read_file(&entry.body_path, "oracle body");
        let compressed = read_file(&entry.compressed_path, "oracle loose object");
        let decoded = decode_or_panic(&compressed, &entry.label);
        let mut expected = format!("{} {}\0", entry.object_type, body.len()).into_bytes();
        expected.extend_from_slice(&body);
        assert_eq!(decoded, expected, "decoded loose object {}", entry.label);

        let reencoded = deflate_zlib(&decoded, DeflateLimits::GIT_OBJECT, DeflateProfile::DEFAULT)
            .unwrap_or_else(|error| panic!("deflate loose object {}: {error}", entry.label));
        assert_eq!(
            decode_or_panic(&reencoded, &entry.label),
            expected,
            "owned encoder round-trips loose object {}",
            entry.label
        );
        fs::write(encoded_directory.join(&entry.oid), reencoded).unwrap_or_else(|error| {
            panic!(
                "write encoded loose object {} for {}: {error}",
                entry.oid, entry.label
            )
        });
    }

    let bomb_input = vec![b'B'; 8 * 1024];
    let bomb_member = deflate_zlib(
        &bomb_input,
        DeflateLimits::GIT_OBJECT,
        DeflateProfile::DEFAULT,
    )
    .unwrap_or_else(|error| panic!("create planted bomb member: {error}"));
    let bomb_limits = InflateLimits {
        max_output_bytes: 1024,
        ..InflateLimits::GIT_OBJECT
    };
    assert!(
        matches!(
            inflate_zlib(&bomb_member, bomb_limits),
            Err(InflateRefusal::ResourceLimit {
                resource: Resource::OutputBytes,
                ..
            })
        ),
        "planted expansion must stop at the output-byte budget"
    );

    let receipt = format!(
        concat!(
            "{{\"schema\":\"frankengit.deflate.loose-object-differential.v1\",",
            "\"oracle_object_count\":{},",
            "\"oracle_pin\":\"git-2.54.0\",",
            "\"encoder_profile\":\"{}\",",
            "\"bomb_refusal\":\"OutputBytes\",",
            "\"non_claim\":\"no zlib bit-compatibility claim\"}}\n"
        ),
        entries.len(),
        DeflateProfile::DEFAULT.id
    );
    fs::write(artifact_directory.join("receipt.ndjson"), receipt)
        .unwrap_or_else(|error| panic!("write differential receipt: {error}"));
}
