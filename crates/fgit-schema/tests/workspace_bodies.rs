//! End-to-end refusal coverage for workspace canonical-body manifests.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn detached_probe_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "fgit-schema-body-probe-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("unnamed")
    ))
}

#[test]
fn check_refuses_a_literal_family_without_an_owning_description() {
    let root = detached_probe_root();
    let crate_root = root.join("crates/fgit-probe");
    fs::create_dir_all(crate_root.join("src")).expect("create detached probe crate");
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers = [\"crates/fgit-probe\"]\nresolver = \"3\"\n",
    )
    .expect("write detached workspace manifest");
    fs::write(
        crate_root.join("Cargo.toml"),
        "[package]\nname = \"fgit-probe\"\nversion = \"0.0.0\"\nedition = \"2024\"\n",
    )
    .expect("write detached probe package manifest");
    fs::write(
        crate_root.join("src/lib.rs"),
        "impl CanonicalBody for Probe {\n    const SCHEMA_FAMILY: SchemaFamily = SchemaFamily::from_static(\"probe-undescribed\");\n    fn write_payload(&self) {}\n}\n",
    )
    .expect("write undocumented probe body");

    let output = Command::new(env!("CARGO_BIN_EXE_fgit-schema-gen"))
        .arg("check")
        .arg("--workspace-root")
        .arg(&root)
        .output()
        .expect("run schema check against detached probe");
    let _ = fs::remove_dir_all(&root);

    assert!(
        !output.status.success(),
        "the schema check accepted a detached canonical-body family without a description"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("probe-undescribed"),
        "the refusal must name the missing family: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
