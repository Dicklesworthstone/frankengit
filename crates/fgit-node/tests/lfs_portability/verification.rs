use super::*;
use std::io::{Seek, SeekFrom, Write};

fn files_below(root: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            paths.extend(files_below(&path));
        } else {
            paths.push(path);
        }
    }
    paths.sort();
    paths
}

#[test]
fn verification_requires_real_payload_custody_and_detects_corruption_without_writes() {
    let scratch = Scratch::new();
    let root = scratch.0.join("node");
    let custody_root = scratch.private("lfs");
    let payload = b"the complete referenced binary payload\0\xff";
    let expected = object(payload);
    let node = init(
        &root,
        GitHashAlgorithm::Sha1,
        &[("asset", expected.pointer())],
    );
    let incarnation = node.repository_incarnation_id();
    node.shutdown().unwrap();
    let command = verify_args(&root, &custody_root, GitHashAlgorithm::Sha1);
    let pins = invoke(&args("inventory", &root, GitHashAlgorithm::Sha1)).unwrap();

    // Inventory alone can succeed while a clone cannot hydrate its payload.
    let error = refused_without_put(invoke(&command));
    assert!(error.contains("LFS custody missing"), "{error}");
    assert!(error.contains(&expected.oid.to_string()), "{error}");
    assert_eq!(fs::read_dir(&custody_root).unwrap().count(), 0);

    // Exact bytes under a different incarnation still cannot satisfy this node.
    let wrong = RepositoryIncarnationId::from_bytes([0xc7; 16]);
    assert_ne!(wrong, incarnation);
    put(&custody(&custody_root, wrong), payload);
    let before = files_below(&custody_root);
    assert!(refused_without_put(invoke(&command)).contains("LFS custody missing"));
    assert_eq!(files_below(&custody_root), before);

    put(&custody(&custody_root, incarnation), payload);
    let current_file = files_below(&custody_root)
        .into_iter()
        .find(|path| !before.contains(path))
        .unwrap();
    let good = fs::read(&current_file).unwrap();
    let verified = invoke(&command).unwrap();
    assert!(verified.contains("\"custody_verified\":true"));
    assert!(verified.contains("\"refs_published\":false"));
    assert_eq!(field(&verified, "head_sha256"), field(&pins, "head_sha256"));

    let original_paths = files_below(&custody_root);
    for mutation in [0, 1] {
        // Test digest corruption and truncation independently, preserving the
        // same content-addressed filename and native pointer in both cases.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&current_file)
            .unwrap();
        if mutation == 0 {
            file.seek(SeekFrom::End(-1)).unwrap();
            file.write_all(&[good[good.len() - 1] ^ 0xff]).unwrap();
        } else {
            file.set_len(good.len() as u64 - 1).unwrap();
        }
        drop(file);
        let corrupt = fs::read(&current_file).unwrap();
        let error = refused_without_put(invoke(&command));
        assert!(error.contains("LFS custody verification failed"), "{error}");
        assert!(error.contains(&expected.oid.to_string()), "{error}");
        assert_eq!(fs::read(&current_file).unwrap(), corrupt);
        assert_eq!(files_below(&custody_root), original_paths);
        assert_eq!(
            invoke(&args("inventory", &root, GitHashAlgorithm::Sha1)).unwrap(),
            pins
        );
        fs::write(&current_file, &good).unwrap();
        assert!(
            invoke(&command)
                .unwrap()
                .contains("\"custody_verified\":true")
        );
    }
}

#[test]
fn verification_honors_source_pins_and_independent_budgets_without_an_archive() {
    let scratch = Scratch::new();
    let root = scratch.0.join("node");
    let custody_root = scratch.private("lfs");
    let payload = b"bounded payload";
    let node = init(
        &root,
        GitHashAlgorithm::Sha256,
        &[("asset", object(payload).pointer())],
    );
    put(
        &custody(&custody_root, node.repository_incarnation_id()),
        payload,
    );
    node.shutdown().unwrap();
    let mut command = verify_args(&root, &custody_root, GitHashAlgorithm::Sha256);
    let pins = invoke(&args("inventory", &root, GitHashAlgorithm::Sha256)).unwrap();
    command.extend([
        "--expected-incarnation".into(),
        field(&pins, "incarnation_id"),
        "--expected-head-sha256".into(),
        field(&pins, "head_sha256"),
        "--max-payload-bytes".into(),
        payload.len().to_string(),
    ]);
    let original_paths = files_below(&custody_root);
    let complete = invoke(&command).unwrap();
    assert!(complete.contains("\"complete\":true"), "{complete}");
    for (flag, value, diagnostic) in [
        (
            "--expected-incarnation",
            "ff".repeat(16),
            "incarnation mismatch",
        ),
        (
            "--expected-head-sha256",
            "00".repeat(32),
            "head pin mismatch",
        ),
        (
            "--max-payload-bytes",
            (payload.len() - 1).to_string(),
            "payload-byte limit",
        ),
        (
            "--max-source-bytes",
            "1".into(),
            "native inventory byte limit",
        ),
        (
            "--max-source-objects",
            "1".into(),
            "native inventory object-count limit",
        ),
    ] {
        let mut invalid = command.clone();
        if let Some(index) = invalid.iter().position(|entry| entry == flag) {
            invalid[index + 1] = value;
        } else {
            invalid.extend([flag.into(), value]);
        }
        let error = refused_without_put(invoke(&invalid));
        assert!(error.contains(diagnostic), "{flag}: {error}");
        assert_eq!(files_below(&custody_root), original_paths);
    }
    let mut output = Vec::new();
    let error =
        lfs_transfer::run_with_timeout(&command, &mut output, Some(Duration::from_nanos(1)))
            .unwrap_err();
    assert!(output.is_empty());
    assert!(lfs_transfer::error_json(&error).contains("\"put_attempts\":0"));
    assert_eq!(files_below(&custody_root), original_paths);
    assert_eq!(invoke(&command).unwrap(), complete);
}

#[test]
fn verification_of_a_repository_without_pointers_does_not_create_an_lfs_namespace() {
    let scratch = Scratch::new();
    let root = scratch.0.join("node");
    let custody_root = scratch.private("lfs");
    init(
        &root,
        GitHashAlgorithm::Sha1,
        &[("README", "source without LFS\n".into())],
    )
    .shutdown()
    .unwrap();
    let report = invoke(&verify_args(&root, &custody_root, GitHashAlgorithm::Sha1)).unwrap();
    assert!(report.contains("\"objects\":0"), "{report}");
    assert!(report.contains("\"payload_bytes\":0"), "{report}");
    assert!(report.contains("\"custody_verified\":true"), "{report}");
    assert_eq!(fs::read_dir(&custody_root).unwrap().count(), 0);
}
