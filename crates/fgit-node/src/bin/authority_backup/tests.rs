use super::*;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fg-authority-command-{}-{id}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
fn args(parts: &[&str]) -> Vec<String> { parts.iter().map(|part| (*part).to_owned()).collect() }

#[test]
fn strict_command_grammar_requires_local_authority_and_independent_restore_pins() {
    assert!(matches!(parse(&args(&["export", "source", "backup", "--trusted-local"])).unwrap().mode, Mode::Export));
    let hash = "ab".repeat(32);
    let restore = args(&["restore", "backup", "new", "--destination-instance", "52",
        "--expected-sha256", &hash, "--trusted-local"]);
    assert!(matches!(parse(&restore).unwrap().mode, Mode::Restore { instance, .. } if instance.raw() == 52));
    for bad in [vec![], vec!["export", "source", "backup"],
        vec!["restore", "source", "backup", "--trusted-local"],
        vec!["export", "source", "backup", "--trusted-local", "--trusted-local"],
        vec!["export", "source", "backup", "--trusted-local", "--destination-instance", "52"],
        vec!["export", "", "backup", "--trusted-local"],
        vec!["export", "source", "/", "--trusted-local"]]
    { assert!(parse(&args(&bad)).is_err(), "{bad:?}"); }
    for number in ["0", "01", "-1", "+1", "1 ", "9223372036854775808"] {
        let mut bad = restore.clone(); bad[4] = number.into();
        assert!(parse(&bad).is_err(), "{number}");
    }
}

#[test]
fn sha256_uses_the_existing_crypto_implementation_and_strict_hex_pins() {
    assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(digest(&hex(&sha256(b"abc"))).unwrap(), sha256(b"abc"));
    for bad in ["".to_owned(), "a".repeat(63), "a".repeat(65), "AB".repeat(32), "gg".repeat(32)] {
        assert!(digest(&bad).is_err());
    }
}

#[test]
fn complete_output_is_atomic_private_and_never_replaces_an_existing_file() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("backup");
    publish_new(&destination, b"complete\0binary\xff").unwrap();
    assert_eq!(fs::read(&destination).unwrap(), b"complete\0binary\xff");
    assert!(publish_new(&destination, b"replacement").is_err());
    assert_eq!(fs::read(&destination).unwrap(), b"complete\0binary\xff");
    assert_eq!(fs::read_dir(&scratch.0).unwrap().count(), 1, "no staging link leaked");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(destination).unwrap().permissions().mode() & 0o077, 0);
    }
}

#[test]
fn checksum_codec_and_same_instance_refusals_precede_destination_creation() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    let target = scratch.0.join("new");
    fs::write(&input, b"invalid portable bytes").unwrap();
    assert!(restore(&input, &target, [0; 32], StoreInstanceId::from_raw(52)).unwrap_err().contains("checksum"));
    assert!(!target.exists());
    assert!(restore(&input, &target, sha256(b"invalid portable bytes"), StoreInstanceId::from_raw(52)).is_err());
    assert!(!target.exists());
    let bundle = ExportBundle { schema_version: 1, instance: 52, bodies: Vec::new(), head: None, issuance: Vec::new() };
    let encoded = export_bundle(&bundle).unwrap();
    fs::write(&input, &encoded).unwrap();
    assert!(restore(&input, &target, sha256(&encoded), StoreInstanceId::from_raw(52)).unwrap_err().contains("instance"));
    assert!(!target.exists());
}

#[test]
fn missing_empty_oversized_and_symlink_inputs_are_not_read_as_backups() {
    let scratch = Scratch::new();
    let input = scratch.0.join("input");
    assert!(read_backup(&input).is_err());
    let file = File::create(&input).unwrap();
    assert!(read_backup(&input).is_err());
    file.set_len(MAX_BYTES as u64 + 1).unwrap();
    assert!(read_backup(&input).unwrap_err().contains("limit"));
    drop(file);
    fs::write(&input, b"x").unwrap();
    assert_eq!(read_backup(&input).unwrap(), b"x");
    #[cfg(unix)]
    {
        let link = scratch.0.join("link");
        std::os::unix::fs::symlink(&input, &link).unwrap();
        assert!(read_backup(&link).is_err());
        assert!(publish_new(&link, b"overwrite").is_err());
        assert_eq!(fs::read(&input).unwrap(), b"x");
    }
}

#[test]
fn diagnostic_strings_escape_terminal_controls_and_receipt_failure_is_not_success() {
    assert_eq!(quote("x\n\u{202e}\"\\"), "\"x\\u000a\\u202e\\\"\\\\\"");
    struct Broken;
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
        fn flush(&mut self) -> std::io::Result<()> { Err(std::io::ErrorKind::BrokenPipe.into()) }
    }
    assert!(run(&args(&["--help"]), &mut Broken).is_err());
    assert!(USAGE.contains("NOT backed up or restored"));
    assert!(USAGE.contains("not evidence of success or non-commit"));
}
