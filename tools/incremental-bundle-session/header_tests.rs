
#[test]
fn small_mapped_fetch_accepts_a_large_full_bundle_advertisement() {
    use fgit_pack::full_bundle::fetch::BundleRefMapping;
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new();
        let (source, _, child, _) = fixture(&source_root, format);
        let full = export(&source, &RefVisibility::new());
        let mut bytes = match format {
            GitHashAlgorithm::Sha1 => b"# v2 git bundle\n".to_vec(),
            GitHashAlgorithm::Sha256 => b"# v3 git bundle\n@object-format=sha256\n".to_vec(),
        };
        for i in 0..80 { bytes.extend_from_slice(format!("{child} refs/heads/wide{i:02}\n").as_bytes()); }
        bytes.push(b'\n');
        bytes.extend_from_slice(&full.bytes()[full.header_bytes()..]);
        let target_root = Scratch::new();
        let destination = empty_node(&target_root, format);
        let request = destination.request_context();
        let mapping = BundleRefMapping {
            source: reference("refs/heads/wide79"),
            destination: reference("refs/remotes/upstream/main"), expected_old: None,
        };
        let result = accepted(destination.runtime().block_on(destination.fetch_full_git_bundle_durable_in(
            &request, &session("one-of-many"), &bytes, &[mapping],
            AdmissionLimits { max_commands: 1, ..AdmissionLimits::default() },
        )));
        assert_eq!(result.commands.len(), 1);
        let selected = snapshot(&destination);
        assert_eq!(selected.snapshot().refs.len(), 1);
        assert_eq!(selected.snapshot().refs[&reference("refs/remotes/upstream/main")], child);
        destination.shutdown().unwrap(); source.shutdown().unwrap();
    }
}

#[test]
fn optional_head_advertisement_does_not_consume_an_incremental_mutation_slot() {
    for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
        let source_root = Scratch::new(); let (source, base, child, _) = fixture(&source_root, format);
        let target_root = Scratch::new(); let destination = empty_node(&target_root, format);
        seed(&source, &destination, base);
        let artifact = sync_export(&source, &["refs/heads/main"], &[base]);
        let mut bytes = artifact.bytes()[..artifact.header_bytes() - 1].to_vec();
        bytes.extend_from_slice(format!("{child} HEAD\n\n").as_bytes());
        bytes.extend_from_slice(&artifact.bytes()[artifact.header_bytes()..]);
        let request = destination.request_context();
        let result = accepted(destination.runtime().block_on(destination.import_incremental_git_bundle_durable_in(
            &request, &session("one-plus-head"), &bytes,
            &[(reference("refs/heads/main"), Some(base))],
            AdmissionLimits { max_commands: 1, ..AdmissionLimits::default() },
        )));
        assert_eq!(result.commands.len(), 1);
        assert_eq!(snapshot(&destination).snapshot().refs[&reference("refs/heads/main")], child);
        destination.shutdown().unwrap(); source.shutdown().unwrap();
    }
}
