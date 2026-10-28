//! Reject an unpublishable canonical closure before placing any object files.
//! These checks describe bytes, not time. They never widen an authority profile.
use super::{CanonicalRefState, ImportControl, LooseGitImportRefusal, PermittedObjectClosure};
use fgit_codec::{CodecRefusal, DecodeLimits, Encoder, encode_body};
use fgit_types::GitHashAlgorithm;

fn codec_error(body: &'static str, source: CodecRefusal) -> LooseGitImportRefusal {
    LooseGitImportRefusal::PublicationMetadataInvalid {
        body,
        source: Box::new(source),
    }
}
const fn check(body: &'static str, bytes: u64, maximum: u64) -> Result<(), LooseGitImportRefusal> {
    if bytes > maximum {
        return Err(LooseGitImportRefusal::PublicationMetadataTooLarge {
            body,
            observed: bytes,
            limit: maximum,
        });
    }
    Ok(())
}
fn closure_bytes(format: GitHashAlgorithm, count: usize) -> Result<u64, LooseGitImportRefusal> {
    // The canonical set has a fixed-width count and concatenated native IDs.
    // Derive the envelope and algorithm width from the real encoder instead
    // of duplicating a frame-header size or confusing hex with native bytes.
    let empty = encode_body(&PermittedObjectClosure::default())
        .map_err(|e| codec_error("object-closure", e))?;
    let mut algorithm = Encoder::new();
    algorithm.write_git_hash_algorithm(format);
    let width = (algorithm.as_bytes().len() + format.digest_len()) as u64;
    Ok((count as u64)
        .saturating_mul(width)
        .saturating_add(empty.len() as u64))
}
fn ref_bytes(
    refs: &CanonicalRefState,
    control: &ImportControl<'_>,
) -> Result<u64, LooseGitImportRefusal> {
    let empty = encode_body(&CanonicalRefState::new(Default::default()))
        .map_err(|e| codec_error("ref-state", e))?;
    let mut total = empty.len() as u64;
    if let Some(head) = refs.head_target() {
        let mut encoded = Encoder::new();
        encoded
            .write_ref_name(head)
            .map_err(|e| codec_error("ref-state", e))?;
        total = total.saturating_add(encoded.as_bytes().len() as u64);
    }
    for (name, oid) in refs.refs() {
        control.checkpoint()?;
        let mut encoded = Encoder::new();
        encoded
            .write_ref_name(name)
            .map_err(|e| codec_error("ref-state", e))?;
        encoded.write_git_oid(oid);
        total = total.saturating_add(encoded.as_bytes().len() as u64);
    }
    Ok(total)
}

pub(super) fn preflight(
    format: GitHashAlgorithm,
    object_count: usize,
    refs: &CanonicalRefState,
    authority_bytes: usize,
    control: &ImportControl<'_>,
) -> Result<(), LooseGitImportRefusal> {
    control.checkpoint()?;
    let maximum = (authority_bytes as u64).min(DecodeLimits::DEFAULT.frame_bytes);
    check(
        "object-closure",
        closure_bytes(format, object_count)?,
        maximum,
    )?;
    check("ref-state", ref_bytes(refs, control)?, maximum)?;
    control.checkpoint()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::{GitOid, RefName};
    use std::collections::BTreeMap;
    fn oid(format: GitHashAlgorithm, n: usize) -> GitOid {
        GitOid::from_hex(
            format,
            &format!("{:0width$x}", n + 1, width = format.digest_len() * 2),
        )
        .unwrap()
    }
    #[test]
    fn exact_size_matches_the_real_codec_for_both_domains_and_raw_ref_names() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            for count in [0, 1, 2, 1024, 47_659, 100_202] {
                let closure =
                    PermittedObjectClosure::new((0..count).map(|n| oid(format, n)).collect());
                assert_eq!(
                    closure_bytes(format, count).unwrap(),
                    encode_body(&closure).unwrap().len() as u64
                );
            }
            let mut names = BTreeMap::new();
            for (n, name) in [
                b"refs/heads/main".as_slice(),
                b"refs/heads/\xff",
                b"refs/tags/one",
            ]
            .iter()
            .enumerate()
            {
                names.insert(RefName::try_new(name).unwrap(), oid(format, n));
            }
            for refs in [
                CanonicalRefState::new(Default::default()),
                CanonicalRefState::new(names.clone()),
                CanonicalRefState::new_with_head_target(
                    names,
                    RefName::try_new(b"refs/heads/main").unwrap(),
                )
                .unwrap(),
            ] {
                let mut live = || true;
                let control = ImportControl::new(&mut live);
                assert_eq!(
                    ref_bytes(&refs, &control).unwrap(),
                    encode_body(&refs).unwrap().len() as u64
                );
            }
        }
    }
    #[test]
    fn last_fitting_closure_passes_and_next_identity_names_the_exceeded_byte_bound() {
        for format in [GitHashAlgorithm::Sha1, GitHashAlgorithm::Sha256] {
            let overhead = closure_bytes(format, 0).unwrap();
            let width = closure_bytes(format, 1).unwrap() - overhead;
            for maximum in [1 << 20, 16 << 20] {
                let count = ((maximum as u64 - overhead) / width) as usize;
                let mut live = || true;
                let control = ImportControl::new(&mut live);
                let refs = CanonicalRefState::new(Default::default());
                preflight(format, count, &refs, maximum, &control).unwrap();
                let failure = preflight(format, count + 1, &refs, maximum, &control).unwrap_err();
                assert!(
                    matches!(failure,LooseGitImportRefusal::PublicationMetadataTooLarge{body:"object-closure",observed,limit} if observed==closure_bytes(format,count+1).unwrap() && limit==maximum as u64)
                );
                let text = failure.to_string();
                assert!(
                    text.contains("before object placement")
                        && text.contains("object-closure")
                        && text.contains(&maximum.to_string())
                );
            }
        }
    }
    #[test]
    fn a_larger_backend_cannot_publish_a_closure_its_readers_would_refuse() {
        let maximum = DecodeLimits::DEFAULT.frame_bytes;
        let count =
            ((maximum - closure_bytes(GitHashAlgorithm::Sha256, 0).unwrap()) / 34 + 1) as usize;
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        assert!(
            matches!(preflight(GitHashAlgorithm::Sha256,count,&CanonicalRefState::new(Default::default()),usize::MAX,&control),
            Err(LooseGitImportRefusal::PublicationMetadataTooLarge{limit,..}) if limit==maximum)
        );
    }
    #[test]
    fn cancellation_is_not_a_size_error_and_never_refreshes_the_control() {
        let mut dead = || false;
        let control = ImportControl::new(&mut dead);
        assert!(matches!(
            preflight(
                GitHashAlgorithm::Sha1,
                0,
                &CanonicalRefState::new(Default::default()),
                16 << 20,
                &control
            ),
            Err(LooseGitImportRefusal::Interrupted { .. })
        ));
    }
    #[test]
    fn explicit_smaller_profile_refuses_ref_state_separately_from_object_closure() {
        let name = RefName::try_new(format!("refs/heads/{}", "a".repeat(300)).as_bytes()).unwrap();
        let refs = CanonicalRefState::new([(name, oid(GitHashAlgorithm::Sha1, 0))].into());
        let mut live = || true;
        let control = ImportControl::new(&mut live);
        assert!(matches!(
            preflight(GitHashAlgorithm::Sha1, 1, &refs, 128, &control),
            Err(LooseGitImportRefusal::PublicationMetadataTooLarge {
                body: "ref-state",
                ..
            })
        ));
        preflight(GitHashAlgorithm::Sha1, 1, &refs, 1024, &control).unwrap();
    }
}

#[cfg(test)]
mod native_preflight {
    use super::*;
    use crate::{NodeConfig, OneNode};
    use fgit_authority::AuthorityLimits;
    use fgit_authority_fsqlite::FsqliteAuthorityStore;
    use fgit_crypto::{GitObjectKind, git_object_id};
    use fgit_types::{GitOid, RepositoryId, TenantId};
    use std::fs;
    use std::path::Path;
    fn put(root: &Path, kind: GitObjectKind, body: &[u8]) -> GitOid {
        let oid = git_object_id(GitHashAlgorithm::Sha1, kind, body);
        let hex = oid.to_string();
        let raw = [
            format!("{} {}\0", kind.label(), body.len()).as_bytes(),
            body,
        ]
        .concat();
        let len = u16::try_from(raw.len()).unwrap();
        let mut z = vec![0x78, 0x01, 0x01];
        z.extend(len.to_le_bytes());
        z.extend((!len).to_le_bytes());
        z.extend(&raw);
        let (a, b) = raw.iter().fold((1u32, 0u32), |(a, b), x| {
            let a = (a + u32::from(*x)) % 65521;
            (a, (b + a) % 65521)
        });
        z.extend(((b << 16) | a).to_be_bytes());
        let path = root.join("objects").join(&hex[..2]);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join(&hex[2..]), z).unwrap();
        oid
    }
    #[test]
    fn real_import_refuses_metadata_before_any_fabric_placement_and_valid_twin_publishes() {
        let root =
            std::env::temp_dir().join(format!("fg-preflight-no-placement-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let source = root.join("source");
        fs::create_dir_all(source.join("refs/heads")).unwrap();
        fs::write(source.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let mut tree = Vec::new();
        let mut objects = Vec::new();
        for i in 0..64 {
            let oid = put(
                &source,
                GitObjectKind::Blob,
                format!("body-{i}\n").as_bytes(),
            );
            objects.push(oid);
            tree.extend(format!("100644 file{i:02}\0").as_bytes());
            tree.extend(oid.as_bytes());
        }
        let tree = put(&source, GitObjectKind::Tree, &tree);
        objects.push(tree);
        let tip=put(&source,GitObjectKind::Commit,format!("tree {tree}\nauthor Test <test@example.invalid> 1 +0000\ncommitter Test <test@example.invalid> 1 +0000\n\npreflight\n").as_bytes());
        objects.push(tip);
        fs::write(source.join("refs/heads/main"), format!("{tip}\n")).unwrap();
        let config = NodeConfig::new(
            root.join("node"),
            TenantId::from_bytes([0xa1; 16]),
            RepositoryId::from_bytes([0xa2; 16]),
        )
        .with_worker_threads(2);
        let (mut node, _) = OneNode::init(config.clone()).unwrap();
        let cx = node.command_request_context(None);
        let replacement = node
            .runtime()
            .block_on(FsqliteAuthorityStore::open(
                cx.authority(),
                crate::authority_database_path(&root.join("node")).unwrap(),
                node.service_config.store_instance,
                AuthorityLimits {
                    body_bytes: 1024,
                    ..Default::default()
                },
            ))
            .unwrap();
        let mut original = std::mem::replace(&mut node.authority, replacement);
        node.runtime()
            .block_on(original.close(cx.authority()))
            .unwrap();
        let refusal = node.stage_loose_git_import(&source).unwrap_err();
        assert!(
            matches!(
                refusal,
                LooseGitImportRefusal::PublicationMetadataTooLarge {
                    body: "object-closure",
                    observed: 1542,
                    limit: 1024
                }
            ),
            "{refusal:?}"
        );
        for oid in &objects {
            assert!(
                node.read_git_object(*oid).is_err(),
                "no object may be placed before metadata preflight"
            );
        }
        node.shutdown().unwrap();
        let mut node = OneNode::open_existing(config).unwrap();
        let head = node
            .runtime()
            .block_on(node.authenticate_authority_head())
            .unwrap();
        node.bring_into_service(head.receipt().generation())
            .unwrap();
        let receipt = node
            .runtime()
            .block_on(node.import_loose_git_directory_durable_in(
                &node.import_request_context(None),
                &source,
                fgit_types::PrincipalId::from_bytes([0xa3; 16]),
                b"preflight-valid-twin",
            ))
            .unwrap();
        assert!(matches!(
            receipt.commands[0].terminal.outcome,
            fgit_types::DecisionOutcome::Committed { .. }
        ));
        for oid in objects {
            node.read_git_object(oid).unwrap();
        }
        node.shutdown().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
