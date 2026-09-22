//! Read-only inventory needed to form exact expectations for the next fetch.
use super::options::{Operation, Options, head_token, hex, parse_inventory};
use super::{
    GitOid, HeadGeneration, NodeConfig, OneNode, RefName, RepositoryAuthorityHeadId, quote,
};
use std::io::Write;

const USAGE: &str = "usage: fg refs <storage-root> <tenant-id> <repository-id> --trusted-local
  [--object-format sha1|sha256] [--limit <1..100>]
  [(--after <full-ref> | --after-hex <bytes>) --expected-head <snapshot-token>]

Lists all visible direct refs, including branches, remote-tracking refs and tags.
Names are lossless lowercase hex; tips are exact native object IDs. Use a tip as
an explicit expected-old value for a later fg bundle fetch. This read never
updates a ref or silently refreshes a failed write expectation. Continue with
next_after_hex and the same snapshot_token; if authority moved, restart the read.
HEAD is not a synthetic ref row. Exit 0: complete page; 2: input/read/output failure.";

pub(super) fn run(args: &[String]) -> Result<u8, String> {
    if args == ["--help"] {
        write_page(&mut std::io::stdout().lock(), USAGE)?;
        return Ok(0);
    }
    let options = parse_inventory(args)?;
    let Operation::List {
        after,
        limit,
        expected_head,
    } = &options.operation
    else {
        return Err("reference inventory is read-only".into());
    };
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| error.to_string())?;
    let operation = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        let request = node.request_context();
        node.runtime()
            .block_on(node.list_refs_in(
                &request,
                &Default::default(),
                after.as_ref(),
                *limit,
                *expected_head,
            ))
            .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    match (operation, cleanup) {
        (Ok((head, rows, next)), None) => {
            write_page(
                &mut std::io::stdout().lock(),
                &receipt(&options, head, &rows, next.as_ref()),
            )?;
            Ok(0)
        }
        (result, cleanup) => {
            let read = result
                .err()
                .map_or_else(String::new, |error| format!("; read: {error}"));
            let close = cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}"));
            Err(format!("no complete reference page returned{read}{close}"))
        }
    }
}
fn write_page(output: &mut impl Write, page: &str) -> Result<(), String> {
    writeln!(output, "{page}")
        .and_then(|()| output.flush())
        .map_err(|error| format!("reference page output incomplete: {error}"))
}
fn receipt(
    options: &Options,
    head: RepositoryAuthorityHeadId,
    rows: &[(RefName, GitOid)],
    next: Option<&RefName>,
) -> String {
    let references = rows
        .iter()
        .map(|(name, tip)| {
            format!(
                "{{\"reference_hex\":{},\"tip\":{}}}",
                quote(&hex(name.as_bytes())),
                quote(&tip.to_string())
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        concat!(
            "{{\"type\":\"reference_page\",\"schema_version\":1,\"tenant_id\":{},\"repository_id\":{},",
            "\"object_format\":{},\"source_head\":{},\"snapshot_token\":{},\"references\":[{}],",
            "\"next_after_hex\":{},\"has_more\":{},\"node_closed\":true}}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(options.format.as_str()),
        quote(&head.to_string()),
        quote(&head_token(head)),
        references,
        next.map_or_else(|| "null".into(), |name| quote(&hex(name.as_bytes()))),
        next.is_some()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgit_types::hash::{DigestAlgorithmId, DigestBytes};
    use fgit_types::{CANONICAL_CODEC_VERSION, GitHashAlgorithm};
    fn args() -> Vec<String> {
        vec![
            "unopened".into(),
            "01".repeat(16),
            "02".repeat(16),
            "--trusted-local".into(),
        ]
    }
    fn head() -> RepositoryAuthorityHeadId {
        RepositoryAuthorityHeadId::from_digest(
            DigestAlgorithmId::try_new(2).unwrap(),
            CANONICAL_CODEC_VERSION,
            DigestBytes::try_new(&[5; 32]).unwrap(),
        )
    }
    #[test]
    fn read_cursor_accepts_raw_remote_refs_but_never_mutation_flags() {
        let mut values = args();
        values.extend([
            "--after-hex".into(),
            hex(b"refs/remotes/origin/\xff"),
            "--expected-head".into(),
            head_token(head()),
        ]);
        let parsed = parse_inventory(&values).unwrap();
        let Operation::List { after, .. } = parsed.operation else {
            panic!()
        };
        assert_eq!(after.unwrap().as_bytes(), b"refs/remotes/origin/\xff");
        let mut branch = vec!["list".into()];
        branch.extend(values.clone());
        assert!(super::super::options::parse(&branch).is_err());
        for flag in [
            "--principal",
            "--idempotency-key",
            "--target",
            "--force",
            "--key-stdin",
        ] {
            let mut bad = args();
            bad.extend([flag.into(), "forbidden".into()]);
            assert!(parse_inventory(&bad).is_err());
        }
        values.truncate(values.len() - 2);
        assert!(parse_inventory(&values).is_err());
        let mut no_trust = args();
        no_trust.pop();
        assert!(parse_inventory(&no_trust).is_err());
    }
    #[test]
    fn lossless_receipt_and_flush_failure_remain_distinct_from_complete_pages() {
        let options = parse_inventory(&args()).unwrap();
        let reference = RefName::try_new(b"refs/remotes/origin/\xff").unwrap();
        let tip = GitOid::from_hex(GitHashAlgorithm::Sha1, &"12".repeat(20)).unwrap();
        let page = receipt(
            &options,
            head(),
            &[(reference.clone(), tip)],
            Some(&reference),
        );
        assert!(page.contains("\"type\":\"reference_page\""));
        assert!(page.contains(&hex(reference.as_bytes())));
        assert!(page.contains(&tip.to_string()));
        assert!(page.contains("\"has_more\":true"));
        assert!(page.contains(&head_token(head())));
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("flush failed"))
            }
        }
        assert!(
            write_page(&mut Broken, &page)
                .unwrap_err()
                .contains("incomplete")
        );
        let mut bytes = Vec::new();
        write_page(&mut bytes, &page).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), format!("{page}\n"));
    }
}
