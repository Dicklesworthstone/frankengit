//! Complete source archives through the shared verified-read collector.
//! The CLI alone owns no-overwrite publication and explicit node shutdown.
use super::{NodeConfig, OneNode, SourceBrowseAction};
use super::{Options, emit, head_token, hex, optional_hex, quote};
use super::{publish_new_bundle, require_absent};
use fgit_forge::source_archive::{self, SourceArchive};
use fgit_types::HeadGeneration;
use std::path::Path;

fn complete_query(options: &Options) -> Result<(), String> {
    if !matches!(
        options.query.action,
        SourceBrowseAction::List {
            after: None,
            limit: 1..=1000
        }
    ) {
        return Err("tree --output requires a complete directory, without --after-hex".into());
    }
    source_archive::validate_query(options.format, &options.query).map_err(str::to_owned)
}

fn after_shutdown(
    result: Result<SourceArchive, String>,
    cleanup: Option<String>,
) -> Result<SourceArchive, String> {
    match (result, cleanup) {
        (Ok(archive), None) => Ok(archive),
        (result, cleanup) => Err(format!(
            "no source archive published{}{}",
            result
                .err()
                .map_or_else(String::new, |error| format!("; read: {error}")),
            cleanup.map_or_else(String::new, |error| format!("; shutdown: {error}"))
        )),
    }
}

pub(super) fn export_tree(options: &Options, destination: &Path) -> Result<u8, String> {
    complete_query(options)?;
    require_absent(destination)?;
    let mut node = OneNode::open_existing(
        NodeConfig::new(options.storage.clone(), options.tenant, options.repository)
            .with_object_format(options.format),
    )
    .map_err(|error| format!("cannot open source archive node: {error}"))?;
    let result = (|| {
        node.bring_into_service(HeadGeneration::FIRST)
            .map_err(|error| error.to_string())?;
        // One request owns the complete traversal, rather than resetting its
        // budget for every directory or file range.
        let request = fgit_cli::command_request_context(&node);
        source_archive::collect(
            options.repository,
            options.format,
            &options.query,
            |query| {
                node.runtime()
                    .block_on(node.browse_source_local_in(&request, &options.reference, query))
            },
        )
        .map_err(|error| error.to_string())
    })();
    let cleanup = node.shutdown().err().map(|error| error.to_string());
    let archive = after_shutdown(result, cleanup)?;
    publish_new_bundle(destination, &archive.bytes)?;
    let receipt = format!(
        concat!(
            "{{\"type\":\"source_tree_export\",\"schema_version\":1,\"profile\":\"ustar-source-v1\",",
            "\"tenant_id\":{},\"repository_id\":{},\"reference_hex\":{},\"object_format\":{},",
            "\"source_head\":{},\"snapshot_token\":{},\"source_rcr\":{},\"source_commit\":{},",
            "\"root_tree\":{},\"selected_tree\":{},\"path_hex\":{},\"archive_prefix\":\"source/\",",
            "\"bytes_written\":{},\"entries\":{},\"gitlink_directories\":{},\"reads\":{},",
            "\"output_created\":true,\"node_closed\":true,\"repository_changed\":false,",
            "\"symlink_followed\":false,\"submodules_materialized\":false,\"git_attributes_applied\":false}}"
        ),
        quote(&options.tenant.to_string()),
        quote(&options.repository.to_string()),
        quote(&hex(options.reference.as_bytes())),
        quote(options.format.as_str()),
        quote(&archive.pin.head.to_string()),
        quote(&head_token(archive.pin.head)),
        quote(&archive.pin.rcr.to_string()),
        quote(&archive.pin.commit.to_string()),
        quote(&archive.pin.tree.to_string()),
        quote(&archive.root.to_string()),
        optional_hex(options.query.path.as_deref()),
        archive.bytes.len(),
        archive.entries,
        archive.gitlinks,
        archive.reads
    );
    emit(&mut std::io::stdout().lock(), &receipt).map_err(|error| {
        format!("complete source archive was created, but receipt failed: {error}")
    })?;
    Ok(0)
}

#[cfg(test)]
mod tests;
