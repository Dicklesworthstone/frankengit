//! Complete current-source archives under the existing source-read grant.
//! Collection must succeed within one request before any tar bytes are sent.

use super::super::issues::ApiError;
use super::request::Selection;
use super::{Status, read_error};
use crate::smart_http::drive_request_while;
use crate::{NodeRequestContext, NodeWorkspaceRefusal, OneNode};
use fgit_forge::source_archive::{
    MAX_ARCHIVE_BYTES, MIN_ARCHIVE_BYTES, PROFILE, SourceArchive, SourceArchiveError,
    collect_with_limit,
};
use fgit_forge::source_browse::SourceBrowseQuery;
use fgit_wire::smart_http::HttpVersion;
use std::io::{self, Write};

pub(super) struct Reply {
    archive: SourceArchive,
}

fn checkpoint(live: &mut impl FnMut() -> bool) -> Result<(), ApiError> {
    if live() {
        Ok(())
    } else {
        Err(ApiError::from_status(Status::Timeout, false))
    }
}

fn archive_error(error: SourceArchiveError<NodeWorkspaceRefusal>) -> ApiError {
    match error {
        SourceArchiveError::Read(error) => read_error(error),
        SourceArchiveError::Budget(_) => ApiError::too_large(),
        // Do not reflect repository names, link targets or internal diagnostics.
        SourceArchiveError::Invalid(_) => {
            ApiError::new(Status::Conflict, "source_archive_profile_refused")
        }
    }
}

pub(super) fn produce(
    node: &OneNode,
    context: &NodeRequestContext,
    selection: &Selection,
    query: &SourceBrowseQuery,
    maximum_response: u64,
    live: &mut impl FnMut() -> bool,
) -> Result<Reply, ApiError> {
    let maximum = usize::try_from(maximum_response)
        .unwrap_or(usize::MAX)
        .min(MAX_ARCHIVE_BYTES);
    // Even an empty directory needs its prefix and the two terminal blocks.
    // Refuse an impossible output ceiling before reading source objects.
    if maximum < MIN_ARCHIVE_BYTES {
        return Err(ApiError::too_large());
    }
    checkpoint(live)?;
    let archive = collect_with_limit(
        node.repository_id,
        node.object_format,
        query,
        maximum,
        |page| {
            checkpoint(live).map_err(|_| NodeWorkspaceRefusal::Cancelled {
                exhaustion: None,
            })?;
            drive_request_while(
                node,
                context,
                node.browse_source_local_in(context, &selection.reference, page),
                live,
            )
        },
    )
    .map_err(archive_error)?;
    checkpoint(live)?;
    Ok(Reply { archive })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Reply {
    pub(super) fn send(&self, writer: &mut impl Write, version: HttpVersion) -> io::Result<()> {
        let version = match version {
            HttpVersion::Http10 => "HTTP/1.0",
            HttpVersion::Http11 => "HTTP/1.1",
        };
        let pin = &self.archive.pin;
        let internal = pin.head.as_internal_object_id();
        let snapshot = format!(
            "alg:{}:{}",
            internal.algorithm().code_point(),
            hex(internal.digest().as_bytes())
        );
        write!(
            writer,
            concat!(
                "{} 200 OK\r\n",
                "Content-Type: application/x-tar\r\n",
                "Content-Disposition: attachment; filename=\"source.tar\"\r\n",
                "Content-Length: {}\r\n",
                "Cache-Control: no-store\r\nPragma: no-cache\r\n",
                "Vary: Authorization\r\nX-Content-Type-Options: nosniff\r\n",
                "X-FrankenGit-Archive-Profile: {}\r\n",
                "X-FrankenGit-Snapshot-Token: {}\r\n",
                "X-FrankenGit-Source-Head: {}\r\n",
                "X-FrankenGit-Source-Rcr: {}\r\n",
                "X-FrankenGit-Source-Commit: {}\r\n",
                "X-FrankenGit-Root-Tree: {}\r\n",
                "X-FrankenGit-Selected-Tree: {}\r\n",
                "X-FrankenGit-Archive-Entries: {}\r\n",
                "X-FrankenGit-Archive-Gitlinks: {}\r\n",
                "X-FrankenGit-Archive-Reads: {}\r\n",
                "Connection: close\r\n\r\n"
            ),
            version,
            self.archive.bytes.len(),
            PROFILE,
            snapshot,
            pin.head,
            pin.rcr,
            pin.commit,
            pin.tree,
            self.archive.root,
            self.archive.entries,
            self.archive.gitlinks,
            self.archive.reads,
        )?;
        // The listener retains the original request deadline through delivery.
        // A socket failure ends the response; it cannot expose a complete file
        // to a client that verifies Content-Length before offering a download.
        for chunk in self.archive.bytes.chunks(64 * 1024) {
            writer.write_all(chunk)?;
        }
        writer.flush()
    }
}

#[cfg(test)]
mod tests;
