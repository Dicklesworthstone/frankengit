//! Current-snapshot export using one independently pinned historical backup.
//! Only Git payload provenance changes. The source's current authority image,
//! selected inventory and retained checkpoint remain the output's sole basis.
//! No live placement is created, replaced, repaired or deleted.

mod ancestry;
mod merge;
mod paths;

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use fgit_authority::{AuthorityHeadAncestryReceipt, HeadReadReceipt, StoreInstanceId};
use fgit_types::GitOid;

use super::archive::Identity;
use super::archive::stream::{RecordHeader, StreamEncoder};
use super::input::PinnedArchive;
use super::profile::{Deadline, Profile};
use super::restore::verify::{VerifiedSourceArchive, verify_pinned_in};
use super::{hex, quote, require_absent};
use crate::{NodeRequestContext, OneNode};

pub(super) const DEFAULT_MAX_ANCESTRY_HOPS: usize = 4096;

#[derive(Debug)]
pub(super) struct Options {
    input: PathBuf,
    expected: [u8; 32],
    scratch: PathBuf,
    instance: StoreInstanceId,
    max_ancestry_hops: usize,
}

#[derive(Default)]
pub(super) struct Flags {
    input: Option<PathBuf>,
    expected: Option<[u8; 32]>,
    scratch: Option<PathBuf>,
    instance: Option<StoreInstanceId>,
    max_ancestry_hops: Option<usize>,
}

impl Flags {
    pub(super) fn accepts(flag: &str) -> bool {
        matches!(
            flag,
            "--donor-backup"
                | "--donor-sha256"
                | "--donor-scratch"
                | "--donor-verification-instance"
                | "--donor-max-ancestry-hops"
        )
    }

    pub(super) fn set(&mut self, flag: &str, value: &str) -> Result<(), String> {
        match flag {
            "--donor-backup" if self.input.is_none() && !value.is_empty() => {
                self.input = Some(value.into());
            }
            "--donor-sha256" if self.expected.is_none() => {
                self.expected = Some(super::restore::digest(value)?);
            }
            "--donor-scratch" if self.scratch.is_none() && !value.is_empty() => {
                self.scratch = Some(value.into());
            }
            "--donor-verification-instance" if self.instance.is_none() => {
                let instance = positive(value)?;
                if i64::try_from(instance).is_err() {
                    return Err(
                        "donor verification instance must fit a positive SQL integer".into(),
                    );
                }
                self.instance = Some(StoreInstanceId::from_raw(instance));
            }
            "--donor-max-ancestry-hops" if self.max_ancestry_hops.is_none() => {
                let hops = usize::try_from(positive(value)?)
                    .map_err(|_| "donor ancestry bound does not fit this host")?;
                if hops > fgit_authority::MAX_AUTHORITY_HEAD_ANCESTRY_HOPS {
                    return Err("donor ancestry bound exceeds 65536".into());
                }
                self.max_ancestry_hops = Some(hops);
            }
            _ => return Err(format!("invalid or duplicate donor export option: {flag}")),
        }
        Ok(())
    }

    pub(super) fn finish(self) -> Result<Option<Options>, String> {
        match (self.input, self.expected, self.scratch, self.instance) {
            (None, None, None, None) if self.max_ancestry_hops.is_none() => Ok(None),
            (Some(input), Some(expected), Some(scratch), Some(instance)) => Ok(Some(Options {
                input,
                expected,
                scratch,
                instance,
                max_ancestry_hops: self.max_ancestry_hops.unwrap_or(DEFAULT_MAX_ANCESTRY_HOPS),
            })),
            _ => Err("donor export requires --donor-backup, --donor-sha256, --donor-scratch and --donor-verification-instance together".into()),
        }
    }
}

fn positive(value: &str) -> Result<u64, String> {
    if value.is_empty() || value.starts_with('0') || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("donor numeric options require canonical positive decimal".into());
    }
    value
        .parse()
        .map_err(|_| "donor numeric option overflows".into())
}

/// Complete native archive preflight, retaining its original input descriptor.
/// Neither this object nor its digest permits a current-head or placement write.
pub(super) struct Prepared {
    archive: VerifiedSourceArchive<File>,
    max_ancestry_hops: usize,
    max_objects: usize,
    max_donor_payload_bytes: u64,
}

pub(super) struct SourceSnapshot<'a> {
    pub node: &'a OneNode,
    pub request: &'a NodeRequestContext,
    pub captured: &'a HeadReadReceipt,
    pub objects: &'a BTreeSet<GitOid>,
}

pub(super) struct Provenance {
    digest: [u8; 32],
    ancestry: AuthorityHeadAncestryReceipt,
    counts: merge::Counts,
}

impl Provenance {
    pub(super) fn receipt_fields(&self) -> String {
        format!(
            concat!(
                ",\"donor_backup\":{{\"sha256\":{},\"head_id\":{},\"head_generation\":{},",
                "\"ancestry_hops\":{},\"selected_objects_supplied\":{},\"payload_bytes_supplied\":{},",
                "\"local_objects_supplied\":{},\"source_objects_repaired\":false}}"
            ),
            quote(&hex(&self.digest)),
            quote(&self.ancestry.ancestor_head_id().to_string()),
            self.ancestry.ancestor_generation().get(),
            self.ancestry.hops(),
            self.counts.donor_objects,
            self.counts.donor_payload_bytes,
            self.counts.local_objects,
        )
    }
}

impl Options {
    /// Path separation is established before any scratch or output file exists.
    /// The same pinned directories are rechecked through final publication.
    pub(super) fn prepare(
        &self,
        source: &Path,
        output: &Path,
        expected: (
            fgit_types::TenantId,
            fgit_types::RepositoryId,
            fgit_types::GitHashAlgorithm,
        ),
        profile: Profile,
        deadline: Deadline,
    ) -> Result<(Prepared, paths::Separation), String> {
        let separation =
            paths::Separation::capture(source, &self.input, output, &self.scratch, || {
                deadline.check()
            })?;
        require_absent(output)?;
        require_absent(&self.scratch)?;
        let archive = PinnedArchive::open(&self.input, self.expected, profile.transfer, deadline)?;
        let identity = archive.header().identity;
        if (identity.tenant, identity.repository, identity.format) != expected {
            return Err(
                "donor backup tenant, repository or object format differs from source".into(),
            );
        }
        separation.check(|| deadline.check())?;
        let bounded_profile = Profile {
            timeout: deadline.remaining()?,
            ..profile
        };
        let archive = verify_pinned_in(
            archive,
            &self.scratch,
            self.instance,
            bounded_profile,
            deadline,
        )?;
        separation.check(|| deadline.check())?;
        Ok((
            Prepared {
                archive,
                max_ancestry_hops: self.max_ancestry_hops,
                max_objects: profile.transfer.max_objects,
                max_donor_payload_bytes: profile.transfer.max_archive_bytes,
            },
            separation,
        ))
    }
}

impl Prepared {
    pub(super) fn write_selected<W: Write>(
        &mut self,
        source: SourceSnapshot<'_>,
        output: &mut StreamEncoder<W>,
        deadline: Deadline,
        mut local: impl FnMut(GitOid, &mut StreamEncoder<W>) -> Result<(), String>,
    ) -> Result<Provenance, String> {
        let node = source.node;
        let identity = Identity {
            tenant: node.tenant_id(),
            repository: node.repository_id(),
            incarnation: node.repository_incarnation_id(),
            format: node.object_format,
        };
        if self.archive.header().identity != identity {
            return Err("donor backup identity or incarnation differs from current source".into());
        }
        let donor = self
            .archive
            .header()
            .authority
            .head
            .as_ref()
            .ok_or("donor backup has no authority head")?;
        let ancestry = node.runtime().block_on(ancestry::authenticate(
            &node.authority,
            source.request.authority(),
            source.captured,
            node.repository_id(),
            ancestry::DonorHead {
                key: &donor.key,
                generation: donor.generation,
                body: &donor.body,
            },
            self.max_ancestry_hops,
            || live_source(deadline, source.request),
        ))?;
        let digest = self.archive.seal().digest;
        let limits = merge::Limits {
            format: identity.format,
            donor_objects: self.archive.header().objects,
            max_objects: self.max_objects,
            max_donor_payload_bytes: self.max_donor_payload_bytes,
        };
        let counts = merge::compose(
            source.objects,
            limits,
            |visit| {
                self.archive
                    .scan_stream(deadline, |header, body| visit(header, body))
            },
            |item| match item {
                merge::Source::Local(oid) => local(oid, output),
                merge::Source::Donor(header, body) => output.object_stream(
                    header.oid,
                    header.kind,
                    header.length,
                    &header.commitment,
                    body,
                    &mut || live_source(deadline, source.request),
                ),
            },
            || live_source(deadline, source.request),
        )?;
        Ok(Provenance {
            digest,
            ancestry,
            counts,
        })
    }
}

fn live_source(deadline: Deadline, request: &NodeRequestContext) -> Result<(), String> {
    deadline.in_request(request)?;
    if request.is_live() {
        Ok(())
    } else {
        Err("donor export cancelled or request budget exhausted".into())
    }
}

impl merge::Record for RecordHeader {
    fn oid(self) -> GitOid {
        self.oid
    }
    fn length(self) -> u64 {
        self.length
    }
}

#[cfg(test)]
mod native_tests;
#[cfg(test)]
mod tests;
