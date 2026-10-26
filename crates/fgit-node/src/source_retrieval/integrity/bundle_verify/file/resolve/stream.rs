//! Blob delta reconstruction into the same private scratch descriptor. Neither
//! the full base nor the result is buffered. The base's indexed blocks and the
//! new result's native identity remain independently authenticated.

use std::io::{Read, Seek, Write};

use fgit_pack::{
    Deadline, DeltaStreamIo, PackLimits, ResolutionBudget, StreamDeltaError,
    apply_delta_streamed_to_charged_base_with_budget,
};
use fgit_types::GitHashAlgorithm;

use super::super::storage::{Append, IndexedSpan, Scratch};
use super::{
    BundleVerifyError, BundleVerifyLimits, NativeEntryHash, ObjectKind, Resolved, checkpoint,
};

pub(super) fn resolve<W: Read + Write + Seek>(
    scratch: &mut Scratch<'_, W>,
    base: Resolved,
    program: &[u8],
    format: GitHashAlgorithm,
    depth: usize,
    limits: &BundleVerifyLimits,
    budget: &mut ResolutionBudget,
    live: &mut impl FnMut() -> bool,
) -> Result<Resolved, BundleVerifyError> {
    checkpoint(live)?;
    if base.kind != ObjectKind::Blob {
        return Err(BundleVerifyError::ResolutionIncomplete);
    }
    let mut delta_limits = limits.pack.clone();
    delta_limits.max_object_bytes = limits.max_streamed_blob_bytes;
    let mut io = StreamedDelta {
        scratch,
        base,
        format,
        limits: &delta_limits,
        index: None,
        append: None,
        native: None,
    };
    let result = apply_delta_streamed_to_charged_base_with_budget(
        base.span.length(),
        program,
        &delta_limits,
        budget,
        &mut io,
        live,
    );
    checkpoint(live)?;
    let length = result.map_err(|error| match error {
        StreamDeltaError::Pack(error) => BundleVerifyError::Pack(error),
        StreamDeltaError::Io(error) => error,
        StreamDeltaError::InvalidBaseRead { .. } => BundleVerifyError::ScratchChanged,
    })?;
    let append = io
        .append
        .take()
        .ok_or(BundleVerifyError::ResolutionIncomplete)?;
    let span = io.scratch.finish_append(append, live)?;
    if span.length() != length {
        return Err(BundleVerifyError::ScratchChanged);
    }
    let id = io
        .native
        .take()
        .ok_or(BundleVerifyError::ResolutionIncomplete)?
        .finish()?;
    checkpoint(live)?;
    Ok(Resolved {
        id,
        kind: ObjectKind::Blob,
        span,
        depth,
    })
}

struct StreamedDelta<'scratch, 'file, 'limits, W> {
    scratch: &'scratch mut Scratch<'file, W>,
    base: Resolved,
    format: GitHashAlgorithm,
    limits: &'limits PackLimits,
    index: Option<IndexedSpan>,
    append: Option<Append>,
    native: Option<NativeEntryHash>,
}

impl<W: Read + Write + Seek> DeltaStreamIo for StreamedDelta<'_, '_, '_, W> {
    type Error = BundleVerifyError;

    fn begin_result(
        &mut self,
        length: usize,
        deadline: &mut impl Deadline,
    ) -> Result<(), Self::Error> {
        let mut live = || deadline.checkpoint();
        checkpoint(&mut live)?;
        if self.index.is_some() || self.append.is_some() || self.native.is_some() {
            return Err(BundleVerifyError::ResolutionIncomplete);
        }
        let mut native =
            NativeEntryHash::new(self.format, ObjectKind::Blob, self.base.span.length());
        let index = self.scratch.index_span(
            self.base.span,
            self.limits.max_object_bytes,
            &mut |bytes| native.update(bytes),
            &mut live,
        )?;
        if native.finish()? != self.base.id {
            return Err(BundleVerifyError::ScratchChanged);
        }
        self.index = Some(index);
        self.append = Some(self.scratch.begin_append(length, &mut live)?);
        self.native = Some(NativeEntryHash::new(self.format, ObjectKind::Blob, length));
        checkpoint(&mut live)
    }

    fn read_base(
        &mut self,
        offset: usize,
        output: &mut [u8],
        budget: &mut ResolutionBudget,
        deadline: &mut impl Deadline,
    ) -> Result<usize, Self::Error> {
        let index = self
            .index
            .as_mut()
            .ok_or(BundleVerifyError::ResolutionIncomplete)?;
        self.scratch
            .read_indexed(index, offset, output, budget, self.limits, &mut || {
                deadline.checkpoint()
            })
    }

    fn write_result(
        &mut self,
        bytes: &[u8],
        deadline: &mut impl Deadline,
    ) -> Result<(), Self::Error> {
        let mut live = || deadline.checkpoint();
        let append = self
            .append
            .as_mut()
            .ok_or(BundleVerifyError::ResolutionIncomplete)?;
        self.scratch.resume_append(append, &mut live)?;
        self.scratch.append_chunk(append, bytes, &mut live)?;
        self.native
            .as_mut()
            .ok_or(BundleVerifyError::ResolutionIncomplete)?
            .update(bytes)?;
        checkpoint(&mut live)
    }
}
