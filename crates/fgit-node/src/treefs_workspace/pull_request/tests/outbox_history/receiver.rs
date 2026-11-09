#![forbid(unsafe_code)]
//! A synced receiver owns only transport receipts; production admission owns
//! every claim, acknowledgement and active-outbox removal under test.

use super::*;
use fgit_admission::merge::native::settlement::DeliveryRequest;
use fgit_resource::DownstreamIdempotency;
use fgit_resource::settlement::{DeliveryVerdict, ProbeVerdict};
use std::future::Future;

pub(super) struct ReceiptDestination {
    root: PathBuf,
}

impl ReceiptDestination {
    pub(super) fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub(super) fn receipt(&self, key: AsciiSlug) -> Vec<u8> {
        fs::read(self.root.join(key.to_string())).unwrap()
    }

    fn bytes(&self, request: &DeliveryRequest<'_>) -> Result<Vec<u8>, RefusalCode> {
        if request.destination != self.destination() {
            return Err(RefusalCode::PublicationPolicyRefused);
        }
        if fgit_admission::evidence::evidence_root(request.events)? != request.payload_root {
            return Err(RefusalCode::EvidenceInvalid);
        }
        fgit_codec::encode_body(request.events).map_err(|_| RefusalCode::CanonicalFramingInvalid)
    }

    fn sync_directory(&self) -> Result<(), RefusalCode> {
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| RefusalCode::EvidenceMissing)
    }
}

fn deferred_once<T>(work: impl FnOnce() -> T + Send) -> impl Future<Output = T> + Send {
    let mut work = Some(work);
    std::future::poll_fn(move |_| match work.take() {
        Some(work) => std::task::Poll::Ready(work()),
        None => std::task::Poll::Pending,
    })
}

impl OutboxDestination<Cx> for ReceiptDestination {
    fn destination(&self) -> AsciiSlug {
        AsciiSlug::from_static("forge-projection")
    }

    fn idempotency(&self) -> DownstreamIdempotency {
        DownstreamIdempotency::Strong
    }

    fn probe<'a>(
        &'a mut self,
        _cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
    ) -> impl Future<Output = Result<(ProbeVerdict, Vec<u8>), RefusalCode>> + Send + 'a {
        deferred_once(move || {
            let expected = self.bytes(request)?;
            match fs::read(self.root.join(request.key.to_string())) {
                Ok(bytes) if bytes == expected => {
                    self.sync_directory()?;
                    Ok((ProbeVerdict::Delivered, b"synced metadata receipt".to_vec()))
                }
                Ok(_) => Err(RefusalCode::EvidenceInvalid),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Ok((ProbeVerdict::NotDelivered, Vec::new()))
                }
                Err(_) => Err(RefusalCode::EvidenceMissing),
            }
        })
    }

    fn deliver<'a>(
        &'a mut self,
        _cx: &'a Cx,
        request: &'a DeliveryRequest<'_>,
        _attempt: u32,
    ) -> impl Future<Output = Result<(DeliveryVerdict, Vec<u8>), RefusalCode>> + Send + 'a {
        deferred_once(move || {
            use std::io::Write;
            let bytes = self.bytes(request)?;
            fs::create_dir_all(&self.root).map_err(|_| RefusalCode::EvidenceMissing)?;
            fs::File::open(self.root.parent().ok_or(RefusalCode::EvidenceMissing)?)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| RefusalCode::EvidenceMissing)?;
            let staging = self
                .root
                .join(format!(".pending-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&staging)
                .map_err(|_| RefusalCode::EvidenceMissing)?;
            let result = (|| {
                file.write_all(&bytes)
                    .map_err(|_| RefusalCode::EvidenceMissing)?;
                file.sync_all().map_err(|_| RefusalCode::EvidenceMissing)?;
                let target = self.root.join(request.key.to_string());
                match fs::hard_link(&staging, &target) {
                    Ok(()) => Ok(DeliveryVerdict::Accepted),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        if fs::read(&target).map_err(|_| RefusalCode::EvidenceMissing)? == bytes {
                            Ok(DeliveryVerdict::DuplicateSuppressed)
                        } else {
                            Err(RefusalCode::EvidenceInvalid)
                        }
                    }
                    Err(_) => Err(RefusalCode::EvidenceMissing),
                }
            })();
            drop(file);
            fs::remove_file(&staging).map_err(|_| RefusalCode::EvidenceMissing)?;
            self.sync_directory()?;
            Ok((result?, b"synced metadata receipt".to_vec()))
        })
    }
}
