//! Native adaptation of the runner's bounded pre-dispatch custody record.
use super::super::{TrustedWorkflowFailure, invalid, io};
pub(super) use fgit_runner::coordinator::delivery::journal::prestart::WatchPrestartIntent as Intent;
use fgit_runner::coordinator::delivery::journal::prestart::WatchPrestartRefusal;

impl From<WatchPrestartRefusal> for TrustedWorkflowFailure {
    fn from(error: WatchPrestartRefusal) -> Self {
        match error {
            WatchPrestartRefusal::Invalid(detail) => invalid(detail),
            WatchPrestartRefusal::Io(error) => io(error),
            WatchPrestartRefusal::Stopped => invalid("prestart intent verification stopped"),
        }
    }
}
