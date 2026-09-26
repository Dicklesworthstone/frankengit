//! SIGTERM and SIGINT as a drain request for a process that owns its
//! serving lifetime.
//!
//! Service managers stop a service with SIGTERM, and an operator's Ctrl-C is
//! SIGINT. Either used to end `fg serve-http --continuous` immediately, so
//! in-flight connections were cut rather than drained
//! (frankengit-root-doctrine-x2mv.4.8). Handlers are installed through the
//! runtime's own signal support (Asupersync), not a separate native shim.
//!
//! Installing the handlers changes what the process does on those signals:
//! from then on they no longer end it, and the owner must poll
//! [`TerminationSignals::requested`] and drain. A library entry point never
//! installs them; the `fg` process decides to.

use std::cell::{Cell, RefCell};
use std::future::Future;
use std::io;
use std::task::{Context, Poll, Waker};

use asupersync::signal::{Signal, sigint, sigterm};

/// Process-wide SIGTERM and SIGINT handlers, read as one latched stop request.
pub struct TerminationSignals {
    terminate: RefCell<Signal>,
    interrupt: RefCell<Signal>,
    requested: Cell<bool>,
}

impl std::fmt::Debug for TerminationSignals {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TerminationSignals")
            .field("requested", &self.requested.get())
            .finish_non_exhaustive()
    }
}

impl TerminationSignals {
    /// Installs the handlers. Only signals delivered after this call count.
    ///
    /// # Errors
    ///
    /// The platform cannot deliver these signals to the runtime; nothing is
    /// then installed, and the default disposition still ends the process.
    pub fn install() -> io::Result<Self> {
        Ok(Self {
            terminate: RefCell::new(sigterm()?),
            interrupt: RefCell::new(sigint()?),
            requested: Cell::new(false),
        })
    }

    /// Whether SIGTERM or SIGINT has arrived since installation. It never
    /// blocks, and once true it stays true: a second signal during the drain
    /// changes nothing.
    pub fn requested(&self) -> bool {
        if !self.requested.get() && (delivered(&self.terminate) || delivered(&self.interrupt)) {
            self.requested.set(true);
        }
        self.requested.get()
    }
}

/// One non-blocking look at a signal stream. `Signal::recv` is cancel-safe and
/// is ready at once when a delivery is pending, so dropping it unpolled again
/// loses nothing.
fn delivered(signal: &RefCell<Signal>) -> bool {
    let Ok(mut signal) = signal.try_borrow_mut() else {
        return false;
    };
    let mut next = std::pin::pin!(signal.recv());
    matches!(
        next.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(()))
    )
}
