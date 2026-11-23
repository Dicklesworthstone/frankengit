//! SSH protocol progress while the authenticated Git service is computing.
//! Keep application bytes in the session's receive window until Git reads them.

use super::*;

impl SshConnectionState {
    /// At most one bounded input burst and two nonblocking writes per liveness
    /// probe. Pending ciphertext precedes any newer packet, including final EOF.
    pub(super) fn poll_upload_connection(&mut self) -> bool {
        if self.deadline.expired() || self.stream.set_nonblocking(true).is_err() {
            return false;
        }
        let result = self.service_ready_upload_input();
        self.stream.set_nonblocking(false).is_ok() && result.unwrap_or(false)
    }

    fn service_ready_upload_input(&mut self) -> io::Result<bool> {
        if !self.write_ready_work_output()? {
            return Ok(true);
        }
        // Even a stream of tiny protocol messages can consume only one burst
        // per probe. The SSH parser bounds incomplete packets and the channel
        // receive window bounds Git bytes outstanding across probes.
        let mut wire = [0u8; 4096];
        match self.stream.read(&mut wire) {
            Ok(0) => return Ok(false),
            Ok(n) => self
                .session
                .handle_incoming_bytes(&wire[..n])
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return Ok(true);
            }
            Err(err) => return Err(err),
        }
        self.work_output = io::Cursor::new(self.session.take_outgoing_bytes());
        self.write_ready_work_output()?;
        Ok(!self.session.is_channel_closed() && self.session.phase() != &SessionPhase::Closed)
    }

    fn write_ready_work_output(&mut self) -> io::Result<bool> {
        let pending = self.work_output.fill_buf()?;
        if pending.is_empty() {
            return Ok(true);
        }
        match self.stream.write(pending) {
            Ok(0) => Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                self.work_output.consume(n);
                Ok(self.work_output.fill_buf()?.is_empty())
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }
}
