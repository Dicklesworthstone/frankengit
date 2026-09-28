//! Socket I/O bounded by one accepted or native response-phase deadline.
//!
//! SSH wire/control bytes never purchase Git ingress time. Only bytes delivered
//! by SshReader to the native Git parser are charged to its work allowance.

use super::{GitDaemonSessionDeadline, Read, TcpStream, Write, io};
use std::time::Duration;

const HANDSHAKE_IDLE: Duration = Duration::from_secs(60);

pub(super) fn read(
    stream: &mut TcpStream,
    deadline: &GitDaemonSessionDeadline,
    buf: &mut [u8],
) -> io::Result<usize> {
    read_with_idle_limit(stream, deadline, buf, None)
}

pub(super) fn read_handshake(
    stream: &mut TcpStream,
    deadline: &GitDaemonSessionDeadline,
    buf: &mut [u8],
) -> io::Result<usize> {
    read_with_idle_limit(stream, deadline, buf, Some(HANDSHAKE_IDLE))
}

fn read_with_idle_limit(
    stream: &mut TcpStream,
    deadline: &GitDaemonSessionDeadline,
    buf: &mut [u8],
    idle: Option<Duration>,
) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    loop {
        let remaining = deadline.remaining()?;
        stream.set_read_timeout(Some(idle.map_or(remaining, |limit| remaining.min(limit))))?;
        match stream.read(buf) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => {
                deadline.remaining()?;
                return result;
            }
        }
    }
}

pub(super) fn write_all(
    stream: &mut TcpStream,
    deadline: &GitDaemonSessionDeadline,
    bytes: &[u8],
) -> io::Result<()> {
    write_all_with_idle_limit(stream, deadline, bytes, None)
}

pub(super) fn write_all_handshake(
    stream: &mut TcpStream,
    deadline: &GitDaemonSessionDeadline,
    bytes: &[u8],
) -> io::Result<()> {
    write_all_with_idle_limit(stream, deadline, bytes, Some(HANDSHAKE_IDLE))
}

fn write_all_with_idle_limit(
    stream: &mut TcpStream,
    deadline: &GitDaemonSessionDeadline,
    mut bytes: &[u8],
    idle: Option<Duration>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let remaining = deadline.remaining()?;
        stream.set_write_timeout(Some(idle.map_or(remaining, |limit| remaining.min(limit))))?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "SSH socket stopped accepting output",
                ));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    let remaining = deadline.remaining()?;
    stream.set_write_timeout(Some(idle.map_or(remaining, |limit| remaining.min(limit))))?;
    stream.flush()?;
    deadline.remaining()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitDaemonSessionTimeout, GitDaemonSessionWorkScaling};
    use std::net::TcpListener;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        client.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        (client, server)
    }

    fn budget(timeout: Duration) -> GitDaemonSessionDeadline {
        GitDaemonSessionDeadline::new(
            GitDaemonSessionTimeout::try_new(timeout).unwrap(),
            GitDaemonSessionWorkScaling::FLAT,
        )
    }

    #[test]
    fn an_expired_accepted_deadline_never_reads_or_writes_even_with_ready_bytes() {
        let (mut client, mut server) = pair();
        client.write_all(b"queued").unwrap();
        let mut expired = budget(Duration::from_millis(1));
        expired.started = Instant::now() - Duration::from_secs(1);
        let mut input = [0u8; 6];
        assert_eq!(
            read(&mut server, &expired, &mut input).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(
            write_all(&mut server, &expired, b"refused").unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );

        let live = budget(Duration::from_secs(5));
        let mut received = 0;
        while received < input.len() {
            let n = read(&mut server, &live, &mut input[received..]).unwrap();
            assert_ne!(n, 0);
            received += n;
        }
        assert_eq!(&input, b"queued");
        write_all(&mut server, &live, b"response").unwrap();
        let mut response = [0u8; 8];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"response");
    }

    #[test]
    fn wire_traffic_does_not_charge_or_restart_the_git_deadline() {
        let (mut client, mut server) = pair();
        let mut deadline = budget(Duration::from_secs(5));
        let started = deadline.started;
        client.write_all(&[7u8; 32]).unwrap();
        let mut input = [0u8; 32];
        let mut received = 0;
        while received < input.len() {
            let n = read(&mut server, &deadline, &mut input[received..]).unwrap();
            assert_ne!(n, 0);
            received += n;
        }
        assert_eq!(deadline.started, started);
        assert_eq!(deadline.shared.admitted_bytes.load(Ordering::Relaxed), 0);

        client.write_all(b"x").unwrap();
        deadline.started = Instant::now() - Duration::from_secs(10);
        assert_eq!(
            read(&mut server, &deadline, &mut input).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn authenticated_io_allows_long_git_work_while_handshake_idle_remains_short() {
        let (mut client, mut server) = pair();
        let deadline = budget(Duration::from_secs(300));
        let mut byte = [0u8; 1];
        client.write_all(b"a").unwrap();
        assert_eq!(read(&mut server, &deadline, &mut byte).unwrap(), 1);
        assert!(server.read_timeout().unwrap().unwrap() > Duration::from_secs(60));
        write_all(&mut server, &deadline, b"b").unwrap();
        assert!(server.write_timeout().unwrap().unwrap() > Duration::from_secs(60));
        client.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"b");

        client.write_all(b"c").unwrap();
        assert_eq!(read_handshake(&mut server, &deadline, &mut byte).unwrap(), 1);
        assert!(server.read_timeout().unwrap().unwrap() <= Duration::from_secs(60));
        write_all_handshake(&mut server, &deadline, b"d").unwrap();
        assert!(server.write_timeout().unwrap().unwrap() <= Duration::from_secs(60));
        client.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"d");
        assert_eq!(deadline.shared.admitted_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn a_silent_socket_wait_is_bounded_by_the_absolute_deadline() {
        let (_client, mut server) = pair();
        let deadline = budget(Duration::from_millis(40));
        let started = Instant::now();
        let error = read(&mut server, &deadline, &mut [0u8; 1]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
    }
}
