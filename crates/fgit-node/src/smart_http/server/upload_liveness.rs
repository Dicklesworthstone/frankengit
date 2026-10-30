//! Reset-aware cancellation for read-only HTTP upload-pack work.
//!
//! A client may finish its request with SHUT_WR and continue reading the pack.
//! An ordinary FIN cannot distinguish that client from an orderly full close,
//! so only a socket failure stops work here; the finite deadline still applies.

use std::net::TcpStream;

use crate::{ClientLiveness, tcp_peer_reachable};

/// Own the probe handle independently of the body reader and response writer.
/// The connection owner calls the callback synchronously between I/O steps.
/// The shared probe peeks without consuming bytes, restores blocking mode, and
/// runs at most once per 100 ms. A reset stays latched after the kernel reports
/// it, even if subsequent peeks would return only EOF.
pub(super) fn cancellation(stream: TcpStream) -> impl FnMut() -> bool {
    let client = ClientLiveness::new(move || Some(tcp_peer_reachable(&stream)));
    move || client.alive()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::time::{Duration, Instant};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        for stream in [&client, &server] {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
        }
        (client, server)
    }

    fn after_probe_interval() {
        std::thread::sleep(Duration::from_millis(120));
    }

    #[test]
    fn a_half_closed_http_request_still_receives_its_response() {
        let (mut client, mut server) = pair();
        let mut live = cancellation(server.try_clone().unwrap());
        client.write_all(b"0000").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut body = [0u8; 4];
        server.read_exact(&mut body).unwrap();
        assert_eq!(&body, b"0000");
        assert_eq!(server.read(&mut [0u8; 1]).unwrap(), 0);

        after_probe_interval();
        assert!(live(), "request EOF does not abandon the response");
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n0000";
        server.write_all(response).unwrap();
        server.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        client.read_to_end(&mut received).unwrap();
        assert_eq!(received, response);
    }

    #[test]
    fn a_reset_http_client_stops_work_and_cannot_become_live_again() {
        let (client, mut server) = pair();
        let mut live = cancellation(server.try_clone().unwrap());
        // Closing with unread incoming data produces a reset. Peek establishes
        // that the data arrived without consuming it or relying on a sleep.
        server.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").unwrap();
        assert_ne!(client.peek(&mut [0u8; 1]).unwrap(), 0);
        drop(client);
        let started = Instant::now();
        while live() {
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "reset did not stop upload work"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // Some kernels consume the reset indication on its first observation.
        // The owning callback must retain it across later work checkpoints.
        after_probe_interval();
        for _ in 0..100 {
            assert!(!live());
        }
    }

    #[test]
    fn upload_probes_preserve_pending_bytes_and_the_original_blocking_socket() {
        let (mut client, mut server) = pair();
        let mut live = cancellation(server.try_clone().unwrap());
        let pending = b"GET /next-request HTTP/1.1\r\n\r\n";
        client.write_all(pending).unwrap();
        after_probe_interval();
        assert!(live());
        let mut untouched = vec![0u8; pending.len()];
        server.read_exact(&mut untouched).unwrap();
        assert_eq!(untouched, pending, "the probe consumed queued input");
        after_probe_interval();
        assert!(live(), "a silent peer can still receive its pack");

        // Nonblocking mode is shared by cloned descriptors. The next ordinary
        // read must wait for data instead of returning WouldBlock immediately.
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                client.write_all(b"x").unwrap();
            });
            let mut byte = [0u8; 1];
            server.read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"x");
        });
    }
}
