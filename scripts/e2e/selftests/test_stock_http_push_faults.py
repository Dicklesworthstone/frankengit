#!/usr/bin/env python3
"""Real socket tests of the fault relay; no native engine proof is claimed."""
from pathlib import Path
import socket
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stock_http_push_faults import Relay


class LimitedReads:
    """Keep real socket I/O, with a legal smaller boundary for every recv."""

    def __init__(self, connection, maximum):
        self.connection, self.maximum = connection, maximum

    def recv(self, maximum):
        return self.connection.recv(min(maximum, self.maximum))

    def __getattr__(self, name):
        return getattr(self.connection, name)


class RelayTests(unittest.TestCase):
    def exchange(self, mode, maximum, target=b"/repo.git/git-receive-pack", *, truncated=False):
        request = b"POST " + target + b" HTTP/1.1"
        if not truncated:
            request += (b"\r\nHost: 127.0.0.1\r\n"
                        b"User-Agent: frankengit-agent\r\nContent-Length: 4\r\n\r\nbody")
        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        stop, served = threading.Event(), threading.Event()
        received, failures = bytearray(), []
        upstream = socket.create_server(("127.0.0.1", 0))
        upstream.settimeout(0.05)

        def answer():
            try:
                while not stop.is_set():
                    try:
                        connection, _ = upstream.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(2)
                        while len(received) < len(request):
                            data = connection.recv(len(request) - len(received))
                            if not data:
                                break
                            received.extend(data)
                        if len(received) == len(request):
                            connection.sendall(response)
                    return
            except OSError as error:
                if not stop.is_set():
                    failures.append(error)

        backend = threading.Thread(target=answer)
        backend.start()
        relay = Relay(upstream.getsockname()[1])
        relay.arm(mode)
        original = relay._serve

        def forward(connection):
            try:
                original(LimitedReads(connection, maximum))
            except BaseException as error:
                failures.append(error)
            finally:
                served.set()

        relay._serve = forward
        observed = bytearray()
        try:
            with socket.create_connection(("127.0.0.1", relay.port), timeout=2) as client:
                client.sendall(request)
                if truncated:
                    client.shutdown(socket.SHUT_WR)
                while True:
                    try:
                        data = client.recv(65536)
                    except ConnectionResetError:
                        break
                    if not data:
                        break
                    observed.extend(data)
            self.assertTrue(served.wait(2), "relay connection did not finish")
        finally:
            stop.set()
            relay.listener.shutdown(socket.SHUT_RDWR)
            relay.listener.close()
            backend.join(2)
            upstream.close()
        self.assertFalse(backend.is_alive(), "upstream fixture did not finish")
        self.assertEqual(failures, [])
        self.assertEqual(relay.mode, "pass" if relay.dropped else mode)
        return request, bytes(received), response, bytes(observed), relay.dropped

    def test_receive_drop_before_is_independent_of_recv_boundaries(self):
        for maximum in (1, 4, 31, 65536):
            with self.subTest(maximum=maximum):
                _, received, _, observed, dropped = self.exchange("drop_before_request", maximum)
                self.assertEqual((received, observed, dropped), (b"", b"", 1))

    def test_receive_drop_after_is_independent_of_recv_boundaries(self):
        for maximum in (1, 4, 31, 65536):
            with self.subTest(maximum=maximum):
                request, received, _, observed, dropped = self.exchange("drop_after_request", maximum)
                self.assertEqual((received, observed, dropped), (request, b"", 1))

    def test_permitted_pass_preserves_every_request_and_response_byte(self):
        for maximum in (1, 65536):
            with self.subTest(maximum=maximum):
                request, received, response, observed, dropped = self.exchange("pass", maximum)
                self.assertEqual((received, observed, dropped), (request, response, 0))

    def test_similar_service_names_do_not_consume_the_armed_drop(self):
        for mode in ("drop_before_request", "drop_after_request"):
            for target in (b"/repo.git/git-receive-pack-extra", b"/repo.git/git-upload-pack?git-receive-pack",
                           b"/repo.git/git-upload-pack?next=/git-receive-pack"):
                with self.subTest(mode=mode, target=target):
                    request, received, response, observed, dropped = self.exchange(mode, 65536, target)
                    self.assertEqual((received, observed, dropped), (request, response, 0))

    def test_incomplete_request_line_is_not_forwarded_or_counted_as_a_drop(self):
        _, received, _, _, dropped = self.exchange("drop_before_request", 1, truncated=True)
        self.assertEqual((received, dropped), (b"", 0))

    def test_overlong_request_line_is_not_forwarded_or_counted_as_a_drop(self):
        _, received, _, observed, dropped = self.exchange("drop_before_request", 4096, b"/" + b"x" * 65536)
        self.assertEqual((received, observed, dropped), (b"", b"", 0))

    def test_request_line_at_the_intake_bound_is_still_forwarded(self):
        target = b"/" + b"x" * (65536 - len(b"POST  HTTP/1.1\r\n") - 1)
        request, received, response, observed, dropped = self.exchange("drop_before_request", 4096, target)
        self.assertEqual((received, observed, dropped), (request, response, 0))


if __name__ == "__main__":
    unittest.main()
