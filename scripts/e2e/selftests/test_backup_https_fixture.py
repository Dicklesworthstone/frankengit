#!/usr/bin/env python3
"""Real TLS listener ownership through actual campaign-journal failures.

No native forge is executed or simulated. Retain test directories and command
streams for diagnosis; emergency cleanup reaps only this test's fixture owner.
"""
from __future__ import annotations

from http.client import HTTPSConnection
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import unittest

E2E = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(E2E))
from operator_backup_https import ObjectFixture, USER_AGENT
from scoped_events_smoke import Campaign


class BackupHttpsFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="fg-backup-https-owners-", dir=os.environ.get("FGE_ARTIFACT_ROOT")))
        cls.key, cls.certificate = cls.root / "key.pem", cls.root / "ca.pem"
        command = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(cls.key), "-out", str(cls.certificate)]
        with (cls.root / "certificate.stdout").open("wb") as out, (cls.root / "certificate.stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=20, check=False)
        if result.returncode:
            raise RuntimeError(f"test-only TLS certificate failed; see {cls.root / 'certificate.stderr'}")
        print(f"retained HTTPS owner selftest artifacts: {cls.root}", file=sys.stderr)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="case-", dir=self.root))
        self.campaign = Campaign(Path("/unused-native"), self.work)
        self.fixture = ObjectFixture(self.campaign, self.work / "objects", self.certificate, self.key)
        self.addCleanup(self.emergency_cleanup)

    def emergency_cleanup(self):
        # Reference failures must not hang the test process or leave a listener.
        if self.fixture.thread.is_alive():
            self.fixture.shutdown()
            self.fixture.thread.join(timeout=3)
        self.fixture.server_close()
        self.assertFalse(self.fixture.thread.is_alive(), "test emergency owner drain failed")

    def assert_closed(self):
        self.assertFalse(self.fixture.thread.is_alive(), "HTTPS owner thread leaked")
        self.assertEqual(self.fixture.fileno(), -1, "HTTPS listener leaked")
        self.assertFalse(self.fixture.sockets, "HTTPS connection leaked")

    def test_startup_journal_failure_closes_listener_and_thread(self):
        # Exercise a real OS failure in the production Campaign.record path.
        # A failed __enter__ never receives an automatic __exit__ call.
        self.campaign.journal.mkdir(mode=0o700)
        with self.assertRaises(IsADirectoryError):
            with self.fixture:
                self.fail("failed startup journal admitted the fixture body")
        self.assert_closed()

    def test_permitted_startup_serves_real_tls_then_records_normal_drain(self):
        body = b"actual loopback TLS bytes\x00\xff"
        self.fixture.path("direct", "archive").write_bytes(body)
        with self.fixture:
            client = HTTPSConnection("127.0.0.1", self.fixture.server_port, timeout=3,
                context=ssl.create_default_context(cafile=str(self.certificate)))
            self.addCleanup(client.close)
            client.request("GET", self.fixture.url("direct", "archive").split(self.fixture.origin, 1)[1],
                           headers={"User-Agent": USER_AGENT})
            response = client.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), body)
            client.close()
        self.assert_closed()
        records = [json.loads(line) for line in self.campaign.journal.read_text().splitlines()]
        self.assertEqual([row["kind"] for row in records], ["https_fixture_start", "https_fixture_stop"])
        self.assertIs(records[-1]["drained"], True)
        self.assertEqual(records[-1]["active_sockets"], 0)
        self.assertFalse(records[-1]["failures"])

    def test_body_exception_preserves_original_error_and_closes_owner(self):
        with self.assertRaisesRegex(ValueError, "original body failure"):
            with self.fixture:
                raise ValueError("original body failure")
        self.assert_closed()

    def test_terminal_journal_failure_occurs_after_owner_drain(self):
        with self.assertRaises(IsADirectoryError):
            with self.fixture:
                self.campaign.journal.rename(self.work / "retained-start.jsonl")
                self.campaign.journal.mkdir(mode=0o700)
        self.assert_closed()


if __name__ == "__main__":
    os.umask(0o077)
    unittest.main(verbosity=2)
