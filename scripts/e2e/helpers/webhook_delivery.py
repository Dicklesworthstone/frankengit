"""Exercise a prebuilt fg with real HTTP, durable authority and cold processes.

No Cargo, substitute forge, exactly-once or canonical settlement claim. Python
independently checks the HMAC and payload against fg's canonical inspection.
"""
import argparse
import contextlib
import hashlib
import hmac
import http.server
import json
import pathlib
import socket
import subprocess
import sys
import threading

TENANT, REPOSITORY, PRINCIPAL = "1" * 32, "2" * 32, "3" * 32
SECRET = b"0123456789abcdef0123456789abcdef"
ROTATED = b"fedcba9876543210fedcba9876543210"


class Receiver:
    def __init__(self, transcript=None):
        self.records, self.status = [], 200
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self):
                self.request.settimeout(3)
                super().setup()

            def do_POST(self):
                size = int(self.headers.get("Content-Length", "-1"))
                if not 0 <= size <= 64 * 1024 * 1024:
                    self.send_error(413)
                    return
                body = self.rfile.read(size)
                if len(body) != size:
                    self.send_error(400)
                    return
                record = {"headers": dict(self.headers.items()),
                          "body": body, "status": owner.status}
                owner.records.append(record)
                if transcript is not None:
                    with transcript.open("a", encoding="utf-8") as output:
                        output.write(json.dumps({**record, "body_hex": body.hex(),
                                                 "body": None}) + "\n")
                self.send_response(owner.status)
                self.send_header("Content-Length", "2")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b"ok")

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook"
        self.worker = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05})
        self.worker.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=5)
        assert not self.worker.is_alive(), "receiver did not drain"

    def check(self, index, secret, inspected, attempt):
        record = self.records[index]
        headers = {key.lower(): value for key, value in record["headers"].items()}
        body = record["body"]
        expected = "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(headers["x-frankengit-signature-256"], expected)
        assert headers["x-frankengit-attempt"] == str(attempt)
        assert headers["x-frankengit-delivery"] == inspected["delivery_id"]
        assert headers["user-agent"].startswith("FrankenGit-Webhook/")
        payload = json.loads(body)
        assert payload["schema"] == "frankengit.webhook.v1"
        for field in ("delivery_id", "destination", "payload_root", "events_count", "events"):
            assert payload[field] == inspected[field], field
        assert len(payload["events"]) == payload["events_count"] == 1
        assert bytes.fromhex(payload["events"][0]["canonical_frame_hex"])
        return body


class Campaign:
    def __init__(self, fg, root):
        self.fg, self.root = str(pathlib.Path(fg).resolve(strict=True)), root
        self.counter, self.facts = 0, {}

    def run(self, label, args, expected=0):
        self.counter += 1
        stem = f"{self.counter:03d}-{label}"
        argv = [self.fg, "--timeout-secs", "120", *map(str, args)]
        result = subprocess.run(argv, capture_output=True, timeout=180, check=False)
        (self.root / f"{stem}.out").write_bytes(result.stdout)
        (self.root / f"{stem}.err").write_bytes(result.stderr)
        with (self.root / "commands.jsonl").open("a", encoding="utf-8") as journal:
            journal.write(json.dumps({"step": stem, "argv": argv,
                                      "exit_code": result.returncode}) + "\n")
        if result.stderr:
            sys.stderr.buffer.write(result.stderr)
            sys.stderr.buffer.flush()
        assert result.returncode == expected, (label, result.returncode, expected,
                                               result.stdout.decode(errors="replace"))
        return result.stdout

    def exercise(self, fmt):
        storage = self.root / f"node-{fmt}"
        scope = [storage, TENANT, REPOSITORY, "--trusted-local"]
        format_args = ["--object-format", fmt]

        def command(label, verb, extra=(), expected=0, formatted=True):
            return json.loads(self.run(f"{fmt}-{label}", ["webhook", *verb, *scope,
                              *extra, *(format_args if formatted else [])], expected))

        def register(identifier, url, permissive=True, expected=0):
            self.run(f"{fmt}-register-{identifier}", ["webhook", "register", *scope,
                     "--id", identifier, "--url", url, "--secret", SECRET.hex(),
                     *(["--permissive-for-tests"] if permissive else [])], expected)

        self.run(f"{fmt}-init", ["init", storage, TENANT, REPOSITORY, fmt])
        self.run(f"{fmt}-issue", ["issue", "open", *scope[:3], "1", "--trusted-local",
                 "--principal", PRINCIPAL, "--idempotency-key", f"webhook-{fmt}",
                 "--expected-version", "0", "--title", "A committed issue",
                 "--body", "Exact canonical bytes: \u03c0\n", *format_args])
        before = command("outbox", ["outbox"])
        assert before["node_closed"] and len(before["entries"]) == 1
        entry = before["entries"][0]
        selection = ["--delivery-id", entry["delivery_id"], "--destination", entry["destination"]]
        inspected = command("inspect", ["inspect"], selection)
        assert inspected["source_head"] == before["source_head"]
        assert inspected["node_closed"] and not inspected["sent"] and not inspected["settled"]
        with contextlib.ExitStack() as owned:
            receiver = Receiver(self.root / f"{fmt}-receiver.jsonl")
            owned.callback(receiver.close)
            for identifier, url in ((101, "http://169.254.169.254/latest/meta-data"),
                                    (102, "http://10.0.0.1/hook"), (103, receiver.url)):
                register(identifier, url, permissive=False, expected=2)
            register(1, receiver.url)
            registrations = command("list", ["list"], formatted=False)
            assert any(row["id"] == 1 for row in registrations["webhooks"])
            self.facts[f"{fmt}_ssrf_twins"] = True
            selected = ["--id", "1", *selection, "--permissive-for-tests"]
            self.run(f"{fmt}-missing-consent", ["webhook", "deliver", *scope,
                     *selected, *format_args], 2)
            for ordinal in (0, 17):
                self.run(f"{fmt}-ordinal-{ordinal}", ["webhook", "deliver", *scope,
                         *selected, "--at-least-once", "--attempt", ordinal, *format_args], 2)
            assert not receiver.records, "refused delivery reached receiver"
            selected += ["--at-least-once"]
            first = command("deliver", ["deliver"], [*selected, "--attempt", "1"])
            assert first["verdict"] == "Accepted" and first["node_closed"]
            assert not first["canonical_settled"] and not first["automatic_retry"]
            body = receiver.check(0, SECRET, inspected, 1)
            command("rotate", ["rotate"], ["--id", "1", "--new-secret", ROTATED.hex(),
                    "--window-secs", "3600"], formatted=False)
            second = command("deliver-retry", ["deliver"], [*selected, "--attempt", "2"])
            assert second["verdict"] == "Accepted", "2xx is not duplicate suppression"
            assert receiver.check(1, ROTATED, inspected, 2) == body
            self.facts[f"{fmt}_canonical_hmac_rotation"] = True
            self.facts[f"{fmt}_refusal_before_send"] = True

            # Retain a bound, non-listening port throughout the refusal drill.
            down = owned.enter_context(socket.socket())
            down.bind(("127.0.0.1", 0))
            register(4, f"http://127.0.0.1:{down.getsockname()[1]}/hook")
            failed = ["--id", "4", *selection, "--at-least-once", "--permissive-for-tests"]
            transient = command("down-first", ["deliver"], [*failed, "--attempt", "1"], 1)
            terminal = command("down-final", ["deliver"], [*failed, "--attempt", "5"], 2)
            assert transient["verdict"] == "TransientFailure"
            assert terminal["verdict"] == "PermanentRejection"
            self.run(f"{fmt}-replay-reset", ["webhook", "dead-letter", "replay", *scope,
                     *failed, "--attempt", "1", *format_args], 2)
            replay = command("down-replay", ["dead-letter", "replay"], failed, 2)
            assert replay["replay"] and replay["attempt"] == 6 and not replay["canonical_settled"]
            letters = command("dead-letters", ["dead-letter", "list"], formatted=False)
            assert any(row["webhook_id"] == 4 and row["delivery_id"] == entry["delivery_id"]
                       and row["attempts"] == 6 for row in letters["dead_letters"])
            self.facts[f"{fmt}_down_retry_dead_letter"] = True

            register(5, receiver.url)
            receiver.status = 503
            rejected = ["--id", "5", *selection, "--at-least-once", "--permissive-for-tests"]
            result = command("http-final", ["deliver"], [*rejected, "--attempt", "5"], 2)
            assert result["verdict"] == "PermanentRejection"
            receiver.check(2, SECRET, inspected, 5)
            receiver.status = 200
            result = command("http-replay", ["dead-letter", "replay"], rejected)
            assert result["replay"] and result["attempt"] == 6 and result["diagnostic_retained"]
            assert result["verdict"] == "Accepted" and not result["canonical_settled"]
            receiver.check(3, SECRET, inspected, 6)
            self.facts[f"{fmt}_live_replay"] = True

            register(2, receiver.url)
            register(3, receiver.url)
            fanout = ["webhook", "dispatch", "fanout", *scope,
                      "--route", f"2:{entry['destination']}", "--route", f"3:{entry['destination']}",
                      "--at-least-once", "--permissive-for-tests", *format_args]

            def sweep(label, extra, expected):
                raw = self.run(f"{fmt}-{label}", [*fanout, *extra], expected)
                records = [json.loads(line) for line in raw.splitlines()]
                assert records and all(row["canonical_settled"] is False for row in records)
                assert records[-1]["type"] == "webhook_fanout_sweep"
                return records[-1]

            limited = sweep("fanout-one", ["--max-total-deliveries", "1"], 1)
            assert limited["attempts"] == limited["accepted"] == 1 and limited["pending"] == 1
            assert len(receiver.records) == 5
            resumed = sweep("fanout-resume", [], 0)
            # Accepted includes retained successes; attempts counts new sends.
            assert resumed["attempts"] == 1 and resumed["accepted"] == 2
            assert len(receiver.records) == 6
            receiver.check(4, SECRET, inspected, 1)
            receiver.check(5, SECRET, inspected, 1)
            restarted = sweep("fanout-restart", [], 0)
            assert restarted["attempts"] == 0 and restarted["accepted"] == 2
            assert len(receiver.records) == 6
            self.facts[f"{fmt}_fanout_restart_budget"] = True
            assert command("outbox-after", ["outbox"]) == before, "canonical state changed"
            self.facts[f"{fmt}_canonical_unsettled"] = True
            (self.root / f"{fmt}-receiver.json").write_text(json.dumps([
                {**record, "body": record["body"].decode("utf-8")}
                for record in receiver.records], indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fg", required=True)
    parser.add_argument("--work", required=True, type=pathlib.Path)
    parser.add_argument("--summary", required=True, type=pathlib.Path)
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=False)
    campaign, complete = Campaign(args.fg, args.work), False
    try:
        for fmt in ("sha1", "sha256"):
            campaign.exercise(fmt)
        complete = True
    finally:
        args.summary.write_text(json.dumps({"complete": complete, "facts": campaign.facts,
                                           "commands": campaign.counter}, indent=2) + "\n",
                                encoding="utf-8")


if __name__ == "__main__":
    main()
