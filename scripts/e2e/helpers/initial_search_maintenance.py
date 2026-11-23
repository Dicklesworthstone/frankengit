"""Drive the dual index controller through the actual HTTP server lifecycle."""
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode, urlsplit

TENANT = "c1" * 16
REPOSITORY = "c2" * 16
PRINCIPAL = "c3" * 16
AGENT = "frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)"


@contextlib.contextmanager
def listening(binary, scope, work, fmt, mode, credentials):
    stop = work / (mode + ".stop")
    out = work / (mode + ".out")
    err = work / (mode + ".err")
    args = [binary, "serve-http", *scope, "127.0.0.1:0", "--trusted-local", "--credentials-file", credentials,
            "--allow-source", "--continuous", "--stop-file", stop, "--index-profile", "both",
            "--index-format", fmt, "--index-state", mode, "--index-state-dir", work / "lexical",
            "--index-symbol-state-dir", work / "symbols", "--index-ref", "refs/heads/main",
            "--index-interval-secs", "1"]
    with out.open("xb") as stdout, err.open("xb") as stderr:
        server = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                if server.poll() is not None:
                    raise RuntimeError(err.read_text(errors="replace"))
                rows = (json.loads(line) for line in out.read_bytes().splitlines() if line.endswith(b"}"))
                ready = next((row for row in rows if row.get("type") == "smart_http_listening"), None)
                if ready:
                    endpoint = urlsplit(ready["url"])
                    assert endpoint.hostname == "127.0.0.1" and endpoint.path == "/" + REPOSITORY + ".git"
                    yield endpoint
                    break
                time.sleep(0.05)
            else:
                raise TimeoutError("HTTP readiness")
        finally:
            stop.touch()
            try:
                code = server.wait(timeout=40)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
                raise
            if code and sys.exc_info()[0] is None:
                raise RuntimeError(f"HTTP exit {code}: {err.read_text(errors='replace')}")
    for name in ("lexical", "symbols"):
        assert (work / name / "checkpoint").is_file()
        assert not (work / name / "run.lock").exists()


def query(endpoint, token, fmt, word, *, route="search-initial", **limits):
    body = urlencode({"ref": "refs/heads/main", "object_format": fmt, "term_hex": word.hex(),
                      "symbol_name_hex": word.hex(), "symbol_policy": "required", **limits})
    connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=10)
    try:
        connection.request("POST", endpoint.path + "/api/v1/source/" + route, body,
                           {"Authorization": "Bearer " + token, "User-Agent": AGENT,
                            "Content-Type": "application/x-www-form-urlencoded"})
        response = connection.getresponse()
        if route == "search-progressive" and response.status == 200:
            assert response.getheader("Content-Type") == "application/x-ndjson"
            assert response.getheader("Connection").lower() == "close"
            assert response.getheader("Cache-Control") == "no-store"
            assert response.getheader("Vary") == "Authorization"
            first, terminal, end = response.readline(), response.readline(), response.readline()
            assert first.endswith(b"\n") and terminal.endswith(b"\n") and end == b""
            return response.status, first + terminal
        return response.status, response.read()
    finally:
        connection.close()


def current(endpoint, token, fmt, word, expected_tip):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, body = query(endpoint, token, fmt, word)
        if status == 200:
            result = json.loads(body)
            assert result["complete"] and result["source_commit"] == expected_tip
            assert result["symbols"]["state"] == "available"
            assert result["content"]["hits"] and result["symbols"]["result"]["matches"]
            for row in result["symbols"]["result"]["matches"]:
                assert bytes.fromhex(row["name_hex"]) == word
                assert bytes.fromhex(row["path_hex"]).endswith(word + b".rs")
            assert result["authorization"]["host"] == "http-repository-read-credential"
            assert result["authorization"]["principal"] == PRINCIPAL
            assert not result["authorization"]["reusable_capability"]
            return result
        if status != 409:
            raise AssertionError((status, body[:500]))
        time.sleep(0.10)
    raise TimeoutError((status, body[:500]))


def main():
    binary, output, fmt, bare, original, updated = sys.argv[1:]
    work = Path(output)
    work.mkdir(mode=0o700)
    for directory in ("lexical", "symbols"):
        (work / directory).mkdir(mode=0o700)
    scope = [work / "node", TENANT, REPOSITORY]

    def fg(*args):
        subprocess.run([binary, *args], check=True, timeout=60)

    fg("init", *scope, fmt)
    imported = subprocess.run([binary, "import", *scope, PRINCIPAL, "initial-serving", bare, "--json"],
                              check=True, stdout=subprocess.PIPE, timeout=60)
    incarnation = json.loads(imported.stdout)["repository_incarnation_id"]
    reader, restricted = secrets.token_hex(32), secrets.token_hex(32)
    with tempfile.TemporaryDirectory(dir=work) as private:
        credentials = Path(private) / "credentials"
        grants = [(hashlib.sha256(value.encode()).hexdigest(), actor, grant) for value, actor, grant in
                  [(reader, PRINCIPAL, "read"), (restricted, "c4" * 16, "pulls-read")]]
        with os.fdopen(os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as stream:
            stream.write(f"frankengit-http-credentials-v1 {TENANT} {REPOSITORY} {incarnation}\n")
            for digest, actor, grant in sorted(grants):
                stream.write(f"{digest} {actor} {grant}\n")
        with listening(binary, scope, work, fmt, "init", credentials) as endpoint:
            first = current(endpoint, reader, fmt, b"Thing", original)
        fg("branch", "update", *scope, "--trusted-local", "--principal", PRINCIPAL,
           "--idempotency-key", "search-next", "--ref", "refs/heads/main", "--object-format", fmt,
           "--expected-tip", original, "--target", updated)
        with listening(binary, scope, work, fmt, "resume", credentials) as endpoint:
            status, denied = query(endpoint, restricted, fmt, b"NextThing")
            assert status == 403 and b"authorization_label" not in denied
            second = current(endpoint, reader, fmt, b"NextThing", updated)
            def progressive(token, word=b"NextThing", **limits):
                return query(endpoint, token, fmt, word, route="search-progressive", **limits)
            status, ranked_body = progressive(reader)
            assert status == 200, (status, ranked_body)
            initial, refined = map(json.loads, ranked_body.splitlines())
            assert initial == {"phase": "Initial", "answer": second}
            assert refined["phase"] == "Refined" and refined["answer"]["retrieval"] == second
            status, limited_body = progressive(reader, context_max_source_bytes=1)
            assert status == 200
            kept, oversized = map(json.loads, limited_body.splitlines())
            assert kept == initial and oversized == {"phase": "RefinementFailed", "code": "resource_limit"}, oversized
            # A single selected file exceeds its one-byte read allowance. For
            # several selected files the same budget gives a zero-byte share.
            original_hits = current(endpoint, reader, fmt, b"Thing", updated)
            status, exhausted_body = progressive(reader, b"Thing", context_max_source_bytes=1)
            assert status == 200
            saved_initial, failed = map(json.loads, exhausted_body.splitlines())
            assert saved_initial == {"phase": "Initial", "answer": original_hits}
            assert failed == {"phase": "RefinementFailed", "code": "resource_limit"}
            denied_status, denied_body = progressive(restricted)
            early_status, early_body = progressive(reader, max_work=32)
            assert denied_status == 403 and early_status == 413
            for refused in (denied_body, early_body):
                assert b'"phase"' not in refused and b'authorization_label' not in refused
        assert first["snapshot_token"] != second["snapshot_token"]
        assert first["content"]["index_token"] != second["content"]["index_token"]
        assert first["symbols"]["result"]["index_token"] != second["symbols"]["result"]["index_token"]
    print(json.dumps({"format": fmt, "initial_tip": original, "resumed_tip": updated,
                      "reader": 200, "restricted_reader": denied_status, "progressive": ["Initial", "Refined", "RefinementFailed"], "controllers_drained": 2}))


if __name__ == "__main__":
    main()
