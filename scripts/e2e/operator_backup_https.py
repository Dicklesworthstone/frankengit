#!/usr/bin/env python3
"""Native signed backup bytes through shipped HTTPS operators and Rust restore.

The disk-backed loopback object service is a transport fixture, not a forge,
cloud provider or physical durability oracle. Original diagnostic bytes survive.
"""
from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
from secrets import token_urlsafe
import signal
import socket
import ssl
import subprocess
import sys
import threading
from urllib.parse import parse_qs, urlsplit

from operator_backup_smoke import FILES, KEYGEN, REF
from operator_backup_jobs import snapshot
from operator_issue_smoke import OperatorCampaign
from operator_workspace_smoke import file_tree
from patch_smoke import loose, oid
from scoped_events_smoke import PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
USER_AGENT = "frankengit-agent (+https://github.com/Dicklesworthstone/frankengit)"
# A fresh fixture capability also acts as the client-output redaction canary.
CAPABILITY = token_urlsafe(24)
ENTRYPOINTS = ("upload_repository_backup.mjs", "repository_backup_upload_job.mjs",
               "download_repository_backup.mjs", "recover_repository_backup.mjs")
PROPERTIES = ("signed_native_archive", "direct_upload_pin_budget_and_exact_retry",
    "sealed_source_custody_without_network", "job_policy_target_budget_refusals",
    "lost_approval_response_retains_partial_completion", "renewed_capabilities_reuse_without_put",
    "download_trust_checkpoint_and_corrupt_mirror_twins", "downloaded_native_restore",
    "https_recovery_then_offline_cache_resume", "redacted_capabilities_and_fixture_drain")
FACTS = tuple(f"{fmt}_{name}" for fmt in ("sha1", "sha256") for name in PROPERTIES)


class ObjectFixture(HTTPServer):
    """Bounded sequential TLS fixture. Bytes live in files, never a success map."""

    def __init__(self, c, directory, certificate, key):
        self.c, self.directory = c, directory
        self.events, self.failures, self.sockets = [], [], set()
        self.lose_approval = None
        directory.mkdir(mode=0o700)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        self.context = context
        super().__init__(("127.0.0.1", 0), ObjectHandler)
        self.origin = f"https://127.0.0.1:{self.server_port}"
        self.thread = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.05})

    def get_request(self):
        raw, address = super().get_request()
        raw.settimeout(2)
        try:
            secured = self.context.wrap_socket(raw, server_side=True)
        except BaseException:
            raw.close()
            raise
        self.sockets.add(secured)
        return secured, address

    def shutdown_request(self, request):
        try:
            super().shutdown_request(request)
        finally:
            self.sockets.discard(request)

    def handle_error(self, request, client_address):
        self.failures.append(type(sys.exception()).__name__)
        super().handle_error(request, client_address)

    def path(self, namespace, kind):
        return self.directory / f"{namespace}-{kind}"

    def url(self, namespace, kind, method="read", version=1):
        return f"{self.origin}/{namespace}/{kind}?cap={CAPABILITY}-{method}-{version}"

    def target(self, namespace, version=1):
        return {kind: {"get": self.url(namespace, kind, "read", version),
                       "put": self.url(namespace, kind, "write", version)} for kind in ("archive", "approval")}

    def __enter__(self):
        self.thread.start()
        self.c.record(kind="https_fixture_start", port=self.server_port, service_class="loopback_transport_fixture")
        return self

    def __exit__(self, kind, error, traceback):
        # shutdown waits for the bounded current handler, then the owner thread
        # joins. No process kill, detached listener or arbitrary drain sleep.
        handlers = {}
        try:
            if threading.current_thread() is threading.main_thread():
                for number in (signal.SIGTERM, signal.SIGINT):
                    handlers[number] = signal.signal(number, signal.SIG_IGN)
            self.shutdown()
            self.thread.join(timeout=3)
            self.server_close()
            drained = not self.thread.is_alive() and not self.sockets and not self.failures
            self.c.record(kind="https_fixture_stop", port=self.server_port, drained=drained,
                          active_sockets=len(self.sockets), failures=self.failures)
            (self.directory / "requests.json").write_text(json.dumps(self.events, indent=2) + "\n")
            require(drained, "loopback HTTPS fixture failed to quiesce")
        finally:
            for number, handler in handlers.items():
                signal.signal(number, handler)


class ObjectHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *args):
        pass  # Never print a capability-bearing request line.

    def reply(self, code, body=b""):
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def locate(self):
        parsed = urlsplit(self.path)
        pieces = parsed.path.split("/")
        if len(pieces) != 3 or pieces[1] not in ("direct", "job-a", "job-b", "corrupt") or pieces[2] not in ("archive", "approval"):
            self.reply(404)
            return None
        expected = "read" if self.command == "GET" else "write"
        token = parse_qs(parsed.query).get("cap", [])
        require(self.headers.get("User-Agent") == USER_AGENT, "operator used an unexpected User-Agent")
        require(len(token) == 1 and token[0] in (f"{CAPABILITY}-{expected}-1", f"{CAPABILITY}-{expected}-2"), "fixture capability mismatch")
        self.server.events.append({"method": self.command, "path": parsed.path,
            "user_agent": self.headers.get("User-Agent"), "conditional": self.headers.get("If-None-Match"),
            "expect": self.headers.get("Expect")})
        return pieces[1], pieces[2]

    def do_GET(self):
        pair = self.locate()
        if pair is not None:
            path = self.server.path(*pair)
            self.reply(200, path.read_bytes()) if path.exists() else self.reply(404)

    def do_PUT(self):
        pair = self.locate()
        if pair is None:
            return
        require(self.headers.get("If-None-Match") == "*" and self.headers.get("Expect") == "100-continue",
                "fixture requires conditional writes with explicit Continue")
        length = int(self.headers["Content-Length"])
        require(0 < length <= 1024 * 1024, "fixture PUT body outside its fixed bound")
        path = self.server.path(*pair)
        if path.exists():
            self.reply(412)
            return
        body = self.rfile.read(length)
        require(len(body) == length, "fixture received a truncated body")
        with path.open("xb") as out:
            out.write(body)
            out.flush()
            os.fsync(out.fileno())
        if self.server.lose_approval == pair:
            self.server.lose_approval = None
            self.server.events[-1]["response_lost"] = True
            self.close_connection = True
            self.connection.shutdown(socket.SHUT_RDWR)
            return
        self.reply(201)


def run_case(c, oracle, fmt, certificate, tls_key):
    home = c.work / fmt
    home.mkdir(mode=0o700)
    source, repository, exports, retained = (home / name for name in ("git-source", "repository", "exports", "retained"))
    exports.mkdir(mode=0o700)
    retained.mkdir(mode=0o700)
    (source / "refs/heads").mkdir(parents=True)
    (source / "HEAD").write_text(f"ref: {REF}\n")
    (source / "config").write_text("[core]\nbare=true\nrepositoryformatversion=" +
        ("0\n" if fmt == "sha1" else "1\n[extensions]\nobjectformat=sha256\n"))
    tree, _ = file_tree(fmt, FILES, lambda kind, body: loose(source, fmt, kind, body))
    tip = loose(source, fmt, "commit", (f"tree {tree}\n"
        "author HTTPS Backup <backup@example.invalid> 1 +0000\n"
        "committer HTTPS Backup <backup@example.invalid> 1 +0000\n\nHTTPS backup\n").encode())
    (source / REF).write_text(tip + "\n")
    check = [str(ROOT / "scripts/e2e/oracle/oracle.sh"), "capture", "git-2.54.0", str(oracle),
        str(source.relative_to(oracle / "work")), fmt + "-https-fsck", "--", "fsck", "--full", "--strict", "--no-reflogs"]
    with (home / "oracle.stdout").open("wb") as out, (home / "oracle.stderr").open("wb") as err:
        result = subprocess.run(check, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=30, check=False)
    c.record(kind="pinned_git_fixture_check", command=check, exit=result.returncode)
    require(result.returncode == 0, f"pinned Git rejected source; see {home / 'oracle.stderr'}")
    c.run("init", repository, TENANT, REPOSITORY, fmt)
    c.run("import", repository, TENANT, REPOSITORY, PRINCIPAL, "https-backup-import", source)
    c.issue(repository, fmt, 0, "https-backup-open", "native HTTPS recovery issue")
    c.issue(repository, fmt, 1, "https-backup-comment", "exact native history through HTTPS")
    canonical = json.loads(c.run("issue", "show", repository, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))
    private, public = home / "private.pem", home / "public.pem"
    require(c.node_command(Path("-e"), [KEYGEN, str(private), str(public)])["fixture_keys_created"] is True, "fixture signing keys missing")

    def operator(name, args, expected=0):
        return c.node_command(ROOT / "scripts" / name, list(map(str, args)), expected, error_reply=expected != 0)

    control = json.loads(c.run("backup", "export", repository, exports / "control.fg", TENANT, REPOSITORY,
        "--trusted-local", "--object-format", fmt))
    identity = ["--tenant-id", TENANT, "--repository-id", REPOSITORY, "--incarnation-id", control["incarnation_id"], "--object-format", fmt]
    archive, approval = exports / "archive.fg", exports / "approval.json"
    signed = operator("attest_repository_backup.mjs", ["export-sign", repository, archive, approval,
        "--fg", c.fg, "--trusted-local", "--verification-instance", "94001", "--private-key", private,
        *identity, "--head-generation", control["head_generation"]])
    require(control["node_closed"] is True and control["complete"] is True and signed["state"] == "complete"
            and signed["approval_result"]["native_content_verified"] is True
            and signed["native"]["sha256"] == file_sha256(archive), "independently selected native archive was not verified/signed")
    expected_archive, expected_approval = archive.read_bytes(), approval.read_bytes()
    size = len(expected_archive)
    policy = [*identity, "--minimum-head-generation", str(control["head_generation"]), "--trust-key", public]
    limits = ["--max-archive-bytes", str(size), "--timeout-secs", "20"]
    independent_approval = home / "independent.approval"
    independent_approval.write_bytes(expected_approval)
    c.facts[f"{fmt}_signed_native_archive"] = True

    def native_readback(root):
        issue = json.loads(c.run("issue", "show", root, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))
        require(issue["node_closed"] is True and issue["issue"] == canonical["issue"] and issue["events"] == canonical["events"],
                "restored canonical issue or complete history differs")
        for path, (mode, body) in FILES.items():
            page = json.loads(c.run("show", root, TENANT, REPOSITORY, "--trusted-local", "--object-format", fmt,
                "--ref", REF, "--path-hex", path.hex(), "--max-bytes", "4096"))
            require(page["node_closed"] is True and page["source_commit"] == tip and page["root_tree"] == tree
                and page["object_id"] == oid(fmt, "blob", body) and bytes.fromhex(page["bytes_hex"]) == body
                and page["kind"] == ("executable" if mode == b"100755" else "file")
                and page["has_more"] is False and page["next_offset"] is None, "restored Git identity, mode or binary bytes differ")
        c.run("doctor", root, TENANT, REPOSITORY)

    with ObjectFixture(c, home / "https-objects", certificate, tls_key) as store:
        direct_file = home / "direct-target.json"
        direct_file.write_text(json.dumps(store.target("direct")))
        direct = [*policy, *limits, "--ca-file", certificate, "--input", archive, "--approval", approval, "--target", direct_file]
        refused = operator(ENTRYPOINTS[0], [*direct, "--max-total-bytes", str(3 * size - 1)], 1)
        require(refused["code"] == "backup_upload_budget" and not store.events, "direct short budget touched HTTPS")
        result = operator(ENTRYPOINTS[0], [*direct, "--max-total-bytes", str(3 * size)])
        checkpoint = result["checkpoint"]
        pins = ["--checkpoint", checkpoint["approval_sha256"], checkpoint["trusted_key_id"]]
        require(result["state"] == "complete" and result["native_content_verified"] is False
                and store.path("direct", "archive").read_bytes() == expected_archive
                and store.path("direct", "approval").read_bytes() == expected_approval, "direct HTTPS upload changed signed native bytes")
        prior, original = len(store.events), snapshot([store.path("direct", kind) for kind in ("archive", "approval")])
        refused = operator(ENTRYPOINTS[0], [*direct, "--checkpoint", "0" * 64, checkpoint["trusted_key_id"]], 1)
        require(refused["code"] == "backup_upload_checkpoint_mismatch" and len(store.events) == prior, "wrong upload pin touched HTTPS")
        repeated = operator(ENTRYPOINTS[0], [*direct, *pins])
        require(repeated["state"] == "complete" and all(e["method"] == "GET" for e in store.events[prior:])
                and snapshot([store.path("direct", kind) for kind in ("archive", "approval")]) == original, "exact direct retry rewrote remote objects")
        verified = operator("restore_repository_backup_native.mjs", ["verify", store.path("direct", "archive"),
            "--approval", independent_approval, *policy, *limits, "--fg", c.fg, "--trusted-local", "--verification-instance", "94000"])
        require(verified["native"]["signature_verified"] is True and verified["native"]["node_closed"] is True
                and verified["destination_changed"] is False, "direct remote bytes failed independent native signed preflight")
        c.facts[f"{fmt}_direct_upload_pin_budget_and_exact_retry"] = True

        targets = [home / "job-a-target.json", home / "job-b-target.json"]
        for namespace, path in zip(("job-a", "job-b"), targets):
            path.write_text(json.dumps(store.target(namespace)))
        jobs = home / "upload-jobs"
        jobs.mkdir(mode=0o700)
        common = ["--trusted-local", *policy, *limits, "--ca-file", certificate,
                  *[part for path in targets for part in ("--target", path)]]
        before = len(store.events)
        sealed = operator(ENTRYPOINTS[1], ["seal", *common, "--job-directory", jobs, "--input", archive, "--approval", approval,
            "--max-total-bytes", str(3 * size)])
        require(sealed["state"] == "complete" and sealed["network_accessed"] is False and len(store.events) == before,
                "upload job seal contacted remote service")
        controls = list(jobs.iterdir())
        stable = snapshot(controls)
        for path in (source, repository, exports):
            path.rename(retained / path.name)
        require(not any(path.exists() for path in (source, repository, archive, approval)), "original source paths remain available")
        c.facts[f"{fmt}_sealed_source_custody_without_network"] = True
        run = ["run", *common, "--intent", sealed["job"]["intent"], "--max-total-bytes", str(6 * size)]
        too_small = run.copy(); too_small[-1] = str(6 * size - 1)
        refused = operator(ENTRYPOINTS[1], too_small, 1)
        require(refused["code"] == "backup_upload_job_budget" and len(store.events) == before, "job budget refusal touched HTTPS")
        stronger = run.copy(); stronger[stronger.index("--minimum-head-generation") + 1] = str(int(control["head_generation"]) + 1)
        refused = operator(ENTRYPOINTS[1], stronger, 1)
        require(refused["code"] == "backup_approval_below_floor" and len(store.events) == before, "unmet job floor touched HTTPS")
        changed = store.target("direct")
        targets[0].write_text(json.dumps(changed))
        refused = operator(ENTRYPOINTS[1], run, 1)
        require(refused["code"] == "backup_upload_job_target_mismatch" and len(store.events) == before, "changed job target touched HTTPS")
        targets[0].write_text(json.dumps(store.target("job-a")))
        c.facts[f"{fmt}_job_policy_target_budget_refusals"] = True

        def target_id(namespace):
            logical = {kind + "_sha256": hashlib.sha256(f"{store.origin}/{namespace}/{kind}".encode()).hexdigest()
                       for kind in ("archive", "approval")}
            return hashlib.sha256((json.dumps(logical, separators=(",", ":")) + "\n").encode()).hexdigest()

        second = sorted(("job-a", "job-b"), key=target_id)[1]
        store.lose_approval = (second, "approval")
        refused = operator(ENTRYPOINTS[1], run, 1)
        require(refused["code"] == "backup_upload_transport" and refused["publication_state"] == "approval_put_unknown"
                and len(refused["upload_job"]["completed_targets"]) == 1 and store.lose_approval is None
                and all(store.path(ns, kind).read_bytes() == (expected_archive if kind == "archive" else expected_approval)
                        for ns in ("job-a", "job-b") for kind in ("archive", "approval"))
                and all(sum(e["method"] == "PUT" and e["path"] == f"/{ns}/{kind}" for e in store.events) == 1
                        for ns in ("job-a", "job-b") for kind in ("archive", "approval")),
                "lost approval reply erased partial completion, retried automatically or lost actual published bytes")
        c.facts[f"{fmt}_lost_approval_response_retains_partial_completion"] = True
        prior = len(store.events)
        job_objects = [store.path(ns, kind) for ns in ("job-a", "job-b") for kind in ("archive", "approval")]
        originals = snapshot(job_objects)
        for namespace, path in zip(("job-a", "job-b"), targets):
            path.write_text(json.dumps(store.target(namespace, version=2)))
        resumed = run.copy()
        indexes = [i + 1 for i, value in enumerate(resumed) if value == "--target"]
        resumed[indexes[0]], resumed[indexes[1]] = resumed[indexes[1]], resumed[indexes[0]]
        result = operator(ENTRYPOINTS[1], resumed)
        require(result["state"] == "complete" and len(result["completed_targets"]) == 2
                and len(store.events[prior:]) == 6 and all(e["method"] == "GET" for e in store.events[prior:])
                and snapshot(job_objects) == originals and snapshot(controls) == stable,
                "refreshed capability/reordered target resume skipped readback, repeated PUT or changed custody")
        c.facts[f"{fmt}_renewed_capabilities_reuse_without_put"] = True

        damaged = bytearray(expected_archive); damaged[-1] ^= 1
        store.path("corrupt", "archive").write_bytes(damaged)
        sources = home / "source-urls.json"
        sources.write_text(json.dumps([store.url("corrupt", "archive"), store.url("job-a", "archive", version=2)]))
        downloaded, witness = home / "downloaded", home / "witness"
        downloaded.mkdir(mode=0o700)
        operator("repository_backup_witness.mjs", ["init", witness, *policy])
        download = [*policy, *limits, "--sources", sources, "--approval", independent_approval,
            "--replica-directory", downloaded, "--witness", witness, "--max-total-read-bytes", str(5 * size)]
        before = len(store.events)
        refused = operator(ENTRYPOINTS[2], [*download, "--checkpoint", "0" * 64, checkpoint["trusted_key_id"], "--ca-file", certificate], 1)
        require(refused["code"] == "backup_download_checkpoint_mismatch" and len(store.events) == before and not list(downloaded.iterdir()),
                "wrong download checkpoint published or connected")
        refused = operator(ENTRYPOINTS[2], download, 1)
        require(refused["code"] == "backup_download_tls" and len(store.events) == before and not list(downloaded.iterdir()),
                "untrusted TLS mirror fell back or published bytes")
        result = operator(ENTRYPOINTS[2], [*download, *pins, "--ca-file", certificate])
        candidate = {key: Path(value) for key, value in result["candidate"].items()}
        require(result["state"] == "complete" and result["native_content_verified"] is False
                and candidate["input"].read_bytes() == expected_archive and candidate["approval"].read_bytes() == expected_approval
                and len(result["source_attempts"]) == 2 and result["source_attempts"][0]["code"] == "backup_download_digest",
                "corrupt-mirror fallback changed checkpoint or failed native byte equality")
        c.facts[f"{fmt}_download_trust_checkpoint_and_corrupt_mirror_twins"] = True

        restored = home / "download-restored"
        result = operator("restore_repository_backup_native.mjs", ["restore", candidate["input"], "--approval", candidate["approval"],
            *policy, *limits, "--fg", c.fg, "--trusted-local", "--verification-instance", "94002",
            "--destination", restored, "--destination-instance", "94003", "--approval-record", home / "download-restore-record"])
        require(result["state"] == "complete" and result["native"]["signature_verified"] is True
                and result["native"]["node_closed"] is True, "downloaded bytes failed actual native signed restore")
        native_readback(restored)
        c.facts[f"{fmt}_downloaded_native_restore"] = True

        cache, recovered, record = home / "cache", home / "https-restored", home / "https-restore-record"
        cache.mkdir(mode=0o700)
        recovery = ["restore", *policy, *limits, "--sources", sources, "--ca-file", certificate,
            "--approval", independent_approval, "--witness", witness, "--cache-directory", cache,
            "--fg", c.fg, "--trusted-local", "--verification-instance", "94004", "--destination", recovered,
            "--destination-instance", "94005", "--approval-record", record, "--max-acquisition-bytes", str(5 * size)]
        before = len(store.events)
        refused = operator(ENTRYPOINTS[3], [*recovery, "--checkpoint", "0" * 64, checkpoint["trusted_key_id"]], 1)
        require(refused["code"] == "backup_recovery_checkpoint_mismatch" and len(store.events) == before
                and not recovered.exists() and not record.exists() and not list(cache.iterdir()), "wrong recovery pin started acquisition/native publication")
        result = operator(ENTRYPOINTS[3], [*recovery, *pins])
        require(result["state"] == "complete" and result["acquisition"]["mode"] == "downloaded"
                and result["native"]["native"]["signature_verified"] is True
                and result["native"]["native"]["node_closed"] is True, "HTTPS recovery did not reach actual native signed restore")
        native_readback(recovered)
        original_record = record.read_bytes()
        authority = c.run("at", recovered, TENANT, REPOSITORY, "latest")
        sources.rename(retained / "source-urls.json")

    # HTTPS is now stopped and its capability input is absent. Resume may use
    # only reverified cache bytes and the exact original native restore identity.
    before = len(store.events)
    resumed = operator(ENTRYPOINTS[3], [*recovery, *pins, "--resume"])
    require(resumed["state"] == "complete" and resumed["acquisition"]["mode"] == "cached"
            and resumed["native"]["native"]["already_published"] is True and record.read_bytes() == original_record
            and len(store.events) == before and c.run("at", recovered, TENANT, REPOSITORY, "latest") == authority,
            "offline cache resume reopened URL input or republished native authority")
    c.facts[f"{fmt}_https_recovery_then_offline_cache_resume"] = True
    outputs = [path for path in c.work.glob("operator-*.stdout")] + [path for path in c.work.glob("operator-*.stderr")]
    require(all(CAPABILITY.encode() not in path.read_bytes() for path in [*outputs, *controls]), "capability leaked in client output or immutable intent")
    require(not store.thread.is_alive() and not store.sockets and not store.failures
            and any(e.get("response_lost") is True for e in store.events), "fixture did not record loss and complete ownership drain")
    for namespace in ("direct", "job-a", "job-b"):
        archive_put = next(i for i, e in enumerate(store.events) if e["method"] == "PUT" and e["path"] == f"/{namespace}/archive")
        approval_put = next(i for i, e in enumerate(store.events) if e["method"] == "PUT" and e["path"] == f"/{namespace}/approval")
        require(archive_put < approval_put and any(e["method"] == "GET" and e["path"] == f"/{namespace}/archive"
                for e in store.events[archive_put + 1:approval_put]), "approval PUT preceded actual archive readback")
    c.facts[f"{fmt}_redacted_capabilities_and_fixture_drain"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary", "oracle-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    fg, node, oracle = args.fg.resolve(strict=True), args.node.resolve(strict=True), args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private campaign directory required")
    c = OperatorCampaign(fg, node, args.work.resolve())
    digest = file_sha256(fg)
    summary = dict(complete=False, facts=c.facts, selected_facts=FACTS, binary_sha256=digest,
        node_sha256=file_sha256(node), entrypoints=[dict(path="scripts/" + name, binary_sha256=digest) for name in ENTRYPOINTS],
        oracle_pin="git-2.54.0", artifacts=str(c.work),
        non_claim="Actual native archives/restores; disk-backed loopback TLS object-service fixture, retained diagnostic originals, not public provider, independent storage, destructive/hardware fault, full capsule, current-main native or full operator qualification.")

    def stop(_signum, _frame):
        raise InterruptedError("HTTPS backup campaign interrupted; preserve original effects/custody")

    signal.signal(signal.SIGTERM, stop)
    try:
        runtime = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(runtime.get("type") == "js_runtime_identity" and runtime.get("corpus_started") is False, "pinned Node runtime required")
        summary["node_version"] = runtime["node"]
        key, certificate = c.work / "tls-key.pem", c.work / "tls-ca.pem"
        command = ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-addext", "basicConstraints=critical,CA:TRUE",
            "-keyout", str(key), "-out", str(certificate)]
        with (c.work / "certificate.stdout").open("wb") as out, (c.work / "certificate.stderr").open("wb") as err:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=20, check=False)
        c.record(kind="fixture_only_certificate", command=command, exit=result.returncode)
        require(result.returncode == 0, "test-only TLS certificate generation failed")
        for fmt in ("sha1", "sha256"):
            run_case(c, oracle, fmt, certificate, key)
        require(set(c.facts) == set(FACTS) and all(v is True for v in c.facts.values()), "selected fact population incomplete")
        require(file_sha256(fg) == digest, "native binary changed during campaign")
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
