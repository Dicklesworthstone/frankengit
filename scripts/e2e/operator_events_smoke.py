#!/usr/bin/env python3
"""Shipped event CLI -> real native feed, immutable archive and Rust frame reads.

No peer server, decoder, Git oracle, implicit build or production credential.
Reuse the existing operator process owner and native HTTP service drain.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import signal
from urllib.parse import urlsplit

from operator_issue_smoke import OperatorCampaign
from scoped_events_smoke import HttpServer, TENANT, REPOSITORY, TOKENS, file_sha256, require, rows

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/fg_events.mjs"


def snapshot(path):
    return {str(p.relative_to(path)): file_sha256(p) if p.is_file() else "directory"
            for p in path.rglob("*")}


def pages(path):
    return [json.loads((p / "record.json").read_bytes())["page"] for p in sorted(path.glob("page-*"))]


def archived_rows(path):
    return [row for page in pages(path) for row in rows(page)]


def private_file(path, text):
    with path.open("x", encoding="utf-8") as out:
        out.write(text)


def accepted(server):
    receipts = [json.loads(line) for line in server.stdout_path.read_bytes().splitlines()]
    return next(row["accepted"] for row in receipts if row.get("type") == "smart_http_drained")


def run_case(c, fmt):
    home = c.work / fmt
    home.mkdir(mode=0o700)
    root, archive, filtered = home / "node", home / "archive", home / "filtered"
    c.run("init", root, TENANT, REPOSITORY, fmt)
    for version, body in enumerate(["Canonical é\r\n<script>inert</script>", "second", "third"]):
        c.issue(root, fmt, version, "events-" + str(version), body)
    canonical = c.canonical(root, fmt)
    require(len(canonical["events"]) == 3, "native seed did not produce three canonical frames")
    credentials, incarnation = c.credentials(root, home)
    original_credentials = credentials.read_bytes()
    token = home / "token"
    private_file(token, TOKENS["issues"])
    config = home / "subscription.json"

    def command(action, extra=(), expected=0, error=False, target=archive, configuration=config):
        args = [action, "--archive", str(target), "--config", str(configuration), "--trusted-local"]
        if action != "inspect":
            args += ["--token-file", str(token)]
        result = c.node_command(SCRIPT, [*args, *map(str, extra)], expected,
                                error_reply=error, json_lines=True)
        require(all(isinstance(item, dict) for item in result), "non-object CLI record")
        return result

    first = HttpServer(c, root, credentials, "events-" + fmt + "-first")
    with first:
        subscription = {"type": "frankengit_event_subscription", "schema_version": 1,
            "endpoint": first.url.rstrip("/"), "scope": {"tenant_id": TENANT, "repository_id": REPOSITORY,
                "repository_incarnation": incarnation, "object_format": fmt, "issues_read": True,
                "pulls_read": False}, "after": "0", "page_size": 1}
        private_file(config, json.dumps(subscription))
        initialized = command("init")[-1]
        require(initialized["initialized"] and initialized["network_attempted"] is False
                and initialized["pages"] == 0, "init did not retain a local empty binding")
        partial = command("capture", ["--max-pages", "1"], expected=1)[-1]
        require(partial["caught_up_at_observed_head"] is False and partial["pages"] == 1
                and archived_rows(archive) == rows(canonical)[:1], "partial capture lost its native prefix")
        retained_prefix = snapshot(archive)
        c.facts[fmt + "_local_init_and_partial_capture"] = True
    require(accepted(first) == 1, "local init or partial capture made unexpected native connections")

    # Reopen the actual service at the exact pinned endpoint after an append.
    # A collision is a refusal, never permission to contact another listener.
    c.issue(root, fmt, 3, "events-offline-append", "appended while service stopped")
    canonical = c.canonical(root, fmt)
    require(len(canonical["events"]) == 4, "offline append is absent from canonical Rust read")
    second = HttpServer(c, root, credentials, "events-" + fmt + "-second")
    second.command[5] = "127.0.0.1:" + str(urlsplit(first.url).port)
    with second:
        require(second.url == first.url, "reopened native service changed the pinned endpoint")
        complete = command("capture", ["--max-pages", "8"])[-1]
        require(complete["caught_up_at_observed_head"] and complete["events"] == 4
                and archived_rows(archive) == rows(canonical), "restart omitted, duplicated or rewrote native frames")
        now = snapshot(archive)
        require(all(now.get(k) == v for k, v in retained_prefix.items()), "restart rewrote a retained prefix")
        c.facts[fmt + "_restart_append_exact_native_frames"] = True

        before = snapshot(archive)
        bad = command("inspect", ["--expected-tail", "0" * 64], 2, True)[-1]
        require(bad["code"] == "event_archive_tail_mismatch" and snapshot(archive) == before,
                "wrong tail pin did not refuse without changing the archive")
        inspected = command("inspect", ["--expected-tail", complete["tail_sha256"], "--page", "1"])[-1]
        require(inspected["archive_modified"] is False and inspected["network_attempted"] is False
                and rows(inspected["selected_page"]["page"]) == rows(canonical)[:1]
                and snapshot(archive) == before, "permitted inspection changed data or native bytes")
        c.facts[fmt + "_readonly_inspection_and_tail_twins"] = True

        watched = command("watch", ["--max-sweeps", "2", "--poll-ms", "100"], expected=1)
        completed = [row for row in watched if row["type"] == "frankengit_event_capture_complete"]
        saved = [row for row in watched if row["type"] == "frankengit_event_page_saved"]
        require(len(completed) == 2 and len(saved) == 2 and saved[-1]["appended"] is False
                and completed[-1]["caught_up_at_observed_head"] and archived_rows(archive) == rows(canonical),
                "bounded quiet watch rewrote frames or grew an identical quiet page")
        before = snapshot(archive)
        quiet = command("capture")[-1]
        require(quiet["caught_up_at_observed_head"] and snapshot(archive) == before,
                "identical quiet capture grew the archive")
        c.facts[fmt + "_quiet_watch_and_no_growth"] = True

        token.write_text(TOKENS["pulls"], encoding="ascii")
        changed = command("capture", expected=2, error=True)[-1]
        require(changed["code"] == "event_archive_binding_mismatch" and snapshot(archive) == before,
                "changed credential silently reused or modified the archive")
        token.write_text(TOKENS["issues"], encoding="ascii")
        credentials.write_bytes(original_credentials.replace(b" issues-read\n", b" pulls-read\n"))
        changed = command("capture", expected=2, error=True)[-1]
        require(changed["code"] == "invalid_event_page_or_scope" and snapshot(archive) == before,
                "changed native grant profile advanced a bound archive")
        credentials.write_bytes(original_credentials)
        require(command("capture")[-1]["caught_up_at_observed_head"] and snapshot(archive) == before,
                "restored credential/grant twin did not preserve its exact quiet state")
        c.facts[fmt + "_credential_and_grant_twins"] = True

        filtered_config = home / "filtered.json"
        pulls = json.loads(config.read_text())
        pulls["scope"].update(issues_read=False, pulls_read=True)
        private_file(filtered_config, json.dumps(pulls))
        token.write_text(TOKENS["pulls"], encoding="ascii")
        command("init", target=filtered, configuration=filtered_config)
        head = command("capture", ["--max-pages", "1"], 1, target=filtered, configuration=filtered_config)[-1]
        require(not head["caught_up_at_observed_head"] and archived_rows(filtered) == []
                and pages(filtered)[0]["has_more"], "empty filtered page was mistaken for EOF or disclosed issue bytes")
        tail = command("capture", ["--max-pages", "8"], target=filtered, configuration=filtered_config)[-1]
        require(tail["caught_up_at_observed_head"] and archived_rows(filtered) == []
                and tail["resume_after"] == quiet["resume_after"], "filtered capture stalled or lost its native watermark")
        token.write_text(TOKENS["issues"], encoding="ascii")
        c.facts[fmt + "_filtered_pages_advance_without_disclosure"] = True

        corrupt = home / "corrupt"
        shutil.copytree(archive, corrupt)
        record = next(corrupt.glob("page-*/record.json"))
        record.write_bytes(record.read_bytes() + b" ")
        damaged = snapshot(corrupt)
        refused = command("inspect", expected=2, error=True, target=corrupt)[-1]
        require(refused["code"] == "noncanonical_event_archive_record" and snapshot(corrupt) == damaged
                and snapshot(archive) == before, "tampered evidence was accepted, repaired or damaged the permitted archive")
        c.facts[fmt + "_tamper_refuses_without_mutation"] = True
        for path in archive.rglob("*"):
            require(path.stat().st_mode & 0o077 == 0, "archive data is not private")
            if path.is_file():
                require(TOKENS["issues"].encode() not in path.read_bytes(), "archive retained the credential itself")
        require(rows(c.canonical(root, fmt)) == rows(canonical), "read-only consumers changed native history")
        c.facts[fmt + "_saved_records_private_and_opaque"] = True
    require(accepted(second) == 12, "local inspections/refusals or bounded captures changed their connection budget")

    disabled = HttpServer(c, root, credentials, "events-" + fmt + "-disabled")
    disabled.command[5] = second.command[5]
    disabled.command.remove("--allow-issues")
    with disabled:
        require(disabled.url == first.url, "disabled-scope twin changed endpoint")
        denied = command("capture", expected=2, error=True)[-1]
        require(denied["code"] == "event_http_refused" and denied["http_status"] == 403
                and snapshot(archive) == before, "disabled native scope was not a refusal without archive advancement")
        c.facts[fmt + "_disabled_scope_refuses_without_archive_change"] = True
    require(accepted(disabled) == 1, "disabled-scope refusal did not own exactly one native connection")
    c.facts[fmt + "_owned_services_drained"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()), "--work must be an empty retained artifact directory")
    require(args.work.stat().st_mode & 0o077 == 0, "event artifacts must be private")
    c = OperatorCampaign(args.fg.resolve(strict=True), args.node.resolve(strict=True), args.work.resolve())
    require(all(path.is_file() and os.access(path, os.X_OK) for path in (c.fg, c.node)),
            "prebuilt native and Node executables required")
    summary = {"complete": False, "facts": c.facts, "entrypoints": ["scripts/fg_events.mjs"],
        "binary_sha256": file_sha256(c.fg), "node_sha256": file_sha256(c.node), "artifacts": str(c.work),
        "non_claim": "Small issue feed/local archive; no Git oracle, PR hidden-ref proof, TLS, hostile isolation, crash durability, same-source native or full operator qualification."}
    def stop(*_):
        raise InterruptedError("event campaign interrupted; retain archive custody and drain owned service")
    signal.signal(signal.SIGTERM, stop)
    try:
        identity = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity["type"] == "js_runtime_identity" and identity["corpus_started"] is False,
                "runtime did not return the shared identity-only receipt")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
