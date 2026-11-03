#!/usr/bin/env python3
"""Exercise shipped PR tip synchronization against native Rust, with pinned Git fixtures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil

from operator_issue_smoke import OperatorCampaign
from operator_pull_smoke import check_fixture
from operator_workflow_smoke import verify_fixture
from patch_smoke import loose
from pull_request_smoke import fixture, commit, SOURCE, TARGET
from scoped_events_smoke import HttpServer, PRINCIPAL, REPOSITORY, TENANT, file_sha256, require

ROOT = Path(__file__).resolve().parents[2]
TOKEN, ROTATED = "c" * 64, "d" * 64


def run_case(c: OperatorCampaign, oracle: Path, fmt: str) -> None:
    home = c.work / fmt
    home.mkdir(mode=0o700)
    root, source = home / "repository", home / "source"
    objects = fixture(source, fmt)
    (home / "reviewed.bundle").write_bytes(objects["bundle"])
    check_fixture(c, oracle, source, objects)
    (source / SOURCE).write_text(objects["base"] + "\n", encoding="ascii")
    c.run("init", root, TENANT, REPOSITORY, fmt)
    c.run("import", root, TENANT, REPOSITORY, PRINCIPAL, "operator-sync-fixture", source)
    credentials, incarnation = c.credentials(root, home)
    header = credentials.read_text().splitlines()[0]

    def grants(scopes: str, rotated_scopes: str = "outcomes-read") -> None:
        pending = home / "credentials.next"
        with pending.open("x", encoding="ascii") as out:
            out.write(header + "\n")
            for token, allowed in [(TOKEN, scopes), (ROTATED, rotated_scopes)]:
                out.write(f"{hashlib.sha256(token.encode()).hexdigest()} {PRINCIPAL} {allowed}\n")
        pending.replace(credentials)

    full_grants = "read,outcomes-read,pulls-read,pulls-write"
    grants(full_grants)
    token_path, rotated_path = home / "token", home / "rotated-token"
    token_path.write_text(TOKEN, encoding="ascii")
    rotated_path.write_text(ROTATED, encoding="ascii")
    title, body = 'Preserve title: "é"', "Preserve body\nwith a second line"
    opened = json.loads(c.run("pr", "open", root, TENANT, REPOSITORY, "1", "--trusted-local",
        "--principal", PRINCIPAL, "--idempotency-key", "operator-sync-open", "--expected-version", "0",
        "--source-ref", SOURCE, "--target-ref", TARGET, "--expected-source", objects["base"],
        "--expected-target", objects["target"], "--title", title, "--body", body, "--object-format", fmt))
    require(opened["command_committed"] is True and opened["node_closed"] is True, "native PR seed failed")

    def readback() -> dict:
        page = json.loads(c.run("pr", "show", root, TENANT, REPOSITORY, "1", "--trusted-local", "--object-format", fmt))
        require(page["found"] is True and page["node_closed"] is True, "canonical PR read did not close")
        return page["pull_request"]

    def expected(version: int, tip: str) -> dict:
        value = readback()
        require(value["state"] == "open" and value["version"] == version and value["data"] == {
            "source_reference_hex": SOURCE.encode().hex(), "target_reference_hex": TARGET.encode().hex(),
            "source_tip": tip, "target_tip": objects["target"], "title": title, "body": body},
            "canonical PR lost its version, exact tips or original metadata")
        return value

    def head() -> bytes:
        return c.run("at", root, TENANT, REPOSITORY, "latest")

    def refs() -> dict:
        lines = c.run("at", root, TENANT, REPOSITORY, "latest", "refs").decode("ascii").splitlines()
        header = re.fullmatch(r"references at latest \(([0-9]+) total\):", lines[0])
        require(header is not None and int(header[1]) == len(lines) - 1, "incomplete native refs")
        result = {}
        for line in lines[1:]:
            row = re.fullmatch(r"  (refs/heads/[a-z-]+) -> ([0-9a-f]{" + str(40 if fmt == "sha1" else 64) + r"})", line)
            require(row is not None and row[1] not in result, "invalid or duplicate native ref")
            result[row[1]] = row[2]
        require(list(result) == sorted(result), "native ref order changed")
        return result

    def advance(old: str, new: str, label: str) -> None:
        (source / SOURCE).write_text(new + "\n", encoding="ascii")
        verify_fixture(c, source, oracle, fmt, label)
        verify_fixture(c, source, oracle, fmt, label + "-bundle", "bundle", "create", "../" + label + ".bundle", SOURCE)
        c.run("bundle", "sync-import", root, TENANT, REPOSITORY, home / (label + ".bundle"),
            "--trusted-local", "--object-format", fmt, "--principal", PRINCIPAL, "--key-stdin",
            "--allow-ref-updates", "--expect", SOURCE + "=" + old, input_bytes=("sync-" + label).encode())
        require(refs() == {TARGET: objects["target"], SOURCE: new}, "fixture advance changed another ref")

    advance(objects["base"], objects["source"], "first")
    expected(1, objects["base"])
    server = HttpServer(c, root, credentials, "sync-" + fmt)
    server.command.extend(["--allow-outcomes", "--allow-source"])
    sync, watch = ROOT / "scripts/fg_pull_sync.mjs", ROOT / "scripts/fg_pull_sync_watch.mjs"
    with server:
        destination = home / "destination.json"
        dest = dict(endpoint=server.url, tenant_id=TENANT, repository_id=REPOSITORY,
                    repository_incarnation=incarnation, object_format=fmt, principal_id=PRINCIPAL)
        destination.write_text(json.dumps(dest) + "\n")
        discovery_args = ["--destination", str(destination), "--token-file", str(token_path), "--pr", "1"]
        before = head()
        grants("outcomes-read,pulls-read,pulls-write")
        denied_read = c.node_command(sync, ["inspect", *discovery_args], 2, error_reply=True)
        require("sync_http_refused" in denied_read["message"] and head() == before, "missing source-read grant was ignored")
        grants(full_grants)
        discovery = c.node_command(sync, ["inspect", *discovery_args])
        require(len(discovery["changes"]) == 1 and discovery["unchanged"] == [], "native stale tip was not discovered")
        plans = []
        for name in ("primary", "stale"):
            state = home / name
            state.mkdir(mode=0o700)
            prepared = c.node_command(sync, ["prepare", *discovery_args, "--state", str(state)])
            shown = c.node_command(sync, ["show", "--state", str(state)])
            require(shown == prepared and shown["mutations_sent_by_this_operation"] == 0, "prepare/show changed plan")
            plans.append((state, prepared["plan_sha256"], (state / "plan.json").read_bytes()))
        state, digest, frozen = plans[0]
        other, other_digest, other_frozen = plans[1]
        plan = json.loads(frozen)
        require(plan["requests"][0]["key"] != json.loads(other_frozen)["requests"][0]["key"], "independent plans reused a key")
        require(head() == before and c.node_command(sync, ["status", "--state", str(state)], 3)["jobs"][0]["state"] == "prepared",
                "discovery or preparation published")
        c.facts[f"{fmt}_native_stale_tips_and_frozen_plans"] = True

        def publication(slot: Path, confirmation: str, *, retry: bool = False, code: int = 0, error: bool = False):
            args = ["send", "--state", str(slot), "--endpoint", server.url, "--token-file", str(token_path),
                    "--confirm", confirmation, *(["--retry"] if retry else [])]
            result = c.node_command(sync, args, code, error_reply=error, json_lines=not error)
            return result if error else result[-1]

        def recover(slot: Path, token: Path = token_path, code: int = 0):
            return c.node_command(sync, ["recover", "--state", str(slot), "--endpoint", server.url,
                "--token-file", str(token)], code, json_lines=True)[-1]

        wrong = publication(state, "0" * 64, code=2, error=True)
        require(wrong["publication_unknown"] is False and "confirmation_required" in wrong["message"]
                and head() == before, "wrong confirmation published")
        grants("read,outcomes-read,pulls-read")
        denied = publication(state, digest, code=3, error=True)
        require(denied["publication_unknown"] is True and (state / "started-000.json").exists() and head() == before,
                "write-grant refusal lost responsibility or changed native state")
        require(recover(state, code=3)["jobs"][0]["state"] == "unknown", "absent outcome was treated as rollback")
        grants(full_grants)
        no_retry = publication(state, digest, code=2, error=True)
        require("explicit_retry_or_recovery" in no_retry["message"] and head() == before, "plain send retried unknown publication")
        sent = publication(state, digest, retry=True)
        require(sent["updates"] == 1 and sent["lookups"] == 1 and sent["jobs"][0]["state"] == "committed",
                "explicit original retry did not commit exactly one update")
        c.facts[f"{fmt}_grant_unknown_and_exact_retry"] = True
        current = expected(2, objects["source"])
        require(refs() == {TARGET: objects["target"], SOURCE: objects["source"]}, "tip synchronization moved refs")
        require((state / "plan.json").read_bytes() == frozen, "retry rewrote frozen plan")
        c.facts[f"{fmt}_canonical_update_preserves_metadata"] = True

        refused = publication(other, other_digest, code=1)
        require(refused["jobs"][0]["state"] == "refused" and readback() == current, "stale plan overwrote canonical metadata")
        after_refusal = head()
        require(recover(other, code=1)["jobs"] == refused["jobs"] and head() == after_refusal,
                "original stale recovery reexecuted or changed its decision")
        require((other / "plan.json").read_bytes() == other_frozen, "stale refusal replanned")
        c.facts[f"{fmt}_stale_refusal_and_original_recovery"] = True

        # Retain the acknowledged original intact. A separate custody copy models
        # loss of observations, without deleting the original terminal receipt.
        lost = home / "lost-observation"
        lost.mkdir(mode=0o700)
        for name in ("plan.json", "started-000.json"):
            shutil.copyfile(state / name, lost / name)
        grants(full_grants, "pulls-read")
        denied_outcome = c.node_command(sync, ["recover", "--state", str(lost), "--endpoint", server.url,
            "--token-file", str(rotated_path)], 3, error_reply=True)
        require(denied_outcome["publication_unknown"] is True and head() == after_refusal
                and sorted(p.name for p in lost.iterdir()) == ["plan.json", "started-000.json"],
                "outcome grant refusal concealed responsibility or manufactured a terminal")
        grants(full_grants)
        recovered = recover(lost, rotated_path)
        require(recovered["updates"] == 0 and recovered["lookups"] == 1 and recovered["jobs"] == sent["jobs"]
                and head() == after_refusal, "rotated outcome-only recovery changed native state or original transaction")
        require((state / "plan.json").read_bytes() == frozen and (state / "terminal-000.json").exists(), "original custody lost")
        c.facts[f"{fmt}_rotated_readonly_recovery"] = True

        next_tip = loose(source, fmt, "commit", commit(objects["tree"], [objects["source"]], "next pushed source"))
        advance(objects["source"], next_tip, "second")
        expected(2, objects["source"])
        watch_state = home / "watch"
        watch_state.mkdir(mode=0o700)
        config = home / "watch.json"
        config.write_text(json.dumps(dict(schema="frankengit-pr-sync-watch-v1", destination=dest, selected=[1],
            state_directory=str(watch_state), max_batches=8, state_bytes=1048576, policy="recorded-tips-only")) + "\n")
        watch_args = ["--config", str(config), "--token-file", str(token_path)]
        before = head()
        denied = c.node_command(watch, ["once", *watch_args], 2, error_reply=True)
        require(denied["publication_unknown"] is False and not any(watch_state.iterdir()) and head() == before,
                "watcher ran without explicit tip-update consent")
        once = c.node_command(watch, ["once", *watch_args, "--allow-tip-updates"], json_lines=True)[-1]
        require(once["updates"] == 1 and once["committed"] == 1 and once["refused"] == 0, "watcher did not publish fresh tips")
        current = expected(3, next_tip)
        c.facts[f"{fmt}_watcher_updates_and_no_consent_twin"] = True
        before = head()
        service = c.node_command(watch, ["serve", *watch_args, "--allow-tip-updates", "--max-polls", "2", "--poll-millis", "100"], json_lines=True)
        require(len(service) == 3 and all(row["type"] == "pull_sync_watch_sweep" and row["updates"] == 0 for row in service[:-1])
                and service[-1]["polls"] == 2 and service[-1]["updates"] == 0 and service[-1]["poll_limit_reached"] is True
                and service[-1]["read_failures"] == 0 and head() == before and readback() == current,
                "bounded watch service repeated updates or changed the canonical PR")
        final_refs = {TARGET: objects["target"], SOURCE: next_tip}
        require(refs() == final_refs, "metadata watcher changed code refs")

    for slot, _, original in plans:
        require((slot / "plan.json").read_bytes() == original, "offline custody changed original plan")
        status = c.node_command(sync, ["status", "--state", str(slot)], 0 if slot == state else 1)
        require(status["owner_present"] is False and status["recovery_owner_present"] is False, "sync owner leaked")
        c.node_command(sync, ["show", "--state", str(slot)])
    status = c.node_command(watch, ["status", "--config", str(config)])
    require(len(status["batches"]) == 1 and status["batches"][0]["committed"] == 1
            and status["batches"][0]["unknown"] == 0 and not (watch_state / "owner.lock").exists(), "watch custody did not settle")
    c.facts[f"{fmt}_bounded_watch_service_and_offline_custody"] = True
    require(refs() == final_refs and readback() == current and server.process is None, "owned native service/refs did not settle")
    c.facts[f"{fmt}_owned_service_drained_and_refs_stable"] = True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("fg", "node", "work", "summary", "oracle-run"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    fg, node, oracle = args.fg.resolve(strict=True), args.node.resolve(strict=True), args.oracle_run.resolve(strict=True)
    args.work.resolve().relative_to(oracle / "work")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(not any(args.work.iterdir()) and args.work.stat().st_mode & 0o077 == 0, "empty private work directory required")
    c = OperatorCampaign(fg, node, args.work.resolve())
    summary = dict(complete=False, facts=c.facts, binary_sha256=file_sha256(fg), node_sha256=file_sha256(node),
        entrypoints=["scripts/fg_pull_sync.mjs", "scripts/fg_pull_sync_watch.mjs"],
        oracle_pin="git-2.54.0", oracle_run=str(oracle), artifacts=str(c.work),
        non_claim="Local native metadata synchronization; not all operators, current-source native qualification, review validity, deployment, TLS or a full negative matrix.")

    def stop(_signum, _frame):
        raise InterruptedError("PR sync campaign interrupted; preserve custody and drain owned service")

    signal.signal(signal.SIGTERM, stop)
    try:
        identity = c.node_command(ROOT / "scripts/verify_js.mjs", ["runtime"])
        require(identity.get("type") == "js_runtime_identity" and identity.get("corpus_started") is False, "pinned runtime required")
        summary["node_version"] = identity["node"]
        for fmt in ("sha1", "sha256"):
            run_case(c, oracle, fmt)
        summary["complete"] = True
    except BaseException as error:
        summary["failure"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
