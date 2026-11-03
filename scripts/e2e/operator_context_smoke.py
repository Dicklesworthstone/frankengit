"""Real native context consumers for the existing workspace campaign.

The original native-backed bundle and independent fixture supply the inputs.
These helpers reuse its process/service owners and never supply a fake node.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from patch_smoke import oid
from scoped_events_smoke import file_sha256, require

ROOT = Path(__file__).resolve().parents[2]


def private_json(path: Path, value: Any) -> Path:
    with path.open("x", encoding="utf-8") as out:
        json.dump(value, out)
    return path


def acquire_context_cases(c, home, fmt, bundle, context, selection, token, grants, original, selected):
    session_cli, proof_cli = ROOT / "scripts/fg_context_session.mjs", ROOT / "scripts/fg_context_proof.mjs"
    parent = {p.name: p.read_bytes() for p in bundle.iterdir()}
    source = json.loads(parent["capture.json"])
    q = source["summary"]["query"]
    cost = dict(queries=1, work=q["limits"]["max_work"], payload_bytes=q["limits"]["max_payload_bytes"],
                source_bytes=q["limits"]["context_max_source_bytes"], excerpt_bytes=q["limits"]["context_max_excerpt_bytes"])
    limits = private_json(home / "session-limits.json", {name: 3 * value for name, value in cost.items()})
    session = home / "context-session"
    created = c.node_command(session_cli, ["init", "--session", str(session), "--from-bundle", str(bundle),
        "--from-sha256", context["manifest_sha256"], "--limits-file", str(limits)])
    root = created["session_sha256"]
    require(created["tip_sha256"] == root, "context session did not begin at its pinned root")
    common = ["--session", str(session), "--session-sha256", root]
    followup = private_json(home / "followup.json", {"terms": q["terms"]})

    def step(tip):
        return ["step", *common, "--tip-sha256", tip, "--followup-file", str(followup), "--token-file", str(token)]

    grants("receive,outcomes-read")
    refused = c.node_command(session_cli, step(root), 2)
    require(refused["type"] == "source_context_session_refused" and refused["http_status"] == 403
            and refused["reservation_retained"] is True, "native denied read lost its charged reservation")
    after_refusal = c.node_command(session_cli, ["status", *common, "--tip-sha256", refused["tip_sha256"]])
    require(after_refusal["reserved"] == cost and after_refusal["history"][0]["state"] == "read_refused"
            and after_refusal["pending"] is None, "refused read was refunded or left untracked")
    grants("read,receive,outcomes-read")
    captured = c.node_command(session_cli, step(refused["tip_sha256"]))
    require(captured["reserved"] == {name: 2 * value for name, value in cost.items()}
            and [row["state"] for row in captured["history"]] == ["read_refused", "captured"],
            "permitted follow-up changed original accounting/history")
    stale = c.node_command(session_cli, step(root), 2, error_reply=True)
    require(stale["code"] == "context_session_tip_moved" and sorted(p.name for p in (session / "steps").iterdir()) == ["0001", "0002"],
            "stale writer reserved or redispatched work")
    native = json.loads((Path(captured["latest_bundle"]) / "capture.json").read_bytes())
    require(native["summary"]["query"]["prefixes_hex"] == q["prefixes_hex"]
            and native["summary"]["source"] == source["summary"]["source"], "native follow-up widened source scope")
    require([bytes.fromhex(row["path_hex"]) for row in native["native_response"]["files"]] == selected,
            "follow-up did not retain its exact native source paths")
    for row in native["native_response"]["files"]:
        body = original[bytes.fromhex(row["path_hex"])][1]
        require(row["blob"] == oid(fmt, "blob", body), "follow-up changed native blob identity")
        for excerpt in row["excerpts"]:
            data = bytes.fromhex(excerpt["untrusted_bytes_hex"])
            require(body[excerpt["byte_offset"]:excerpt["byte_offset"] + len(data)] == data, "follow-up excerpt differs from independent source")
    c.facts[f"{fmt}_native_context_session_quota_and_grants"] = True

    # The public lifecycle API supplies an ordinary never-started reservation;
    # the shipped CLI owns dispatch and original-candidate finalization.
    reserve = """import(process.argv[1]).then(async ({reserveSessionStep})=>{
const result=await reserveSessionStep(process.argv[2],process.argv[3],process.argv[4],JSON.parse(process.argv[5]));
console.log(JSON.stringify(result));});"""
    reservation = c.node_command(Path("-e"), [reserve, (ROOT / "scripts/operator/source_context_session.mjs").as_uri(),
        str(session), root, captured["tip_sha256"], json.dumps({"terms": q["terms"]})])
    dispatch = ["dispatch", *common, "--tip-sha256", captured["tip_sha256"], "--request-sha256", reservation["request_sha256"],
                "--token-file", str(token)]
    staged = c.node_command(session_cli, dispatch, 3)
    require(staged["type"] == "source_context_session_staged" and staged["request_sha256"] == reservation["request_sha256"],
            "explicit dispatch did not stage the original reservation")
    duplicate = c.node_command(session_cli, dispatch, 2, error_reply=True)
    require(duplicate["code"] == "context_session_dispatch_already_started", "duplicate dispatch failed for an unrelated reason")
    recover = ["recover", *common, "--tip-sha256", captured["tip_sha256"], "--request-sha256", reservation["request_sha256"]]
    wrong = c.node_command(session_cli, [*recover, "--candidate-sha256", "0" * 64], 2, error_reply=True)
    require(wrong["code"] == "context_session_candidate_pin_changed", "wrong candidate pin was not the recovery refusal")
    require({p.name: p.read_bytes() for p in bundle.iterdir()} == parent, "session acquisition changed its external parent")

    proof = home / "context-proof.json"
    proof_args = ["capture", "--selection", str(selection), "--context", str(bundle / "capture.json"),
        "--context-sha256", context["capture_sha256"], "--token-file", str(token), "--output", str(proof)]
    grants("receive,outcomes-read")
    denied = c.node_command(proof_cli, proof_args, 2, error_reply=True)
    require("HTTP 403" in denied["message"] and not proof.exists(), "sparse proof bypassed native source-read denial")
    grants("read,receive,outcomes-read")
    proved = c.node_command(proof_cli, proof_args)
    require(proved["source_commit"] == q["expected_commit"] and proved["verified_file_count"] == len(selected)
            and proved["selected_path_membership_verified"] is proved["excerpt_bytes_verified"] is True
            and proved["authority_verified"] is proved["freshness_verified"] is proved["search_evidence_verified"] is False
            and proved["proof_sha256"] == file_sha256(proof), "context proof changed the source or inflated authority")
    portable = json.loads(proof.read_bytes())["capture"]
    require({bytes.fromhex(row["path_hex"]): (row["object_id"], bytes.fromhex(row["body_hex"])) for row in portable["files"]}
            == {p: (oid(fmt, "blob", original[p][1]), original[p][1]) for p in selected}, "proof full blobs differ from independent source")
    c.facts[f"{fmt}_native_context_proof_bytes_and_grants"] = True
    return dict(session_cli=session_cli, proof_cli=proof_cli, common=common, recover=recover, staged=staged,
        session=session, root=root, step=step, cost=cost, bundle=bundle, parent=parent, proof=proof,
        proved=proved, context=context, selection=selection, original=original, selected=selected)


def inspect_context_cases(c, home, fmt, data):
    cli, common = data["session_cli"], data["common"]
    recover = [*data["recover"], "--candidate-sha256", data["staged"]["candidate_sha256"]]
    settled = c.node_command(cli, recover)
    repeated = c.node_command(cli, recover)
    require(settled == repeated and settled["pending"] is None and settled["acquisition_retried"] is False
            and settled["reserved"] == {name: 3 * value for name, value in data["cost"].items()},
            "offline original-candidate recovery changed accounting or its decision")
    tip = settled["tip_sha256"]
    quota = c.node_command(cli, data["step"](tip), 2, error_reply=True)
    require(quota["code"] == "context_session_budget_exhausted" and sorted(p.name for p in (data["session"] / "steps").iterdir()) == ["0001", "0002", "0003"],
            "exhausted session started or refunded another query")
    state = c.node_command(cli, ["status", *common, "--tip-sha256", tip])
    require(state["remaining"]["queries"] == 0 and [h["state"] for h in state["history"]] == ["read_refused", "captured", "captured"],
            "offline status lost a refused or captured acquisition")
    for prefix, expected_queries, expected_refusals, code, name in [(data["root"], 1, 0, 0, "base"), (tip, 3, 1, 3, "terminal")]:
        output = home / ("context-export-" + name)
        args = [*common, "--tip-sha256", prefix, "--output", str(output)]
        exported = c.node_command(cli, ["export", *args], code)
        checked = c.node_command(cli, ["inspect-export", *args, "--export-sha256", exported["manifest_sha256"]], code)
        require(exported["captured_queries"] == expected_queries and exported["refused_steps"] == expected_refusals
                and checked["replay_verified"] is True and exported["network_requests"] == 0
                and exported["all_captured_queries_complete"] is True and exported["authority_verified"] is False,
                "offline prefix export lost query provenance or exaggerated authority")
        material = json.loads((output / "context.json").read_bytes())
        require(material["context"]["query_count"] == expected_queries
                and all(bytes.fromhex(row["path_hex"]) in data["selected"] for row in material["context"]["files"]),
                "session export disclosed an unselected source path")
        for row in material["context"]["files"]:
            body = data["original"][bytes.fromhex(row["path_hex"])][1]
            for excerpt in row["excerpts"]:
                value = bytes.fromhex(excerpt["untrusted_bytes_hex"])
                require(body[excerpt["byte_offset"]:excerpt["byte_offset"] + len(value)] == value,
                        "session export bytes differ from independently selected native source")
        wrong = c.node_command(cli, ["inspect-export", *args, "--export-sha256", "0" * 64], 2, error_reply=True)
        require(wrong["code"] == "context_union_manifest_changed", "wrong export pin failed for an unrelated reason")
    require({p.name: p.read_bytes() for p in data["bundle"].iterdir()} == data["parent"], "offline session changed external custody")
    c.facts[f"{fmt}_native_context_session_dispatch_and_offline_export"] = True
    args = ["inspect", "--selection", str(data["selection"]), "--context", str(data["bundle"] / "capture.json"),
        "--context-sha256", data["context"]["capture_sha256"], "--proof", str(data["proof"])]
    inspected = c.node_command(data["proof_cli"], [*args, "--proof-sha256", data["proved"]["proof_sha256"]])
    require(inspected["source_commit"] == data["proved"]["source_commit"] and inspected["verified_file_count"] == len(data["selected"]),
            "offline proof lost independent source membership")
    wrong = c.node_command(data["proof_cli"], [*args, "--proof-sha256", "0" * 64], 2, error_reply=True)
    require(wrong["message"] == "Proof input differs from its independently retained hash.", "wrong proof pin failed for an unrelated reason")
    require(file_sha256(data["proof"]) == data["proved"]["proof_sha256"], "wrong proof pin changed retained evidence")
    c.facts[f"{fmt}_native_context_proof_offline_pins"] = True


def workspace_scan_case(c, home, fmt, workspace, workspace_hash, capture, captured, original, after, paths, result_tree):
    cli = ROOT / "scripts/fg_source_workspace_scan.mjs"
    scope = private_json(home / "scan-scope.json", dict(roots_hex=[""], exclude_hex=[], include_unselected=True))
    base = ["--workspace", str(workspace), "--sha256", workspace_hash]
    scan = c.node_command(cli, ["scan", *base, "--scope", str(scope)])
    report = private_json(home / "scan.json", scan)
    selected = c.node_command(cli, ["select", *base, "--scan", str(report), "--approve-scan-sha256", scan["scan_sha256"],
        "--byte-profile", "binary-safe-v1"])
    require(selected["paths_hex"] == [p.hex() for p in paths] and len(selected["observations"]) == len(paths),
            "scan did not select the independently expected changed paths")
    for row in scan["scan"]["entries"]:
        path = bytes.fromhex(row["path_hex"])
        require(path in paths, "sparse workspace scan invented another path")
        if path in original:
            require(row["before"]["sha256"] == hashlib.sha256(original[path][1]).hexdigest(), "scan changed baseline source bytes")
        if path in after:
            require(row["after"]["sha256"] == hashlib.sha256(after[path][1]).hexdigest()
                    and row["after"]["executable"] == (after[path][0] == b"100755"), "scan changed edited bytes or mode")
        else:
            require(row["state"] == "deleted" and row["after"] is None, "scan lost selected deletion")
    c.facts[f"{fmt}_native_workspace_scan_selection"] = True
    common = [*base, "--scan", str(report), "--approve-scan-sha256", scan["scan_sha256"]]
    refused = home / "scan-text-capture"
    binary = c.node_command(cli, ["capture", *common, "--output", str(refused)], 2, error_reply=True)
    require(binary["code"] == "source_changes_binary_unsupported", "default profile failed for an unrelated reason")
    require(not refused.exists(), "default text profile accepted the binary edit")
    output = home / "scan-capture"
    result = c.node_command(cli, ["capture", *common, "--byte-profile", "binary-safe-v1", "--output", str(output)])
    require(result["capture"]["expected_tree"] == result_tree
            and result["capture"]["draft_sha256"] == captured["draft_sha256"]
            and result["network_attempted"] is result["repository_changed"] is result["source_executed"] is False,
            "scan capture differs from independently selected manual/native-backed intent")
    for name in ("source.json", "expected.json", "changes.json"):
        require((output / name).read_bytes() == (capture / name).read_bytes(), "scan capture changed native source or intended edits")
    # Preserve both the reviewed state and a separately pinned later edit.
    edited = workspace / "files" / paths[0].decode()
    before = edited.read_bytes()
    edited.write_bytes(before + b"later local edit")
    stale = c.node_command(cli, ["select", *common, "--byte-profile", "binary-safe-v1"], 2, error_reply=True)
    require(stale["code"] == "source_workspace_scan_stale", "stale approved scan silently selected new bytes")
    edited.write_bytes(before)
    require((output / "changes.json").read_bytes() == (capture / "changes.json").read_bytes(), "stale refusal changed an existing capture")
    c.facts[f"{fmt}_native_workspace_scan_capture_and_stale_twin"] = True
