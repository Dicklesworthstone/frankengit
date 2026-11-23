"""Compare native Initial rows and hydrated anchors with the original Git files."""
import hashlib
import json
import re
import sys
from pathlib import Path


def check_rows(report, files, algorithm, tip):
    auth = report["authorization"]
    assert (auth["host"], auth["scope"], auth["reusable_capability"]) == (
        "trusted-local-cli", "whole-repository", False,
    )
    assert re.fullmatch("[0-9a-f]{64}", auth["binding"])
    assert report["source_commit"] == tip and report["object_format"] == algorithm
    assert report["source_blobs_read"] == report["source_bytes_read"] == 0
    work = 0
    witnesses = {}
    labels = set()
    channels = [
        ("content", report["content"], "source-blob-bytes"),
        ("path", report["path"], "raw-path-bytes"),
    ]
    if report["symbols"]["state"] == "available":
        channels.append(("symbol", report["symbols"]["result"], "source-declaration-bytes"))
    for name, channel, domain in channels:
        assert channel["source_commit"] == tip
        work += channel["work_units"]
        rows = channel["matches" if name == "symbol" else "hits"]
        assert rows
        for row in rows:
            path = bytes.fromhex(row["path_hex"])
            payload = files[path]
            oid = hashlib.new(algorithm, b"blob %d\0" % len(payload) + payload).hexdigest()
            assert row["blob"] == oid and row["position_domain"] == domain
            label = row["authorization_label"]
            assert re.fullmatch("[0-9a-f]{64}", label) and label not in labels
            labels.add(label)
            spans = [(row["byte_offset"], row["match_length"])] if name == "symbol" else [
                (s["byte_offset"], s["byte_length"]) for s in row["spans"]]
            assert spans
            source = path if name == "path" else payload
            for offset, length in spans:
                assert source[offset:offset + length] == b"Thing"
                witnesses[(row["path_hex"], name, offset, length)] = (label, domain)
    assert report["completed_work_units"] == work <= report["max_work"]
    assert report["completed_payload_bytes_read"] <= report["max_payload_bytes"]
    assert report["retained_result_bytes"] <= report["max_result_bytes"]
    return witnesses


def main():
    output, source = map(Path, sys.argv[1:3])
    algorithm, tip = sys.argv[3:]
    files = {name: (source / name.decode()).read_bytes() for name in
             (b"src/Thing.rs", b"src/comment.rs", b"src2/Thing.rs")}
    initial = json.loads((output / "initial.json").read_text())
    assert initial["symbols"]["state"] == "available"
    check_rows(initial, files, algorithm, tip)
    for mode in ("context", "raw"):
        packet = json.loads((output / (mode + ".json")).read_text())
        expected = check_rows(packet["retrieval"], files, algorithm, tip)
        used = set()
        for item in packet["files"]:
            labels = set()
            for anchor in item["anchors"]:
                key = (item["path_hex"], anchor["channel"], anchor["byte_offset"], anchor["byte_length"])
                assert key not in used
                assert expected[key] == (anchor["authorization_label"], anchor["position_domain"])
                labels.add(anchor["authorization_label"])
                used.add(key)
            assert labels and labels == set(item["authorization_labels"])
        assert used == set(expected)


if __name__ == "__main__":
    main()
