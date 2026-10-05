#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Compare a safe probe transcript with saved ANTT entry/exit and async records.

Absent native cases are SKIP, never an assertion that blindly calling a syscall
is safe. Presence is verified separately from payload decoder completeness.
"""
import argparse
import collections
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "src/antinomie/monitor/protocol/native-syscalls.json"


def packets(path):
    with path.open("rb") as raw:
        while prefix := raw.read(4):
            if len(prefix) != 4:
                raise ValueError("truncated length prefix")
            length, = struct.unpack("<I", prefix)
            if not 136 <= length <= 262112:
                raise ValueError(f"invalid packet size {length}")
            data = raw.read(length)
            if len(data) != length or data[:4] != b"ANTT":
                raise ValueError("truncated packet or bad magic")
            if struct.unpack_from("<HHH", data, 4) != (1, 1, 136):
                raise ValueError("unexpected schema/header")
            if struct.unpack_from("<I", data, 12)[0] != length:
                raise ValueError("packet framing mismatch")
            if struct.unpack_from("<I", data, 120)[0] != length - 136:
                raise ValueError("body framing mismatch")
            yield data


def fixed_async_report(raw, require_partial_read=False):
    """Check the two private fixed-buffer requests, never all async layouts."""
    events = {}
    for packet in packets(raw):
        if packet[98] != 3:
            continue
        identity = struct.unpack_from("<QQQ", packet, 24)
        event_id = struct.unpack_from("<Q", packet, 48)[0]
        event = events.setdefault(identity + (event_id,), {})
        if len(events) > 4096:
            raise ValueError("async verifier event budget exceeded")
        kind = packet[99]
        if kind not in (2, 3, 4):
            continue
        object_id = struct.unpack_from("<I", packet, 100)[0]
        field = event.setdefault(object_id, {"chunks": {}})
        if len(event) > 64:
            raise ValueError("async verifier field budget exceeded")
        if kind == 2:
            key_len, layout_len = struct.unpack_from("<HH", packet, 168)
            if len(packet) != 176 + key_len + layout_len:
                raise ValueError("bad async field metadata")
            field["key"] = packet[176:176 + key_len].decode("utf8", errors="strict")
        elif kind == 3:
            offset = struct.unpack_from("<Q", packet, 104)[0]
            # Retain only the test-sized prefix, not guest-declared extents.
            if offset < 8192:
                chunk = packet[136:136 + min(8192 - offset, len(packet) - 136)]
                previous = field["chunks"].get(offset)
                if previous is not None and previous != chunk:
                    raise ValueError("conflicting async payload chunk")
                field["chunks"][offset] = chunk
        else:
            if len(packet) != 168:
                raise ValueError("bad async field end")
            field["size"], field["captured"], field["status"] = struct.unpack_from("<QQI", packet, 136)
    observations = []
    for identity, fields in events.items():
        named = {}
        for field in fields.values():
            content = bytearray()
            for offset, chunk in sorted(field["chunks"].items()):
                if offset != len(content):
                    break
                content.extend(chunk)
            field["data"] = bytes(content)
            if "key" in field:
                named[field["key"]] = field
        observations.append((identity, named))

    def scalar(fields, key):
        field = fields.get(key, {})
        if field.get("status") == 0 and field.get("captured") == 8 and len(field.get("data", b"")) == 8:
            return struct.unpack("<Q", field["data"])[0]
        return None

    expected = b"ANTINOMIE-NATIVE-PAYLOAD\0"
    expected += b"U" * (4096 - len(expected))
    rows = []
    for user_data, opcode, direction, key in [
            (0x616e747600, 5, 1, "async.payload.input"),
            (0x616e747601, 4, 2, "async.payload.output")]:
        selected = [(identity, fields) for identity, fields in observations
                    if scalar(fields, "async.user_data") == user_data]
        request_ids = {scalar(fields, "async.request_id") for _, fields in selected}
        origins = {identity[:3] for identity, _ in selected}
        correlated = (len(request_ids) == 1 and None not in request_ids and 0 not in request_ids
                      and len(origins) == 1 and all(identity[2] != 0 for identity in origins))
        stages = {scalar(fields, "async.stage") for _, fields in selected}
        final = any(scalar(fields, "async.stage") == 4 and scalar(fields, "async.final") == 1
                    and scalar(fields, "async.result") == 4096 for _, fields in selected)
        payload = any(fields.get(key, {}).get("data") == expected
                      and fields[key].get("status") == 0
                      and fields[key].get("size") == fields[key].get("captured") == 4096
                      and scalar(fields, "async.payload.direction") == direction
                      and scalar(fields, "async.payload.requested_size") == 4096
                      and scalar(fields, "async.payload.result_offset") == 0
                      for _, fields in selected)
        correct_opcode = bool(selected) and all(scalar(fields, "async.opcode") == opcode
                                               for _, fields in selected)
        passed = correlated and {1, 2, 4}.issubset(stages) and final and payload and correct_opcode
        rows.append({"user_data": user_data, "opcode": opcode, "verdict": "PASS" if passed else "FAIL",
                     "observations": len(selected), "correlated": correlated,
                     "request_id": next(iter(request_ids)) if correlated else None,
                     "final_result_verified": final, "payload_verified": payload})
    result = {"scope": "two private 4096-byte registered-buffer io_uring operations only",
              "passed": all(row["verdict"] == "PASS" for row in rows)
                  and rows[0]["request_id"] != rows[1]["request_id"], "requests": rows}
    if require_partial_read:
        selected = [(identity, fields) for identity, fields in observations
                    if scalar(fields, "async.user_data") == 0x616e747602]
        request_ids = {scalar(fields, "async.request_id") for _, fields in selected}
        origins = {identity[:3] for identity, _ in selected}
        correlated = (len(request_ids) == 1 and None not in request_ids and 0 not in request_ids
                      and len(origins) == 1 and all(identity[2] != 0 for identity in origins))
        stages = {scalar(fields, "async.stage") for _, fields in selected}
        final = any(scalar(fields, "async.stage") == 4 and scalar(fields, "async.final") == 1
                    and scalar(fields, "async.result") == 8192 for _, fields in selected)
        expected_read = expected + b"V" * 4096
        segments = {}
        for _, fields in selected:
            field = fields.get("async.payload.output", {})
            offset = scalar(fields, "async.payload.result_offset")
            data = field.get("data", b"")
            if (offset is not None and 0 <= offset <= 8192 and data
                    and field.get("status") == 0
                    and field.get("size") == field.get("captured") == len(data)
                    and scalar(fields, "async.payload.direction") == 2
                    and scalar(fields, "async.opcode") == 4
                    and data == expected_read[offset:offset + len(data)]):
                segments[offset] = data
        position = 0
        for offset, data in sorted(segments.items()):
            if offset != position:
                break
            position += len(data)
        full = correlated and {1, 2, 4}.issubset(stages) and final and position == 8192
        retried = len(segments) >= 2 and any(offset > 0 for offset in segments)
        partial = {"verdict": "PASS" if full and retried else "FAIL",
                   "request_ids": sorted(value for value in request_ids if value is not None),
                   "payload_verified": full, "retry_observed": retried,
                   "captured_ranges": [[offset, len(data)] for offset, data in sorted(segments.items())]}
        result["partial_read"] = partial
        result["passed"] &= full and retried
    return result


def report(transcript, raw, inventory):
    cases = collections.defaultdict(list)
    text = transcript.read_text(errors="strict")
    if "NATIVE PASS" not in text:
        raise ValueError("probe did not complete its payload/cleanup checks")
    case_ids = set()
    for line in text.splitlines():
        if line.startswith("ANT_CASE "):
            item = json.loads(line.removeprefix("ANT_CASE "))
            if item["verdict"] not in ("PASS", "FAIL", "SKIP", "EXPECTED_REJECTION"):
                raise ValueError("invalid probe verdict")
            if (not isinstance(item.get("tid"), int) or item["tid"] <= 0
                    or not isinstance(item.get("case_id"), int) or item["case_id"] <= 0
                    or item["case_id"] in case_ids
                    or not isinstance(item.get("started_ns"), int)
                    or not isinstance(item.get("finished_ns"), int)
                    or not 0 < item["started_ns"] <= item["finished_ns"]):
                raise ValueError("invalid or absent probe identity/time interval; rerun updated probe")
            case_ids.add(item["case_id"])
            cases[item["number"]].append(item)
    if not cases:
        raise ValueError("probe produced no case results")
    summaries = collections.Counter()
    invocations = collections.defaultdict(dict)
    incomplete = collections.Counter()
    statuses = collections.defaultdict(collections.Counter)
    async_fields = collections.Counter()
    for packet in packets(raw):
        number, = struct.unpack_from("<Q", packet, 88)
        phase, kind = packet[98:100]
        if kind == 1:
            if len(packet) != 256:
                raise ValueError("bad event summary size")
            if phase in (1, 2):
                identity = struct.unpack_from("<QQQ", packet, 24)
                tid = struct.unpack_from("<I", packet, 76)[0]
                timestamp = struct.unpack_from("<Q", packet, 64)[0]
                value = struct.unpack_from("<q", packet, 192)[0]
                event = (number, tid, timestamp, value)
                previous = invocations[identity].get(phase)
                if previous is not None and previous != event:
                    raise ValueError("conflicting summary for invocation phase")
                if previous is None:
                    summaries[number, phase] += 1
                invocations[identity][phase] = event
        elif kind == 4:
            if len(packet) != 168:
                raise ValueError("bad field-end size")
            status, = struct.unpack_from("<I", packet, 152)
            statuses[number][status] += 1
        elif kind == 5:
            if len(packet) != 168:
                raise ValueError("bad event-end size")
            state, = struct.unpack_from("<Q", packet, 160)
            if state:
                incomplete[number] += 1
        elif phase == 3 and kind == 2:
            if len(packet) < 176:
                raise ValueError("bad field metadata size")
            key_len, layout_len = struct.unpack_from("<HH", packet, 168)
            if len(packet) != 176 + key_len + layout_len:
                raise ValueError("bad field key/layout lengths")
            key = packet[176:176 + key_len].decode("utf8", errors="strict")
            if key.startswith("async."):
                async_fields[key] += 1
    rows = []
    known = {item["number"] for item in inventory["syscalls"]}
    if set(cases) - known:
        raise ValueError("probe contains syscall outside pinned native table")
    for item in inventory["syscalls"]:
        nr = item["number"]
        observations = cases[nr]
        pairs = []
        for identity, phases in invocations.items():
            if 1 not in phases or 2 not in phases:
                continue
            entry, exit_event = phases[1], phases[2]
            if entry[0] == nr and exit_event[0] == nr and entry[1] == exit_event[1]:
                pairs.append((identity, entry, exit_event))
        used = set()
        matched = 0
        for case in observations:
            expected = case["result"] if case["result"] >= 0 else -case["errno"]
            for identity, entry, exit_event in pairs:
                if (identity not in used and entry[1] == case["tid"]
                        and exit_event[3] == expected
                        and case["started_ns"] <= entry[2] <= exit_event[2] <= case["finished_ns"]):
                    used.add(identity)
                    matched += 1
                    break
        verdict = "SKIP"
        reason = "No approved safe exercise implemented for this syscall yet"
        if observations:
            if any(case["name"] != item["name"] for case in observations):
                raise ValueError(f"probe name/number mismatch: {nr}")
            if any(case["verdict"] == "FAIL" for case in observations):
                verdict, reason = "FAIL", "Probe syscall or payload invariant failed"
            elif matched != len(observations):
                verdict, reason = "FAIL", "Missing distinct invocation pair matching task, time and return"
            elif all(case["verdict"] == "SKIP" for case in observations):
                reason = "Guest feature or permission unavailable; rejection was traced"
            else:
                verdict, reason = "PASS", "Safe exercise and entry/exit observed"
        rows.append({"number": nr, "name": item["name"], "verdict": verdict,
                     "reason": reason, "probe_calls": len(observations),
                     "matched_calls": matched,
                     "entry_events": summaries[nr, 1], "exit_events": summaries[nr, 2],
                     "capture_verdict": "INCOMPLETE" if incomplete[nr] else "NOT_VERIFIED",
                     "incomplete_events": incomplete[nr],
                     "field_statuses": dict(statuses[nr])})
    return {"kernel_version": inventory["kernel_version"], "native_count": len(rows),
            "summary": dict(collections.Counter(row["verdict"] for row in rows)),
            "async_field_counts": dict(async_fields),
            "payload_completeness_verified": False,
            "note": "PASS verifies this safe exercise and tracing, not all syscall layouts",
            "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recording", type=Path)
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-fixed-async", action="store_true")
    parser.add_argument("--require-partial-read", action="store_true")
    args = parser.parse_args()
    transcript = args.transcript or args.recording / "terminal-transcript.raw"
    result = report(transcript, args.recording / "telemetry.raw",
                    json.loads(INVENTORY.read_text()))
    if args.require_fixed_async or args.require_partial_read:
        result["fixed_async"] = fixed_async_report(args.recording / "telemetry.raw", args.require_partial_read)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))
    if result["summary"].get("FAIL", 0) or ((args.require_fixed_async or args.require_partial_read)
                                          and not result["fixed_async"]["passed"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
