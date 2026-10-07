#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Compare a safe probe transcript with saved ANTT entry/exit and async records.

Absent native cases are SKIP, never an assertion that blindly calling a syscall
is safe. Presence is verified separately from payload decoder completeness.
"""
import argparse
import collections
import errno
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INVENTORY = ROOT / "src/antinomie/monitor/protocol/native-syscalls.json"
STATUS_NAMES = ["COMPLETE", "COPY_FAULT", "INVALID_EXTENT", "UNKNOWN_EXTENT", "NO_DECODER",
                "NULL_POINTER", "ADDRESS_ONLY", "ASYNC_UNOBSERVED", "RESOURCE_EXHAUSTED",
                "ABORTED_ON_LOSS", "CONTEXT_MISSING", "NOT_WRITTEN"]
U64_MAX = (1 << 64) - 1
FIELD_DATA_BUDGET = 1 << 20


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


def report(transcript, raw, inventory, fixture_numbers=frozenset()):
    """fixture_numbers selects syscalls whose entry/exit field records are kept."""
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
            if "label" in item and not isinstance(item["label"], str):
                raise ValueError("invalid probe case label")
            cases[item["number"]].append(item)
    if not cases:
        raise ValueError("probe produced no case results")
    summaries = collections.Counter()
    invocations = collections.defaultdict(dict)
    incomplete = collections.Counter()
    statuses = collections.defaultdict(collections.Counter)
    async_fields = collections.Counter()
    fields = collections.defaultdict(dict)
    retained = 0
    for packet in packets(raw):
        number, = struct.unpack_from("<Q", packet, 88)
        phase, kind = packet[98:100]
        if number in fixture_numbers and phase in (1, 2) and kind in (2, 3, 4):
            identity = struct.unpack_from("<QQQ", packet, 24)
            object_id, = struct.unpack_from("<I", packet, 100)
            field = fields[identity].setdefault((phase, object_id), {"chunks": {}})
            if kind == 2:
                key_len, layout_len = struct.unpack_from("<HH", packet, 168)
                if len(packet) != 176 + key_len + layout_len:
                    raise ValueError("bad field key/layout lengths")
                field["arg"] = packet[136]
                field["address"], = struct.unpack_from("<Q", packet, 144)
                field["declared"], = struct.unpack_from("<Q", packet, 160)
                field["key"] = packet[176:176 + key_len].decode("utf8", errors="strict")
                field["layout"] = packet[176 + key_len:].decode("utf8", errors="strict")
            elif kind == 3:
                offset, = struct.unpack_from("<Q", packet, 104)
                chunk = packet[136:]
                retained += len(chunk)
                if retained > FIELD_DATA_BUDGET:
                    raise ValueError("fixture field data budget exceeded")
                field["chunks"][offset] = chunk
            else:
                field["size"], field["captured"], status = struct.unpack_from("<QQI", packet, 136)
                field["status"] = STATUS_NAMES[status] if status < len(STATUS_NAMES) else str(status)
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
                    case["identity"] = identity
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
            elif item.get("implemented") is False:
                if all(case["verdict"] == "EXPECTED_REJECTION" and case["errno"] == 38
                       for case in observations):
                    verdict, reason = "EXPECTED_ENOSYS", "No entry point; ENOSYS was traced"
                else:
                    verdict, reason = "FAIL", "Unimplemented row did not return ENOSYS"
            else:
                verdict, reason = "PASS", "Safe exercise and entry/exit observed"
        rows.append({"number": nr, "name": item["name"], "verdict": verdict,
                     "reason": reason, "probe_calls": len(observations),
                     "matched_calls": matched,
                     "entry_events": summaries[nr, 1], "exit_events": summaries[nr, 2],
                     "capture_verdict": "INCOMPLETE" if incomplete[nr] else "NOT_VERIFIED",
                     "incomplete_events": incomplete[nr],
                     "field_statuses": dict(statuses[nr])})
    labeled = {}
    for observations in cases.values():
        for case in observations:
            if "label" in case:
                if case["label"] in labeled:
                    raise ValueError(f"duplicate probe case label {case['label']}")
                labeled[case["label"]] = case
    return {"_labeled": labeled, "_fields": fields,
            "kernel_version": inventory["kernel_version"], "native_count": len(rows),
            "summary": dict(collections.Counter(row["verdict"] for row in rows)),
            "async_field_counts": dict(async_fields),
            "payload_completeness_verified": False,
            "note": "PASS verifies this safe exercise and tracing, not all syscall layouts",
            "cases": rows}


def expected_result(case, result):
    if "|" in result:
        return any(expected_result(case, choice) for choice in result.split("|"))
    if result == "zero":
        return case["result"] == 0
    if result == "nonnegative":
        return case["result"] >= 0
    if result == "positive":
        return case["result"] > 0
    # Compare numbers: aliases such as EOPNOTSUPP and ENOTSUP share one value.
    number = getattr(errno, result.removeprefix("errno:"), None)
    return case["result"] < 0 and number is not None and case["errno"] == number


def field_problems(expected, actual, observed, result=None):
    problems = []
    seen = observed.get(expected["key"])
    for member in ("arg", "layout", "size", "captured", "declared", "status"):
        want = expected[member]
        if want == "observed":
            want = len(bytes.fromhex(seen)) if seen is not None else None
        want = U64_MAX if want == "max" else result if want == "result" else want
        if actual.get(member) != want:
            problems.append(f"{member} {actual.get(member)!r} != {want!r}")
    data = bytearray()
    for offset, chunk in sorted(actual["chunks"].items()):
        if offset != len(data):
            problems.append("noncontiguous chunks")
            break
        data.extend(chunk)
    data = bytes(data[:actual.get("captured", 0)])
    if expected["data"] == "observed":
        want = observed.get(expected["key"])
        if want is None or data.hex() != want:
            problems.append(f"data {data.hex()} != observed {want}")
    elif expected["data"] is not None and data.hex() != expected["data"]:
        problems.append(f"data {data.hex()} != {expected['data']}")
    if expected.get("address") == "nonzero" and not actual.get("address"):
        problems.append("address is zero")
    return problems


def schema_report(fixture_dir, labeled, fields):
    """Compare every fixture case with the fields recorded for its invocation."""
    rows = []
    for path in sorted(fixture_dir.glob("*.json")):
        document = json.loads(path.read_text())
        for expected in document["cases"]:
            problems = []
            case = labeled.get(expected["label"])
            if case is None:
                problems.append("probe case missing")
            elif "identity" not in case:
                problems.append("no matching invocation pair")
            else:
                if not expected_result(case, expected["result"]):
                    problems.append(f"result {case['result']} errno {case['errno']}")
                recorded = {}
                for (phase, _), field in fields.get(case["identity"], {}).items():
                    name = ("entry" if phase == 1 else "exit", field.get("key"))
                    if name in recorded:
                        problems.append(f"duplicate field {name}")
                    recorded[name] = field
                observed = case.get("observed", {})
                # A when_observed field exists exactly when the probe reported it.
                wanted = {(item["phase"], item["key"]): item for item in expected["fields"]
                          if not item.get("when_observed") or item["key"] in observed}
                for name in sorted(set(recorded) - set(wanted)):
                    problems.append(f"unexpected field {name}")
                for name, item in sorted(wanted.items()):
                    if name not in recorded:
                        problems.append(f"missing field {name}")
                    else:
                        problems.extend(f"{name[0]} {name[1]}: {problem}" for problem in
                                        field_problems(item, recorded[name],
                                                       case.get("observed", {}),
                                                       case["result"]))
            rows.append({"slice": document["slice"], "label": expected["label"],
                         "verdict": "FAIL" if problems else "PASS", "problems": problems})
    return {"passed": bool(rows) and all(row["verdict"] == "PASS" for row in rows),
            "summary": dict(collections.Counter(row["verdict"] for row in rows)),
            "cases": rows}


ASYNC_FLAGS = {"PAYLOAD_GAP": 1, "PRODUCER_UNKNOWN": 2, "ABANDONED": 4}


def async_events(raw, budget=8192):
    """Every async event (phase 3) with its fields, keyed by key."""
    events = {}
    retained = 0
    for packet in packets(raw):
        if packet[98] != 3:
            continue
        identity = struct.unpack_from("<QQQ", packet, 24) + struct.unpack_from("<Q", packet, 48)
        event = events.setdefault(identity, {})
        if len(events) > 16384:
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
            field["layout"] = packet[176 + key_len:].decode("utf8", errors="strict")
        elif kind == 3:
            offset = struct.unpack_from("<Q", packet, 104)[0]
            if offset < budget:
                chunk = packet[136:136 + min(budget - offset, len(packet) - 136)]
                retained += len(chunk)
                if retained > FIELD_DATA_BUDGET:
                    raise ValueError("async field data budget exceeded")
                field["chunks"][offset] = chunk
        else:
            if len(packet) != 168:
                raise ValueError("bad async field end")
            field["size"], field["captured"], status = struct.unpack_from("<QQI", packet, 136)
            field["status"] = STATUS_NAMES[status] if status < len(STATUS_NAMES) else str(status)
    result = []
    for fields in events.values():
        named = {}
        for field in fields.values():
            data = bytearray()
            for offset, chunk in sorted(field["chunks"].items()):
                if offset != len(data):
                    break
                data.extend(chunk)
            field["data"] = bytes(data[:field.get("captured", 0)])
            if "key" in field:
                named[field["key"]] = field
        result.append(named)
    return result


def async_scalar(fields, key):
    field = fields.get(key, {})
    if field.get("status") == "COMPLETE" and len(field.get("data", b"")) == 8:
        return struct.unpack("<Q", field["data"])[0]
    return None


def async_transcript(transcript):
    """ANT_ASYNC lines: the probe's own view of each labeled request."""
    reported = {}
    for line in transcript.read_text(errors="strict").splitlines():
        if line.startswith("ANT_ASYNC "):
            item = json.loads(line.removeprefix("ANT_ASYNC "))
            if item["label"] in reported:
                raise ValueError(f"duplicate async probe label {item['label']}")
            reported[item["label"]] = item
    return reported


def async_field_problems(expected, actual, observed):
    problems = []
    seen = observed.get(expected["key"])
    for member in ("layout", "size", "status"):
        want = expected[member]
        if want == "observed":
            want = len(bytes.fromhex(seen)) if seen is not None else None
        if actual.get(member) != want:
            problems.append(f"{member} {actual.get(member)!r} != {want!r}")
    complete = actual.get("status") == "COMPLETE"
    if actual.get("captured") != (actual.get("size") if complete else 0):
        problems.append(f"captured {actual.get('captured')!r} for {actual.get('status')}")
    data = actual.get("data", b"")
    if expected["data"] == "observed":
        if seen is None or data.hex() != seen:
            problems.append(f"data {data.hex()[:64]} != observed {str(seen)[:64]}")
    elif expected["data"] is not None and data.hex() != expected["data"]:
        problems.append(f"data {data.hex()} != {expected['data']}")
    return problems


def async_fixture_report(fixture_dir, raw, transcript, run_status=None):
    """Contract revision 7, 14.7: requests are matched by user_data."""
    events = async_events(raw)
    reported = async_transcript(transcript)
    rows = []
    for path in sorted(fixture_dir.glob("*.json")):
        document = json.loads(path.read_text())
        for expected in document["cases"]:
            problems = []
            user_data = int(expected["user_data"], 16)
            selected = [fields for fields in events
                        if async_scalar(fields, "async.user_data") == user_data]
            probe = reported.get(expected["label"])
            if probe is None:
                problems.append("probe case missing")
            elif int(probe["user_data"], 16) != user_data:
                problems.append("probe user_data mismatch")
            request_ids = {async_scalar(fields, "async.request_id") for fields in selected}
            if len(request_ids) != 1 or None in request_ids or 0 in request_ids:
                problems.append(f"request ids {sorted(map(str, request_ids))}")
            stages = sorted({async_scalar(fields, "async.stage") for fields in selected},
                            key=str)
            if stages != sorted(expected["stages"]):
                problems.append(f"stages {stages} != {expected['stages']}")
            finals = [fields for fields in selected if async_scalar(fields, "async.final") == 1]
            last = finals[-1] if finals else (selected[-1] if selected else {})
            flags = async_scalar(last, "async.flags") or 0
            for name in expected.get("flags_set", []):
                if not flags & ASYNC_FLAGS[name]:
                    problems.append(f"flag {name} not set")
            for name in expected.get("flags_clear", []):
                if flags & ASYNC_FLAGS[name]:
                    problems.append(f"flag {name} set")
            observed = probe.get("observed", {}) if probe else {}
            for item in expected["fields"]:
                matches = [fields[item["key"]] for fields in selected
                           if item["key"] in fields
                           and async_scalar(fields, "async.stage") == item["stage"]]
                name = f"stage {item['stage']} {item['key']}"
                if len(matches) != 1:
                    problems.append(f"{name}: {len(matches)} records")
                else:
                    problems.extend(f"{name}: {problem}" for problem in
                                    async_field_problems(item, matches[0], observed))
            rows.append({"slice": document["slice"], "label": expected["label"],
                         "verdict": "FAIL" if problems else "PASS", "problems": problems,
                         "events": len(selected)})
        stress = document.get("stress")
        if stress:
            problems = []
            if run_status is None:
                problems.append("stress run status not supplied")
            else:
                losses = run_status.get("async_loss_count", 0)
                incomplete = bool(run_status.get("flags", 0) & 16)
                if losses < stress["run"]["async_loss_min"]:
                    problems.append(f"async losses {losses}")
                if incomplete != stress["run"]["incomplete"]:
                    problems.append(f"incomplete {incomplete}")
            rows.append({"slice": document["slice"], "label": stress["label"],
                         "verdict": "FAIL" if problems else "PASS", "problems": problems,
                         "run_status": run_status})
    return {"passed": bool(rows) and all(row["verdict"] == "PASS" for row in rows),
            "summary": dict(collections.Counter(row["verdict"] for row in rows)),
            "cases": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("recording", type=Path)
    parser.add_argument("--transcript", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-fixed-async", action="store_true")
    parser.add_argument("--require-partial-read", action="store_true")
    parser.add_argument("--schema-fixtures", type=Path,
                        help="directory of native-schema fixture files to enforce")
    parser.add_argument("--async-fixtures", type=Path,
                        help="directory of native-schema-async fixture files to enforce")
    parser.add_argument("--async-run-status", type=Path,
                        help="headless report (stress_execution) for the async stress block")
    args = parser.parse_args()
    transcript = args.transcript or args.recording / "terminal-transcript.raw"
    inventory = json.loads(INVENTORY.read_text())
    numbers = {}
    if args.schema_fixtures:
        names = {item["name"]: item["number"] for item in inventory["syscalls"]}
        for path in args.schema_fixtures.glob("*.json"):
            for case in json.loads(path.read_text())["cases"]:
                numbers[case.get("number", names.get(case["syscall"]))] = True
    result = report(transcript, args.recording / "telemetry.raw", inventory,
                    frozenset(numbers))
    labeled, fields = result.pop("_labeled"), result.pop("_fields")
    if args.schema_fixtures:
        result["schema_fixtures"] = schema_report(args.schema_fixtures, labeled, fields)
    if args.async_fixtures:
        status = None
        if args.async_run_status:
            document = json.loads(args.async_run_status.read_text())
            status = document.get("stress_execution", document)
        result["async_fixtures"] = async_fixture_report(
            args.async_fixtures, args.recording / "telemetry.raw", transcript, status)
    if args.require_fixed_async or args.require_partial_read:
        result["fixed_async"] = fixed_async_report(args.recording / "telemetry.raw", args.require_partial_read)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result["summary"]))
    if args.schema_fixtures:
        print(json.dumps({"schema_fixtures": result["schema_fixtures"]["summary"]}))
    if args.async_fixtures:
        print(json.dumps({"async_fixtures": result["async_fixtures"]["summary"]}))
    if result["summary"].get("FAIL", 0) or ((args.require_fixed_async or args.require_partial_read)
                                          and not result["fixed_async"]["passed"]) or (
            args.schema_fixtures and not result["schema_fixtures"]["passed"]) or (
            args.async_fixtures and not result["async_fixtures"]["passed"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
