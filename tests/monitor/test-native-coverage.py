#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

MODULE = Path(__file__).with_name("verify-native-coverage.py")
SPEC = importlib.util.spec_from_file_location("coverage", MODULE)
coverage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(coverage)


def summary(number, phase, result=0, task=11, call=1, tid=20, timestamp=None):
    data = bytearray(256)
    data[:4] = b"ANTT"
    struct.pack_into("<HHH", data, 4, 1, 1, 136)
    struct.pack_into("<I", data, 12, len(data))
    struct.pack_into("<Q", data, 88, number)
    struct.pack_into("<QQQ", data, 24, 1, task, call)
    struct.pack_into("<Q", data, 64, timestamp if timestamp is not None else 100 + phase)
    struct.pack_into("<I", data, 76, tid)
    struct.pack_into("<I", data, 120, 120)
    data[98:100] = bytes((phase, 1))
    struct.pack_into("<q", data, 192, result)
    return struct.pack("<I", len(data)) + data


def field_packets(event_id, object_id, key, content, status=0, request_call=1):
    def packet(kind, body):
        header = bytearray(summary(426, 3, call=request_call)[4:140])
        struct.pack_into("<Q", header, 48, event_id)
        struct.pack_into("<I", header, 100, object_id)
        struct.pack_into("<Q", header, 112, len(content))
        struct.pack_into("<I", header, 120, len(body))
        struct.pack_into("<I", header, 12, 136 + len(body))
        header[99] = kind
        return struct.pack("<I", 136 + len(body)) + header + body
    name = key.encode()
    begin = bytearray(40)
    struct.pack_into("<HH", begin, 32, len(name), 0)
    end = struct.pack("<QQIiQ", len(content), len(content), status, 0, 1)
    return packet(2, begin + name) + packet(3, content) + packet(4, end)


def fixed_observations(bad_payload=False, duplicate_request=False):
    raw = bytearray()
    payload = b"ANTINOMIE-NATIVE-PAYLOAD\0"
    payload += b"U" * (4096 - len(payload))
    for request, (user_data, opcode, direction, key) in enumerate([
            (0x616e747600, 5, 1, "async.payload.input"),
            (0x616e747601, 4, 2, "async.payload.output")]):
        for stage in [1, 2, 4]:
            event_id = 100 + request * 10 + stage
            values = {"async.request_id": 1 if duplicate_request else request + 1,
                      "async.user_data": user_data, "async.opcode": opcode,
                      "async.stage": stage, "async.final": int(stage == 4),
                      "async.result": 4096 if stage == 4 else 0}
            payload_stage = 1 if direction == 1 else 4
            if stage == payload_stage:
                values |= {"async.payload.direction": direction,
                           "async.payload.requested_size": 4096,
                           "async.payload.result_offset": 0}
            for object_id, (name, value) in enumerate(values.items(), 1):
                raw.extend(field_packets(event_id, object_id, name, struct.pack("<Q", value),
                                         request_call=request + 1))
            if stage == payload_stage:
                content = b"X" * 4096 if bad_payload else payload
                raw.extend(field_packets(event_id, 20, key, content, request_call=request + 1))
    return bytes(raw)


def retry_observations(prefix=True, whole=False):
    raw = bytearray(fixed_observations())
    content = b"ANTINOMIE-NATIVE-PAYLOAD\0"
    content += b"U" * (4096 - len(content)) + b"V" * 4096
    records = [(1, None), (2, None)]
    if whole:
        records.append((4, (0, content)))
    else:
        if prefix:
            records.append((4, (0, content[:4096])))
        records.append((4, (4096, content[4096:])))
    records.append((4, None))
    for index, (stage, segment) in enumerate(records):
        values = {"async.request_id": 3, "async.user_data": 0x616e747602,
                  "async.opcode": 4, "async.stage": stage,
                  "async.final": int(index == len(records) - 1),
                  "async.result": 8192 if index == len(records) - 1 else 0}
        if segment:
            offset, data = segment
            values |= {"async.payload.direction": 2, "async.payload.requested_size": len(data),
                       "async.payload.result_offset": offset}
        event = 200 + index
        for object_id, (name, value) in enumerate(values.items(), 1):
            raw.extend(field_packets(event, object_id, name, struct.pack("<Q", value), request_call=3))
        if segment:
            raw.extend(field_packets(event, 20, "async.payload.output", data, request_call=3))
    return bytes(raw)


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.transcript = self.root / "terminal"
        self.raw = self.root / "telemetry"
        self.inventory = {"kernel_version": "6.12.94", "syscalls": [
            {"number": 0, "name": "read"}, {"number": 1, "name": "write"}]}
        self.transcript.write_text('ANT_CASE ' + json.dumps({"name": "read", "number": 0,
                                  "result": 7, "errno": 0, "verdict": "PASS",
                                  "case_id": 1, "tid": 20, "started_ns": 100,
                                  "finished_ns": 110}) + '\nNATIVE PASS\n')
        self.raw.write_bytes(summary(0, 1) + summary(0, 2, 7))

    def report(self):
        return coverage.report(self.transcript, self.raw, self.inventory)

    def test_safe_presence_does_not_claim_payload_or_skipped_coverage(self):
        result = self.report()
        self.assertEqual(result["summary"], {"PASS": 1, "SKIP": 1})
        self.assertFalse(result["payload_completeness_verified"])

    def test_missing_exit_is_failure(self):
        self.raw.write_bytes(summary(0, 1))
        self.assertEqual(self.report()["cases"][0]["verdict"], "FAIL")

    def test_wrong_return_is_failure(self):
        self.raw.write_bytes(summary(0, 1) + summary(0, 2, 9))
        self.assertEqual(self.report()["cases"][0]["verdict"], "FAIL")

    def test_unrelated_task_or_call_cannot_supply_exit(self):
        for task, call in [(22, 1), (11, 2)]:
            self.raw.write_bytes(summary(0, 1) + summary(0, 2, 7, task=task, call=call))
            self.assertEqual(self.report()["cases"][0]["verdict"], "FAIL")

    def test_one_pair_cannot_pass_five_repeated_cases(self):
        lines = self.transcript.read_text().splitlines()
        item = json.loads(lines[0].removeprefix("ANT_CASE "))
        self.transcript.write_text(''.join("ANT_CASE " + json.dumps(item | {"case_id": i}) + '\n'
                                         for i in range(1, 6)) + "NATIVE PASS\n")
        result = self.report()["cases"][0]
        self.assertEqual(result["verdict"], "FAIL")
        self.assertEqual(result["matched_calls"], 1)

    def test_wrong_tid_or_time_cannot_match(self):
        self.raw.write_bytes(summary(0, 1, tid=99) + summary(0, 2, 7, tid=99))
        self.assertEqual(self.report()["cases"][0]["verdict"], "FAIL")
        self.raw.write_bytes(summary(0, 1, timestamp=90) + summary(0, 2, 7))
        self.assertEqual(self.report()["cases"][0]["verdict"], "FAIL")

    def test_name_mismatch_is_rejected(self):
        self.inventory["syscalls"][0]["name"] = "wrong"
        with self.assertRaisesRegex(ValueError, "name/number"):
            self.report()

    def test_truncated_packet_is_rejected(self):
        self.raw.write_bytes(summary(0, 1)[:-1])
        with self.assertRaisesRegex(ValueError, "truncated"):
            self.report()

    def test_incomplete_probe_is_rejected(self):
        self.transcript.write_text("NATIVE READY\n")
        with self.assertRaisesRegex(ValueError, "did not complete"):
            self.report()

    def test_fixed_async_checks_actual_payload_and_distinct_request_identity(self):
        self.raw.write_bytes(fixed_observations())
        self.assertTrue(coverage.fixed_async_report(self.raw)["passed"])
        self.raw.write_bytes(fixed_observations(bad_payload=True))
        self.assertFalse(coverage.fixed_async_report(self.raw)["passed"])
        self.raw.write_bytes(fixed_observations(duplicate_request=True))
        self.assertFalse(coverage.fixed_async_report(self.raw)["passed"])

    def test_missing_fixed_async_is_failure_not_metadata_coverage(self):
        self.assertFalse(coverage.fixed_async_report(self.raw)["passed"])

    def test_partial_read_requires_prefix_and_tail_not_just_final_success(self):
        self.raw.write_bytes(retry_observations())
        result = coverage.fixed_async_report(self.raw, require_partial_read=True)
        self.assertTrue(result["passed"])
        self.assertEqual(result["partial_read"]["captured_ranges"], [[0, 4096], [4096, 4096]])
        self.raw.write_bytes(retry_observations(prefix=False))
        self.assertFalse(coverage.fixed_async_report(self.raw, require_partial_read=True)["passed"])

    def test_whole_read_does_not_prove_retry_branch_was_exercised(self):
        self.raw.write_bytes(retry_observations(whole=True))
        result = coverage.fixed_async_report(self.raw, require_partial_read=True)
        self.assertTrue(result["partial_read"]["payload_verified"])
        self.assertFalse(result["partial_read"]["retry_observed"])
        self.assertFalse(result["passed"])


if __name__ == "__main__":
    unittest.main()
