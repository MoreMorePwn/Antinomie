#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Qualify the actual static collector in pipe and PTY sessions, without a VM."""
import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import time
import unittest

SOURCE = Path(__file__).resolve().parents[2] / 'src/antinomie/monitor/crates/monitor-core/src/guest_resources.c'
TOKEN = '0123456789abcdef0123456789abcdef'


def line(fd, timeout=4):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while time.monotonic() < deadline and len(data) < 1024:
        if select.select([fd], [], [], max(0, deadline - time.monotonic()))[0]:
            char = os.read(fd, 1)
            if not char:
                raise AssertionError('collector exited before a complete report')
            data.extend(char)
            if char == b'\n':
                return data.decode('ascii').strip().split()
    raise AssertionError('collector output timeout or excessive frame')


class CollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='antinomie-collector-test-')
        cls.binary = Path(cls.directory.name) / 'template'
        subprocess.run([os.environ.get('ANTINOMIE_GUEST_CC', 'musl-gcc'), '-static', '-Os', '-s',
                        '-std=c11', '-Wall', '-Wextra', '-Werror', '-o', str(cls.binary), str(SOURCE)], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def launch(self, token=TOKEN, terminal=False):
        path = Path(self.directory.name) / str(time.monotonic_ns())
        shutil.copy2(self.binary, path)
        if terminal:
            master, slave = pty.openpty()
            process = subprocess.Popen([str(path), token], stdin=slave, stdout=slave, stderr=slave)
            os.close(slave)
            self.addCleanup(os.close, master)
            source, sink = master, master
        else:
            process = subprocess.Popen([str(path), token], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            source, sink = process.stdout.fileno(), process.stdin.fileno()
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=2)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        self.addCleanup(cleanup)
        return process, path, source, sink

    def check_report(self, fields, sequence):
        self.assertEqual(fields[:3], ['ANTRES1', TOKEN, str(sequence)])
        self.assertEqual(len(fields), 11)
        mem_error, total, available, disk_error, blocks, free, allowed, fragment = map(int, fields[3:])
        self.assertEqual(mem_error, 0)
        self.assertEqual(disk_error, 0)
        host_total = next(int(row.split()[1]) * 1024 for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith('MemTotal:'))
        self.assertEqual(total, host_total)
        self.assertLessEqual(available, total)
        self.assertGreater(fragment, 0)
        self.assertGreater(blocks, 0)
        self.assertLessEqual(allowed, free)
        self.assertLessEqual(free, blocks)
        # This qualification runs on the test host, not a guest telemetry claim.
        host_disk = os.statvfs('/')
        self.assertEqual(blocks, host_disk.f_blocks)
        self.assertEqual(fragment, host_disk.f_frsize)

    def test_static_elf_has_no_dynamic_loader(self):
        header = self.binary.read_bytes()[:20]
        self.assertEqual(header[:5], b'\x7fELF\x02')
        self.assertEqual(int.from_bytes(header[18:20], 'little'), 62)
        output = subprocess.check_output(['readelf', '-l', str(self.binary)], text=True)
        self.assertNotIn('INTERP', output)

    def test_pipe_sampling_unlinks_and_exits_on_input_close(self):
        process, path, source, sink = self.launch()
        self.assertEqual(line(source), ['ANTREADY1', TOKEN])
        self.assertFalse(path.exists())
        for sequence in (1, 2):
            os.write(sink, f'{sequence}\n'.encode())
            self.check_report(line(source), sequence)
        process.stdin.close()
        self.assertEqual(process.wait(timeout=2), 0)

    def test_pty_ready_handshake_prevents_echo_and_preserves_framing(self):
        process, path, source, sink = self.launch(terminal=True)
        self.assertEqual(line(source), ['ANTREADY1', TOKEN])
        self.assertFalse(path.exists())
        os.write(sink, b'1\n')
        self.check_report(line(source), 1)
        os.write(sink, b'1\n')
        self.assertEqual(process.wait(timeout=2), 6)

    def test_invalid_token_cannot_unlink_an_unstarted_executable(self):
        process, path, _, _ = self.launch(token='bad')
        self.assertEqual(process.wait(timeout=2), 2)
        self.assertTrue(path.exists())

    def test_idle_lease_ends_without_host_cleanup(self):
        process, path, source, _ = self.launch()
        self.assertEqual(line(source), ['ANTREADY1', TOKEN])
        self.assertFalse(path.exists())
        self.assertEqual(process.wait(timeout=34), 0)


if __name__ == '__main__':
    unittest.main()
