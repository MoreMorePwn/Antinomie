#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Boot a four-vCPU disposable root with no QMP socket or persistent image write.

Usage: python3 tests/monitor/run-guest-resource-probe.py BASE_DIRECTORY
This tests actual guest collector execution; it does not qualify host controls,
snapshot/reconnect ownership, or native UI. The base is opened with -snapshot.
"""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def entry(name, data, mode, index):
    name = name.encode() + b'\0'
    fields = [index, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(name), 0]
    header = b'070701' + ''.join(f'{value:08x}' for value in fields).encode()
    result = header + name
    result += b'\0' * (-len(result) % 4)
    result += data
    return result + b'\0' * (-len(data) % 4)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base_directory', type=Path)
    args = parser.parse_args()
    base = args.base_directory.resolve()
    for name in ('kernel', 'base.qcow2'):
        if not (base / name).is_file():
            parser.error(f'base lacks {name}')
    with tempfile.TemporaryDirectory(prefix='antinomie-guest-resource-') as directory:
        work = Path(directory)
        compiler = os.environ.get('ANTINOMIE_GUEST_CC', 'musl-gcc')
        for output, source in [
            ('init', ROOT / 'tests/monitor/guest-resource-init.c'),
            ('probe', ROOT / 'src/antinomie/monitor/crates/monitor-core/src/guest_resources.c'),
        ]:
            subprocess.run([compiler, '-static', '-Os', '-s', '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-o', str(work / output), str(source)], check=True)
        archive = b''.join(entry(name, (work / name).read_bytes(), 0o100755, index)
                           for index, name in enumerate(('init', 'probe'), 1))
        archive += entry('TRAILER!!!', b'', 0, 3)
        (work / 'initrd').write_bytes(archive)
        disk_path = str(base / 'base.qcow2').replace(',', ',,')
        command = ['qemu-system-x86_64', '-machine', 'q35,accel=tcg', '-m', '512', '-smp', '4',
                   '-nodefaults', '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-nic', 'none',
                   '-kernel', str(base / 'kernel'), '-initrd', str(work / 'initrd'),
                   '-append', 'console=ttyS0 quiet panic=1', '-snapshot',
                   '-drive', f'file={disk_path},if=virtio,format=qcow2', '-no-reboot']
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90, text=True,
                                env={**os.environ, "TMPDIR": str(work)})
        print(result.stdout, end='')
        if result.returncode or 'ANTINOMIE_RESOURCE_PROBE PASS' not in result.stdout:
            raise SystemExit('guest resource qualification failed')
        print('PASS: actual guest proc/meminfo + root statvfs; static launch, self-unlink and EOF cleanup, 4 vCPU / 512 MiB / TCG')


if __name__ == '__main__':
    main()
