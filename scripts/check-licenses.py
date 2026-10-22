#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Check the host license boundary and inventory locked Cargo dependencies.

This is a metadata/provenance gate, not a determination of legal clearance.
--output DIR also retains dependency license/notice documents for packaging.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
MONITOR = ROOT / 'src/antinomie/monitor'
HOST_LICENSE = 'GPL-3.0-only'
PERMITTED = {
    'MIT', 'MIT-0', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', '0BSD',
    'ISC', 'BSL-1.0', 'Zlib', 'Unlicense', 'CC0-1.0', 'Unicode-3.0',
    'GPL-3.0-only', 'GPL-3.0-or-later',
    # Font data retains its independent license; do not relabel it as host code.
    'OFL-1.1', 'Ubuntu-font-1.0',
}
SHARED = (
    'src/antinomie/transport/abi.h', 'src/antinomie/transport/queue.h',
    'src/antinomie/transport/bootstrap_layout.h',
    'src/antinomie/monitor/protocol/control.h',
)
KERNEL = (
    'src/antinomie/transport/guest.c', 'src/antinomie/transport/bootstrap.c',
    'src/antinomie/transport/guest_api.h',
)


def permitted(expression):
    """Evaluate an SPDX AND/OR expression; unknown IDs and exceptions fail closed."""
    tokens = re.findall(r'[A-Za-z0-9.+-]+|[()/]', expression)
    if ''.join(tokens) != re.sub(r'\s+', '', expression):
        raise ValueError(f'unrecognized license expression: {expression}')
    tokens = ['OR' if value == '/' else value for value in tokens]
    cursor = 0

    def atom():
        nonlocal cursor
        if cursor >= len(tokens):
            raise ValueError('missing license operand')
        value = tokens[cursor]
        cursor += 1
        if value == '(':
            result = disjunction()
            if cursor >= len(tokens) or tokens[cursor] != ')':
                raise ValueError('unclosed license group')
            cursor += 1
            return result
        if value in ('AND', 'OR', 'WITH', ')'):
            raise ValueError('invalid license operand')
        if cursor < len(tokens) and tokens[cursor] == 'WITH':
            cursor += 1
            if cursor >= len(tokens):
                raise ValueError('missing license exception')
            exception = tokens[cursor]
            cursor += 1
            return value == 'Apache-2.0' and exception == 'LLVM-exception'
        return value in PERMITTED

    def conjunction():
        nonlocal cursor
        result = atom()
        while cursor < len(tokens) and tokens[cursor] == 'AND':
            cursor += 1
            other = atom()
            result = result and other
        return result

    def disjunction():
        nonlocal cursor
        result = conjunction()
        while cursor < len(tokens) and tokens[cursor] == 'OR':
            cursor += 1
            other = conjunction()
            result = result or other
        return result

    result = disjunction()
    if cursor != len(tokens):
        raise ValueError('trailing license tokens')
    return result


def boundary():
    expected = [(name, 'MIT') for name in SHARED]
    expected += [(name, 'GPL-2.0-only') for name in KERNEL]
    expected += [(f'src/antinomie/transport/{name}', HOST_LICENSE)
                 for name in ('host.c', 'host_api.h')]
    for name, license_id in expected:
        if f'SPDX-License-Identifier: {license_id}' not in (ROOT / name).read_text().splitlines()[0]:
            raise ValueError(f'wrong license boundary: {name}')
    if f'license = "{HOST_LICENSE}"' not in (MONITOR / 'Cargo.toml').read_text():
        raise ValueError('workspace license differs from the host license')
    license_text = (ROOT / 'LICENSE').read_text()
    if 'GNU GENERAL PUBLIC LICENSE' not in license_text or 'Version 3, 29 June 2007' not in license_text:
        raise ValueError('root GPLv3 text is missing')


def documents(package):
    root = Path(package['manifest_path']).parent
    found = []
    for file in sorted(root.rglob('*')):
        relative = file.relative_to(root)
        if len(relative.parts) > 5 or not file.is_file() or file.is_symlink():
            continue
        if file.name.lower().startswith(('license', 'licence', 'copying', 'copyright', 'notice')):
            if file.stat().st_size > 1024 * 1024:
                raise ValueError(f'oversized license document in {package["name"]}')
            found.append((relative, file))
    if package.get('license_file'):
        file = (root / package['license_file']).resolve(strict=True)
        if not file.is_relative_to(root.resolve()) or not file.is_file():
            raise ValueError('license_file leaves the crate directory')
        pair = (file.relative_to(root.resolve()), file)
        if pair not in found:
            found.append(pair)
    if not found:
        notices = ROOT / 'LICENSES/third-party/cargo-upstream'
        manifest = notices / 'manifest.json'
        if manifest.is_file():
            prepared = json.loads(manifest.read_text())
            for entry in prepared:
                if (entry['name'], entry['version']) != (package['name'], package['version']):
                    continue
                for document in entry.get('documents', []):
                    file = (notices / document['path']).resolve(strict=True)
                    if not file.is_relative_to(notices.resolve()) or not file.is_file():
                        raise ValueError('prepared notice leaves its directory')
                    if hashlib.sha256(file.read_bytes()).hexdigest() != document['sha256']:
                        raise ValueError('prepared notice checksum differs')
                    found.append((Path('upstream') / document['path'], file))
    return found


def inventory(metadata, output=None):
    nodes = {node['id']: node for node in metadata['resolve']['nodes']}
    reachable, pending = set(), list(metadata['workspace_members'])
    while pending:
        package_id = pending.pop()
        if package_id not in reachable:
            reachable.add(package_id)
            pending.extend(nodes[package_id]['dependencies'])
    rows = []
    for package in sorted(metadata['packages'], key=lambda item: (item['name'], item['version'])):
        expression = package.get('license') or ''
        if not permitted(expression):
            raise ValueError(f'license requires review: {package["name"]} {expression!r}')
        if package['id'] in metadata['workspace_members']:
            if expression != HOST_LICENSE:
                raise ValueError('workspace member has a different license')
            continue
        row = {key: package.get(key) for key in ('name', 'version', 'license', 'repository', 'authors')}
        row['linux_x86_64_reachable'] = package['id'] in reachable
        row['documents'] = []
        for relative, file in documents(package):
            row['documents'].append({'path': relative.as_posix(), 'sha256': hashlib.sha256(file.read_bytes()).hexdigest()})
            if output:
                destination = output / f'{package["name"]}-{package["version"]}' / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(file, destination)
        # Some published crates omit a separate license file. Keep that gap
        # explicit; metadata approval does not certify notice completeness.
        row['notice_status'] = 'documents retained' if row['documents'] else 'metadata only; source review required'
        rows.append(row)
    return {'schema': 1, 'host_license': HOST_LICENSE,
            'scope': 'all locked Cargo packages; Linux x86-64 graph includes build/dev dependencies; fonts retain separate terms',
            'packages': rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    boundary()
    data = subprocess.check_output(['cargo', 'metadata', '--locked', '--format-version', '1', '--filter-platform', 'x86_64-unknown-linux-gnu'], cwd=MONITOR, text=True)
    result = inventory(json.loads(data), args.output)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / 'manifest.json').write_text(json.dumps(result, indent=2) + '\n')
    gaps = sum(not row['documents'] and row['linux_x86_64_reachable'] for row in result['packages'])
    print(f'license boundary and {len(result["packages"])} dependency expressions checked; {gaps} Linux graph packages lack separate notice documents')


if __name__ == '__main__':
    main()
