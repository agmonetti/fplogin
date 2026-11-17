#!/usr/bin/env python3
"""Inspect the dual-Qt archive against a trusted, same-build-environment Qt6 reference.

References are verification inputs, not package contents. E5 must generate its own
reference; an older toolchain's binary hashes are not a compatibility criterion.
"""
import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path, PurePosixPath

METADATA = {'.PKGINFO', '.BUILDINFO', '.MTREE'}
ROOTS = ('usr/bin/sddm-greeter', 'usr/lib/qt/qml/SddmComponents',
         'usr/share/sddm/translations-qt5')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pinned(path, expected):
    data = path.read_bytes()
    require(digest(data) == expected, f'input digest mismatch: {path}')
    return data


def archive(data):
    # No extraction: validate names/types before reading bytes or invoking readelf.
    if data[:4] == b'\x28\xb5\x2f\xfd':
        data = subprocess.run(['zstd', '-dc'], input=data, capture_output=True, check=True).stdout
    entries = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:') as tar:
        for member in tar:
            name = member.name
            while name.startswith('./'):
                name = name[2:]
            name = name.rstrip('/')
            require(name and not name.startswith('/') and '..' not in name.split('/')
                    and str(PurePosixPath(name)) == name, f'unsafe archive path: {member.name}')
            require(name not in entries, f'duplicate archive path: {name}')
            require(member.isfile() or member.isdir(), f'unsupported archive type/link: {name}')
            require(member.uid == member.gid == 0, f'non-root ownership: {name}')
            executable = name.startswith(('usr/bin/', 'usr/share/sddm/scripts/')) or name in {
                'usr/lib/sddm/sddm-helper', 'usr/lib/sddm/sddm-helper-start-wayland',
                'usr/lib/sddm/sddm-helper-start-x11user'}
            expected_mode = 0o755 if member.isdir() or executable else 0o644
            require(member.mode == expected_mode, f'wrong mode: {name}: {member.mode:o}')
            content = None
            if member.isfile():
                stream = tar.extractfile(member)
                require(stream is not None, f'unreadable archive member: {name}')
                assert stream is not None
                content = stream.read()
            entries[name] = ('file' if member.isfile() else 'dir', member.mode, content)
    require(entries.keys() >= METADATA, 'missing package metadata')
    return entries


def payload(entries):
    return {k: v for k, v in entries.items() if k not in METADATA}


def needed(content):
    require(content.startswith(b'\x7fELF'), 'expected ELF binary')
    with tempfile.TemporaryDirectory(prefix='sprint3-elf-') as tmp:
        path = Path(tmp) / 'binary'
        path.write_bytes(content)
        text = subprocess.run(['readelf', '-d', str(path)], capture_output=True, text=True, check=True).stdout
    return re.findall(r'\(NEEDED\).*?\[(.*?)\]', text)


def inspect(candidate, reference, report, repo):
    entries, canonical = archive(candidate), payload(archive(reference))
    files = payload(entries)
    additions = report['additions']
    require(all(any(n == root or n.startswith(root + '/') or root.startswith(n + '/')
                    for root in ROOTS) for n in additions), 'addition outside allowlist')
    require(set(files) - set(canonical) == set(additions), 'wrong additions/missing Qt5 inventory')
    require(all(files.get(n) == value for n, value in canonical.items()), 'canonical payload changed')
    for name, value in additions.items():
        require(files[name][:2] == tuple(value[:2]), f'addition type/mode mismatch: {name}')
        # makepkg strips the greeter after merging; QML/translations stay byte-identical.
        if value[0] == 'file' and name != 'usr/bin/sddm-greeter':
            require(digest(files[name][2]) == value[2], f'Qt5 content checksum mismatch: {name}')
    for major, binary, module in [(5, 'usr/bin/sddm-greeter', 'qt'),
                                  (6, 'usr/bin/sddm-greeter-qt6', 'qt6')]:
        require(binary in files and files[binary][0] == 'file', f'missing greeter: {binary}')
        for root in (f'usr/lib/{module}/qml/SddmComponents', f'usr/share/sddm/translations-qt{major}'):
            require(root in files and files[root][0] == 'dir', f'missing module/translations: {root}')
            require(any(n.startswith(root + '/') and v[0] == 'file' for n, v in files.items()), f'empty root: {root}')
        require(f'usr/lib/{module}/qml/SddmComponents/qmldir' in files, 'missing qmldir')
        libs = needed(files[binary][2])
        require(any(n.startswith(f'libQt{major}Quick.so') for n in libs), f'wrong Qt linkage: {binary}')
        require(not any(n.startswith(f'libQt{11-major}') for n in libs), f'mixed Qt linkage: {binary}')
    for binary in ('usr/bin/sddm', 'usr/lib/sddm/sddm-helper'):
        libs = needed(files[binary][2])
        require(any(n.startswith('libQt6Core.so') for n in libs) and not any(n.startswith('libQt5') for n in libs),
                f'noncanonical linkage: {binary}')
    expected = {'etc/pam.d/sddm-fingerprint': repo / 'platforms/arch/pam/sddm-fingerprint'}
    expected.update({f'usr/share/sddm/themes/fplogin/{p.name}': p
                     for p in (repo / 'adapters/sddm/assets/theme').iterdir() if p.is_file() and p.name != 'LICENSE'})
    expected['usr/share/licenses/sddm-fplogin/fplogin-theme-LICENSE'] = repo / 'adapters/sddm/assets/theme/LICENSE'
    for name, path in expected.items():
        require(name in files and files[name][2] == path.read_bytes(), f'repository checksum mismatch: {name}')
    require(not any('/themes/fplogin/theme/' in n for n in files), 'nested theme directory')
    meta = {}
    for line in entries['.PKGINFO'][2].decode().splitlines():
        if ' = ' in line:
            key, value = line.split(' = ', 1)
            meta.setdefault(key, set()).add(value)
    for key, values in {'pkgname': {'sddm-fplogin'}, 'pkgver': {'0.21.0-3'}, 'arch': {'x86_64'},
                        'provides': {'sddm=0.21.0', 'display-manager'}, 'conflict': {'sddm'},
                        'backup': {f'etc/pam.d/{n}' for n in ('sddm', 'sddm-autologin', 'sddm-greeter', 'sddm-fingerprint')}}.items():
        require(meta.get(key) == values, f'wrong metadata: {key}')
    require({'qt5-base', 'qt5-declarative', 'qt5-quickcontrols2', 'qt5-svg', 'qt6-base', 'qt6-declarative', 'pam', 'fprintd'}
            <= meta.get('depend', set()), 'missing runtime dependencies')
    return {'status': 'PASS - archive only, no login', 'canonical_entries': len(canonical),
            'qt5_additions': len(additions), 'candidate_sha256': digest(candidate),
            'reference_sha256': digest(reference), 'payload_files': {
                n: digest(v[2]) for n, v in files.items() if v[0] == 'file'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--reference-sha256', required=True)
    parser.add_argument('--merge-report', type=Path, required=True)
    parser.add_argument('--merge-sha256', required=True)
    parser.add_argument('--repo-root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = inspect(pinned(args.package, args.sha256), pinned(args.reference, args.reference_sha256),
                     json.loads(pinned(args.merge_report, args.merge_sha256)), args.repo_root)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
