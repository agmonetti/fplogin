#!/usr/bin/env python3
"""Fail-closed ELF preflight. Run ONLY inside the trusted guest/isolated sandbox.

Checks installed package ELFs (including plugins), not just package dependencies.
This executes the dynamic loader; never use it on untrusted files or on the host.
A PASS is ABI evidence, not proof of QML loading, daemon selection or login.
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ENV = {'PATH': '/usr/bin:/usr/sbin', 'LC_ALL': 'C', 'HOME': '/nonexistent'}
ERROR = re.compile(r'not found|undefined symbol|symbol lookup error|cannot open shared object', re.I)


def invoke(argv):
    return subprocess.run(argv, env=ENV, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=30)


def validate(returncode, output):
    return returncode == 0 and ERROR.search(output) is None


def elf(path):
    if not path.is_absolute():
        raise ValueError(f'non-absolute package path: {path}')
    if not path.exists():
        raise ValueError(f'missing installed path: {path}')
    if not path.is_file():
        return False
    with path.open('rb') as stream:
        return stream.read(4) == b'\x7fELF'


def check(packages, paths):
    identities = {}
    skipped = []
    for package in packages:
        identity = invoke(['/usr/bin/pacman', '-Q', package])
        inventory = invoke(['/usr/bin/pacman', '-Qlq', package])
        if identity.returncode or inventory.returncode:
            raise ValueError(f'cannot inventory installed package: {package}')
        identities[package] = identity.stdout.strip()
        for line in inventory.stdout.splitlines():
            path = Path(line)
            if not path.is_absolute():
                raise ValueError(f'non-absolute package path: {path}')
            if not path.exists() and line.startswith(('/usr/share/doc/', '/usr/share/man/')):
                skipped.append({'path': line, 'reason': 'absent non-runtime documentation (NoExtract)'})
            else:
                paths.append(path)
    records = []
    seen = set()
    for path in sorted(set(paths)):
        if not elf(path):
            continue
        resolved = path.resolve(strict=True)
        if resolved in seen:
            continue
        seen.add(resolved)
        command = ['/usr/bin/ldd', '-r', str(path)]
        result = invoke(command)
        providers = {}
        for name in re.findall(r'(?:=>\s+|^\s*)(/\S+)\s+\(', result.stdout, re.M):
            provider = Path(name)
            if provider.is_file():
                providers[name] = hashlib.sha256(provider.read_bytes()).hexdigest()
        records.append({'path': str(path), 'resolved': str(resolved),
                        'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                        'command': command, 'providers_sha256': providers, 'exit': result.returncode,
                        'output': result.stdout, 'passed': validate(result.returncode, result.stdout)})
    if not records:
        raise ValueError('no ELF inputs checked')
    return {'packages': identities, 'skipped': skipped, 'elf_count': len(records),
            'passed': all(record['passed'] for record in records), 'elf': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--isolated-runtime', action='store_true', required=True,
                        help='acknowledge execution inside guest/sandbox, never host')
    parser.add_argument('--package', action='append', default=[])
    parser.add_argument('paths', nargs='*', type=Path)
    args = parser.parse_args()
    try:
        report = check(args.package, args.paths)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({'passed': False, 'error': str(error)}))
        return 1
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
