#!/usr/bin/env python3
"""Mutation tests using the actual candidate/reference, not synthetic ELF lookalikes."""
import argparse
import copy
import importlib.util
import io
import json
import subprocess
import tarfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('inspector', Path(__file__).with_name('sprint3-package-inspect.py'))
assert SPEC and SPEC.loader
inspector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inspector)


def repack(entries, mutate):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as tar:
        for name, (kind, mode, data) in entries.items():
            member = tarfile.TarInfo(name)
            member.mode = mode
            member.type = tarfile.DIRTYPE if kind == 'dir' else tarfile.REGTYPE
            member.size = len(data) if data is not None else 0
            result = mutate(member, data)
            if result is not None:
                member, data = result
                member.size = len(data) if data is not None else 0
                tar.addfile(member, io.BytesIO(data) if data is not None else None)
    return output.getvalue()


class InspectorTest(unittest.TestCase):
    candidate_path: Path
    candidate: bytes
    reference: bytes
    report: dict
    repo: Path
    entries: dict

    def check_archive(self, candidate):
        return inspector.inspect(candidate, self.reference, self.report, self.repo)

    def test_positive(self):
        self.assertEqual(self.check_archive(self.candidate)['qt5_additions'], 62)

    def test_mutations(self):
        def change(target, operation):
            return lambda member, data: operation(member, data) if member.name == target else (member, data)

        def rename(name):
            def apply(member, data):
                member.name = name
                return member, data
            return apply

        def field(key, value):
            def apply(member, data):
                setattr(member, key, value)
                return member, data
            return apply

        greeter = 'usr/bin/sddm-greeter'
        helper = 'usr/lib/sddm/sddm-helper'
        mutations = {
            'missing-qt5-greeter': change(greeter, lambda m, d: None),
            'misplaced-module': change('usr/lib/qt/qml/SddmComponents/qmldir', rename('usr/lib/qt6/qml/misplaced/qmldir')),
            'canonical-helper-substitution': change(helper, lambda m, d: (m, self.entries[greeter][2])),
            'qt5-qml-content': change('usr/lib/qt/qml/SddmComponents/TextBox.qml', lambda m, d: (m, b'corrupt QML')),
            'qt5-translation-content': change('usr/share/sddm/translations-qt5/de.qm', lambda m, d: (m, b'corrupt translation')),
            'wrong-qt-major': change(greeter, lambda m, d: (m, self.entries['usr/bin/sddm-greeter-qt6'][2])),
            'non-elf': change(greeter, lambda m, d: (m, b'not ELF')),
            'mode': change(greeter, field('mode', 0o4755)),
            'owner': change(greeter, field('uid', 1000)),
            'pam-digest': change('etc/pam.d/sddm-fingerprint', lambda m, d: (m, b'wrong PAM')),
            'missing-dependency': change('.PKGINFO', lambda m, d: (m, d.replace(b'depend = qt5-quickcontrols2\n', b''))),
            'missing-svg-dependency': change('.PKGINFO', lambda m, d: (m, d.replace(b'depend = qt5-svg\n', b''))),
            'bad-provides': change('.PKGINFO', lambda m, d: (m, d.replace(b'provides = sddm=0.21.0', b'provides = sddm=0.20.0'))),
            'traversal': change(greeter, rename('../escape')),
            'absolute': change(greeter, rename('/escape')),
            'duplicate-normalized': change(greeter, rename('./usr/bin/sddm-greeter-qt6')),
            'symlink': change(greeter, field('type', tarfile.SYMTYPE)),
            'special': change(greeter, field('type', tarfile.FIFOTYPE)),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check_archive(repack(self.entries, mutate))

    def test_bad_inputs(self):
        with self.assertRaises((tarfile.TarError, ValueError)):
            self.check_archive(b'not an archive')
        with self.assertRaises(subprocess.CalledProcessError):
            self.check_archive(self.candidate[:100])
        report = copy.deepcopy(self.report)
        report['additions']['etc/unexpected'] = ['file', 420, 'ignored']
        with self.assertRaisesRegex(ValueError, 'outside allowlist'):
            inspector.inspect(self.candidate, self.reference, report, self.repo)
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            inspector.pinned(self.candidate_path, '0' * 64)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('candidate', type=Path)
    parser.add_argument('reference', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    InspectorTest.candidate_path = args.candidate
    InspectorTest.candidate = args.candidate.read_bytes()
    InspectorTest.reference = args.reference.read_bytes()
    InspectorTest.report = json.loads(args.report.read_text())
    InspectorTest.repo = Path(__file__).resolve().parents[2]
    InspectorTest.entries = inspector.archive(InspectorTest.candidate)
    unittest.main(argv=[__file__], verbosity=2)
