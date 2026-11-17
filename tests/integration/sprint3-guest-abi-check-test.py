#!/usr/bin/env python3
"""Regression checks for the E6 loader preflight, without executing host ELFs."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('abi', Path(__file__).with_name('sprint3-guest-abi-check.py'))
assert SPEC and SPEC.loader
abi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(abi)


class AbiTest(unittest.TestCase):
    def test_loader_errors_even_with_exit_zero(self):
        for output in ('libssl.so.4 => not found',
                       "version `OPENSSL_3.6.0' not found",
                       'undefined symbol: SSL_new', 'symbol lookup error: x',
                       'cannot open shared object file'):
            with self.subTest(output=output):
                self.assertFalse(abi.validate(0, output))
        self.assertFalse(abi.validate(1, ''))
        self.assertTrue(abi.validate(0, 'libssl.so.4 => /usr/lib/libssl.so.4'))

    def test_plugin_symlink_and_missing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / 'plugin.so'
            plugin.write_bytes(b'\x7fELFtest')
            link = Path(directory) / 'plugin-link.so'
            link.symlink_to(plugin.name)
            with patch.object(abi, 'invoke') as invoke:
                invoke.return_value.returncode = 0
                invoke.return_value.stdout = 'resolved'
                report = abi.check([], [plugin, link])
            self.assertTrue(report['passed'])
            self.assertEqual(report['elf_count'], 1)
            self.assertEqual(report['elf'][0]['resolved'], str(plugin))
            with self.assertRaises(ValueError):
                abi.elf(Path(directory) / 'missing')
            with self.assertRaises(ValueError):
                abi.elf(Path('relative'))
            with self.assertRaises(ValueError):
                abi.check([], [])

    def test_package_missing_runtime_fails_but_docs_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / 'plugin.so'
            plugin.write_bytes(b'\x7fELFtest')
            missing_doc = '/usr/share/doc/fplogin-abi-nonexistent-test/file'
            with patch.object(abi, 'invoke') as invoke:
                invoke.side_effect = [
                    abi.subprocess.CompletedProcess([], 0, 'fixture 1'),
                    abi.subprocess.CompletedProcess([], 0, f'{plugin}\n{missing_doc}\n'),
                    abi.subprocess.CompletedProcess([], 0, 'resolved')]
                report = abi.check(['fixture'], [])
            self.assertTrue(report['passed'])
            self.assertEqual(report['skipped'][0]['path'], missing_doc)
            with patch.object(abi, 'invoke') as invoke:
                invoke.side_effect = [
                    abi.subprocess.CompletedProcess([], 0, 'fixture 1'),
                    abi.subprocess.CompletedProcess([], 0, '/usr/lib/fplogin-abi-nonexistent-test.so\n')]
                with self.assertRaises(ValueError):
                    abi.check(['fixture'], [])

    def test_package_inventory_failure(self):
        with patch.object(abi, 'invoke') as invoke:
            invoke.return_value = abi.subprocess.CompletedProcess([], 1, 'missing package')
            with self.assertRaises(ValueError):
                abi.check(['missing'], [])

    def test_clean_subprocess_environment(self):
        poison = dict.fromkeys(
            ('LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH', 'QT_PLUGIN_PATH', 'QML2_IMPORT_PATH'), '/untrusted')
        with patch.dict(os.environ, poison), patch.object(abi.subprocess, 'run') as run:
            abi.invoke(['/usr/bin/ldd', '-r', '/usr/bin/sddm'])
        self.assertEqual(run.call_args.kwargs['env'], abi.ENV)
        self.assertFalse(set(poison) & run.call_args.kwargs['env'].keys())
        self.assertEqual(run.call_args.kwargs['timeout'], 30)


if __name__ == '__main__':
    unittest.main(verbosity=2)
