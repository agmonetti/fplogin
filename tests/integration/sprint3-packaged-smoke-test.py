#!/usr/bin/env python3
"""Ensure rendering diagnostics cannot be hidden by a live fallback/window."""
import importlib.util
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('sprint3-packaged-smoke.py'))
assert SPEC and SPEC.loader
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class SmokeTest(unittest.TestCase):
    def test_maya_svg_regression(self):
        log = 'file:///usr/lib/qt/qml/SddmComponents/PasswordBox.qml:64:5: QML Image: Error decoding: file:///usr/share/sddm/themes/maya/images/ic_warning_white_24px.svg: Unsupported image format'
        with self.assertRaises(ValueError):
            smoke.diagnostics(log)

    def test_narrow_warning_allowlist(self):
        socket = 'Socket error:  "QLocalSocket::connectToServer: Invalid name"'
        deprecated = 'file:///usr/lib/qt/qml/SddmComponents/LayoutBox.qml:35:5: QML Connections: Implicitly defined onFoo properties in Connections are deprecated. Use this syntax instead: function onFoo(<arguments>) { ... }'
        self.assertEqual(smoke.diagnostics(socket + '\n' + deprecated), [socket, deprecated])
        for line in (deprecated.replace('Connections:', 'Image:'), socket + ' unknown',
                     'file:///usr/share/sddm/themes/maya/Main.qml:1:1: new diagnostic', 'QML warning: new warning'):
            with self.subTest(line=line), self.assertRaises(ValueError):
                smoke.diagnostics(line)

    def test_same_validation_rejects_bad_runtime(self):
        theme = Path('/usr/share/sddm/themes/maya')
        module = '/usr/lib/qt/qml/SddmComponents'
        good = f'Loading file://{theme}/Main.qml...\nQQmlImports: {module}/TextBox.qml'
        smoke.validate(good, theme, module, [{'pid': 1}], True)
        for log, windows, alive in [(good, [], True), (good, [{'pid': 1}], False),
                                    (good + '\nFallback to embedded theme', [{'pid': 1}], True),
                                    (good.replace(module, '/wrong'), [{'pid': 1}], True),
                                    (good.replace(str(theme), '/wrong'), [{'pid': 1}], True)]:
            with self.subTest(log=log, windows=windows, alive=alive), self.assertRaises(ValueError):
                smoke.validate(log, theme, module, windows, alive)


if __name__ == '__main__':
    unittest.main(verbosity=2)
