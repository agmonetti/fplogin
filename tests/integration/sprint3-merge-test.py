#!/usr/bin/env python3
"""E3 allowlist merge: no host installation, containers or Qt runtime needed."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "merge_qt5", ROOT / "platforms/arch/sddm-fplogin/merge-qt5.py")
assert spec is not None and spec.loader is not None
merge_qt5 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(merge_qt5)


class MergeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.package = self.base / "package"
        self.private = self.base / "private"
        self.put(self.package, "usr/bin/sddm", b"canonical daemon", 0o755)
        self.put(self.package, "usr/lib/sddm/sddm-helper", b"canonical helper", 0o755)
        self.put(self.package, "etc/pam.d/sddm-fingerprint", b"canonical PAM")
        self.put(self.package, "usr/share/sddm/themes/maya/translations/en.qm", b"Qt6 shared theme")
        (self.package / "usr/bin").chmod(0o751)
        self.put(self.private, "usr/bin/sddm-greeter", b"Qt5 greeter", 0o755)
        self.put(self.private, "usr/lib/qt/qml/SddmComponents/qmldir", b"module SddmComponents")
        self.put(self.private, "usr/share/sddm/translations-qt5/en.qm", b"Qt5 component")
        # These must not be copied, even though the Qt5 install contains them.
        self.put(self.private, "usr/bin/sddm", b"wrong daemon", 0o755)
        self.put(self.private, "usr/lib/sddm/sddm-helper", b"wrong helper", 0o755)
        self.put(self.private, "usr/share/sddm/themes/maya/translations/en.qm", b"wrong shared theme")

    def put(self, root, name, content, mode=0o644):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)

    def test_exact_delta_preserves_canonical_and_shared_modes(self):
        before = merge_qt5.inventory(self.package)
        result = merge_qt5.merge(self.package, self.private, before)
        after = merge_qt5.inventory(self.package)
        merge_qt5.verify(before, after, result["additions"])
        self.assertEqual((self.package / "usr/bin").stat().st_mode & 0o777, 0o751)
        self.assertEqual(len([v for v in result["additions"].values() if v[0] == "file"]), 3)
        (self.package / "usr/lib/sddm/sddm-helper").write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "canonical"):
            merge_qt5.verify(before, merge_qt5.inventory(self.package), result["additions"])

    def test_preflight_rejects_without_writing(self):
        faults = ("missing", "empty", "nonexecutable", "collision", "directory-collision",
                  "source-link", "destination-link", "destination-file", "fifo")
        for fault in faults:
            with self.subTest(fault=fault):
                # Each mutation has its own fresh fixture.
                case = MergeTest()
                case.setUp()
                try:
                    greeter = case.private / "usr/bin/sddm-greeter"
                    module = case.private / "usr/lib/qt/qml/SddmComponents"
                    if fault == "missing":
                        greeter.unlink()
                    elif fault == "empty":
                        (module / "qmldir").unlink()
                    elif fault == "nonexecutable":
                        greeter.chmod(0o644)
                    elif fault == "collision":
                        case.put(case.package, "usr/bin/sddm-greeter", b"collision")
                    elif fault == "directory-collision":
                        (case.package / "usr/lib/qt/qml/SddmComponents").mkdir(parents=True)
                    elif fault == "source-link":
                        (module / "link").symlink_to("/outside")
                    elif fault == "destination-link":
                        (case.package / "usr/lib/qt").symlink_to(case.private / "usr/lib/qt")
                    elif fault == "destination-file":
                        case.put(case.package, "usr/lib/qt", b"not a directory")
                    else:
                        os.mkfifo(module / "fifo")
                    before = merge_qt5.inventory(case.package)
                    with self.assertRaises((ValueError, OSError)):
                        merge_qt5.merge(case.package, case.private, before)
                    self.assertEqual(merge_qt5.inventory(case.package), before)
                finally:
                    case.doCleanups()

    def test_changed_snapshot_and_overlapping_roots_rejected(self):
        before = merge_qt5.inventory(self.package)
        (self.package / "usr/bin/sddm").write_bytes(b"changed before merge")
        with self.assertRaisesRegex(ValueError, "before merge"):
            merge_qt5.merge(self.package, self.private, before)
        with self.assertRaisesRegex(ValueError, "overlapping"):
            merge_qt5.independent_roots(self.package, self.package / "private")
        with self.assertRaisesRegex(ValueError, "overlapping"):
            merge_qt5.independent_roots(self.package, self.private, self.package / "manifest.json")


if __name__ == "__main__":
    unittest.main()
