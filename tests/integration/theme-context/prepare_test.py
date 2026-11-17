import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from prepare import INTEGRATION, ROOT, prepare, verify_inputs


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT / ".work/labs/sprint3")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.manifest = json.loads((INTEGRATION / "provenance.json").read_text())

    def test_prepare_checks_patch_and_refuses_overwrite(self):
        output = prepare(self.work / "adapted")
        text = (output / "Main.qml").read_text()
        self.assertIn("publishAuthenticationContext", text)
        self.assertNotIn('|| "123test"', text)
        self.assertNotIn("startFingerprint(", text)
        with self.assertRaises(FileExistsError):
            prepare(output)

    def test_automatic_preparation_and_integrity(self):
        output = prepare(self.work / "automatic", automatic=True)
        text = (output / "Main.qml").read_text()
        self.assertIn("themeAuthentication.attach", text)
        self.assertIn('sequence: "Escape"', text)
        self.assertIn('sequence: "F4"', text)
        self.assertNotIn("publishAuthenticationContext", text)
        # A separate manifest fixture cannot weaken the tracked patch digest.
        manifests = self.work / "manifests"
        manifests.mkdir()
        shutil.copyfile(INTEGRATION / "provenance.json", manifests / "provenance.json")
        automatic = json.loads((INTEGRATION / "automatic.json").read_text())
        automatic["theme_patch_sha256"] = "0" * 64
        (manifests / "automatic.json").write_text(json.dumps(automatic))
        with patch("prepare.INTEGRATION", manifests), self.assertRaisesRegex(ValueError, "Automatic patch integrity"):
            prepare(self.work / "rejected", automatic=True)

    def test_tampering_is_rejected(self):
        fixtures = self.work / "base"
        shutil.copytree(ROOT / self.manifest["fixture_root"], fixtures)
        patch = self.work / "theme.patch"
        shutil.copyfile(ROOT / self.manifest["patch"], patch)
        verify_inputs(fixtures, patch, self.manifest)
        original = (fixtures / "Main.qml").read_bytes()
        (fixtures / "Main.qml").write_bytes(original + b"\n")
        with self.assertRaisesRegex(ValueError, "Fixture integrity"):
            verify_inputs(fixtures, patch, self.manifest)
        (fixtures / "Main.qml").write_bytes(original)
        patch.write_bytes(patch.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "Patch integrity"):
            verify_inputs(fixtures, patch, self.manifest)

    def test_container_runner_rejects_path_traversal(self):
        result = subprocess.run(
            ["bash", str(ROOT / "tests/integration/theme-context/run-container.sh"), "../escape"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid run label", result.stderr)

    def test_nonpersistent_output_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Output must"):
            prepare(ROOT / ".work/build/theme-contract-not-allowed")


if __name__ == "__main__":
    unittest.main()
