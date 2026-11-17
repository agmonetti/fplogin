#!/usr/bin/env python3
"""Staging regressions; set SPRINT3_TEST_IMAGE for real container makepkg checks."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECIPE = Path("platforms/arch/sddm-fplogin")


def run(*args, **kwargs):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, **kwargs)


class RecipeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def stage(self, directory, root=ROOT):
        directory.mkdir()
        result = run("sh", str(root / RECIPE / "stage.sh"), str(directory))
        self.assertEqual(result.returncode, 0, result.stdout)

    def inputs(self, directory):
        result = run("bash", "-c", 'source "$1"; printf "%s\\n" "${source[@]}" -- "${sha256sums[@]}"',
                     "bash", str(directory / "PKGBUILD"))
        self.assertEqual(result.returncode, 0, result.stdout)
        sources, sums = result.stdout.strip().split("\n--\n")
        return sources.splitlines(), sums.splitlines()

    def test_deterministic_complete_staging(self):
        first, second = self.base / "a", self.base / "b"
        self.stage(first)
        self.stage(second)
        self.assertEqual({p.name: p.read_bytes() for p in first.iterdir()},
                         {p.name: p.read_bytes() for p in second.iterdir()})
        sources, sums = self.inputs(first)
        self.assertEqual(len(sources), len(sums))
        self.assertEqual(sums[0], "SKIP")
        deps = run("bash", "-c", 'source "$1"; printf "%s\\n" "${depends[@]}"',
                   "bash", str(first / "PKGBUILD"))
        self.assertEqual(deps.returncode, 0, deps.stdout)
        self.assertIn("qt5-svg", deps.stdout.splitlines())
        self.assertEqual(sources[1:6], ["0000-cmake-raise-required-version.patch",
                                      "0001-concurrent-authentication-methods.patch",
                                      "0002-greeter-api-and-theme-lifecycle.patch",
                                      "0003-qt5-compatibility.patch",
                                      "0004-availability-deadline-and-fixture-cleanup.patch"])
        self.assertEqual({p.name for p in first.iterdir()}, set(sources[1:]) | {"PKGBUILD"})
        for source, digest in zip(sources[1:], sums[1:], strict=True):
            self.assertEqual(hashlib.sha256((first / source).read_bytes()).hexdigest(), digest)
        result = run("sh", str(ROOT / RECIPE / "stage.sh"), str(first))
        self.assertNotEqual(result.returncode, 0, "nonempty output was accepted")

    def test_missing_supplement_stops_staging(self):
        root = self.base / "repo"
        shutil.copytree(ROOT / RECIPE, root / RECIPE)
        for patch in ("0003-qt5-compatibility.patch",
                      "0004-availability-deadline-and-fixture-cleanup.patch"):
            with self.subTest(patch=patch):
                original = (root / RECIPE / patch).read_bytes()
                (root / RECIPE / patch).unlink()
                out = self.base / patch
                out.mkdir()
                result = run("sh", str(root / RECIPE / "stage.sh"), str(out))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((out / "PKGBUILD").exists())
                (root / RECIPE / patch).write_bytes(original)

    def test_check_result_validation(self):
        staged = self.base / "src"
        self.stage(staged)
        code = (staged / "PKGBUILD").read_text().split(
            'python3 - "$variant" <<\'PY\' || return\n', 1)[1].split("\nPY\n", 1)[0]
        suites = ["Configuration", "QMLThemeConfig", "Session", "AuthMessages",
                  "AuthAttemptGate", "AuthTransport", "GreeterProxy", "DaemonContext", "GreeterApp"]
        for variant in ("qt5", "qt6"):
            names = suites + (["FploginTheme"] if variant == "qt6" else [])
            build = self.base / f"build-{variant}"
            (build / "Testing/Temporary").mkdir(parents=True)
            for fault in ("missing-suite", "ctest-skip", "qtest-skip", "missing-totals", None):
                with self.subTest(variant=variant, fault=fault):
                    listed = names[:-1] if fault == "missing-suite" else names
                    (build / "test-list.json").write_text(json.dumps(
                        {"tests": [{"name": name} for name in listed]}))
                    skip = "<skipped/>" if fault == "ctest-skip" else ""
                    (build / "results.xml").write_text("<testsuite>" + "".join(
                        f'<testcase name="{name}">{skip}</testcase>' for name in names) + "</testsuite>")
                    totals = "Totals: 3 passed, 0 failed, 0 skipped\n" * len(names)
                    if fault == "qtest-skip":
                        totals = totals.replace("0 skipped", "1 skipped", 1)
                    if fault == "missing-totals":
                        totals = ""
                    (build / "Testing/Temporary/LastTest.log").write_text(totals)
                    result = run("python3", "-", variant, input=code, cwd=self.base)
                    self.assertEqual(result.returncode == 0, fault is None, result.stdout)
            (build / "test").mkdir()
            shutil.copy(build / "test-list.json", build / "test-list.fixture.json")
        fixture = self.base / "sddm/test/plasmawayland-dev.desktop"
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(b"[Desktop Entry]\nName=Fixture identity regression\n")
        # CTest is stubbed only here; verify the real recipe stages both fixtures first.
        script = '''source "$1"
srcdir=$PWD
ctest() {
  cmp sddm/test/plasmawayland-dev.desktop "$2/test/plasmawayland-dev.desktop" || return
  if [[ $* == *--show-only* ]]; then cat "$2/test-list.fixture.json"; fi
}
check
'''
        result = run("bash", "-c", script, "bash", str(staged / "PKGBUILD"), cwd=self.base)
        self.assertEqual(result.returncode, 0, result.stdout)
        for variant in ("qt5", "qt6"):
            self.assertEqual((self.base / f"build-{variant}/test" / fixture.name).read_bytes(),
                             fixture.read_bytes())

    @unittest.skipUnless(os.environ.get("SPRINT3_TEST_IMAGE"), "container image not specified")
    def test_container_checksum_and_failing_check(self):
        # Everything runs inside a disposable, networkless container; no host pacman/useradd.
        self.stage(self.base / "src")
        shutil.copy(ROOT / RECIPE / "clean-build.sh", self.base)
        script = r'''
set -eu
# Return fixture ownership even on failure so host TemporaryDirectory cleanup works.
trap 'chown -hR "$(stat -c %u /pkg):$(stat -c %g /pkg)" /pkg' EXIT
useradd -m verifier
cp -r /pkg/src /home/verifier/pkg
chown -R verifier /home/verifier/pkg
# Keep the real local source/checksum arrays; omit only the remote Git input.
printf '\nsource=("${source[@]:1}"); sha256sums=("${sha256sums[@]:1}")\n' >> /home/verifier/pkg/PKGBUILD
verify() { su verifier -c 'cd /home/verifier/pkg && makepkg --verifysource --noconfirm'; }
verify
for patch in 0003-qt5-compatibility.patch 0004-availability-deadline-and-fixture-cleanup.patch; do
  printf '\ntampered\n' >> /home/verifier/pkg/"$patch"
  if verify; then echo 'tampered supplement accepted'; exit 1; fi
  rm /home/verifier/pkg/"$patch"
  if verify; then echo 'missing supplement accepted'; exit 1; fi
  cp /pkg/src/"$patch" /home/verifier/pkg/
done
# Exercise the whole build wrapper with real makepkg and an intentionally failing check().
printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/pacman
chmod +x /usr/local/bin/pacman
cat > /pkg/src/PKGBUILD <<'PKG'
pkgname=fplogin-check-regression
pkgver=1
pkgrel=1
pkgdesc='Intentional package check failure'
arch=('any')
license=('MIT')
check() { echo INTENTIONAL_CHECK_FAILURE; return 37; }
package() { echo PACKAGE_MUST_NOT_RUN; return 1; }
PKG
if OUT=failing sh /pkg/clean-build.sh; then rc=0; else rc=$?; fi
test "$rc" -eq 4 # makepkg maps a failed check() to E_BUILD_FAILED.
test ! -e /pkg/failing
grep -q INTENTIONAL_CHECK_FAILURE /pkg/failing.makepkg.log
! grep -q PACKAGE_MUST_NOT_RUN /pkg/failing.makepkg.log
# An export failure must not replace makepkg's original status.
userdel -r builder
ln -s /dev/full /pkg/export-failure.makepkg.log
if OUT=export-failure sh /pkg/clean-build.sh; then rc=0; else rc=$?; fi
test "$rc" -eq 4
userdel -r builder
cat > /pkg/src/PKGBUILD <<'PKG'
pkgname=fplogin-check-regression
pkgver=1
pkgrel=1
pkgdesc='Successful package check fixture'
arch=('any')
license=('MIT')
check() { echo SUCCESSFUL_CHECK; }
package() { mkdir -p "$pkgdir/usr/share/fplogin-test"; echo fixture > "$pkgdir/usr/share/fplogin-test/result"; }
PKG
OUT=good sh /pkg/clean-build.sh
test -f /pkg/good/fplogin-check-regression-1-1-any.pkg.tar.zst
userdel -r builder
printf 'not a directory\n' > /pkg/blocked
if OUT=blocked sh /pkg/clean-build.sh > /pkg/export-dir-failure.log 2>&1; then rc=0; else rc=$?; fi
test "$rc" -ne 0
! grep -q BUILD_DONE /pkg/export-dir-failure.log
'''
        result = run("docker", "run", "--rm", "--network", "none", "--entrypoint", "/bin/sh",
                     "-v", f"{self.base}:/pkg", os.environ["SPRINT3_TEST_IMAGE"], "-c", script)
        print(result.stdout)
        self.assertEqual(result.returncode, 0, result.stdout)


if __name__ == "__main__":
    unittest.main()
