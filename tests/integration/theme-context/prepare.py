#!/usr/bin/env python3
"""Verify portable fixtures and patch; prepare a NEW persistent test theme, never install it."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
INTEGRATION = ROOT / "adapters/sddm/integrations/where-is-my-sddm-qt5"


def verify_inputs(fixtures, patch, manifest):
    expected = manifest["fixture_sha256"]
    if {path.name for path in fixtures.iterdir()} != set(expected):
        raise ValueError("Fixture inventory mismatch")
    for name, digest in expected.items():
        path = fixtures / name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError(f"Fixture integrity mismatch: {name}")
    if patch.is_symlink() or hashlib.sha256(patch.read_bytes()).hexdigest() != manifest["patch_sha256"]:
        raise ValueError("Patch integrity mismatch")


def prepare(output, automatic=False):
    output = output.resolve()
    allowed = (ROOT / ".work/labs/sprint3").resolve()
    if not output.is_relative_to(allowed) or output == allowed:
        raise ValueError("Output must be a new directory below repository .work/labs/sprint3")
    manifest = json.loads((INTEGRATION / "provenance.json").read_text())
    fixtures = ROOT / manifest["fixture_root"]
    patch = ROOT / manifest["patch"]
    verify_inputs(fixtures, patch, manifest)
    # copytree refuses existing output; retain partial output on failure as evidence.
    shutil.copytree(fixtures, output)
    command = ["git", "apply", "--directory=" + str(output.relative_to(ROOT)), str(patch)]
    subprocess.run(command[:2] + ["--check"] + command[2:], cwd=ROOT, check=True)
    subprocess.run(command, cwd=ROOT, check=True)
    if automatic:
        auto = json.loads((INTEGRATION / "automatic.json").read_text())
        patch = ROOT / auto["theme_patch"]
        if patch.is_symlink() or hashlib.sha256(patch.read_bytes()).hexdigest() != auto["theme_patch_sha256"]:
            raise ValueError("Automatic patch integrity mismatch")
        command = ["git", "apply", "--directory=" + str(output.relative_to(ROOT)), str(patch)]
        subprocess.run(command[:2] + ["--check"] + command[2:], cwd=ROOT, check=True)
        subprocess.run(command, cwd=ROOT, check=True)
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--automatic", action="store_true", help="Apply the separate experimental automatic policy consumer")
    args = parser.parse_args()
    print(prepare(args.output, automatic=args.automatic))
