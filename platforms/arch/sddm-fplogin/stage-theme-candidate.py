#!/usr/bin/env python3
"""Stage the private dual-Qt cooperative-theme SDDM preview, not an installer."""
import argparse
import hashlib
import shutil
import subprocess
from pathlib import Path


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError(f'Expected exactly one recipe anchor: {before!r}')
    return text.replace(before, after, 1)


def stage(output):
    recipe = Path(__file__).resolve().parent
    patches = recipe.parents[2] / 'adapters/sddm/integrations/where-is-my-sddm-qt5'
    names = [f'sddm-theme-{name}.patch' for name in ('automatic-policy', 'lifecycle', 'root-window')]
    subprocess.run(['sh', str(recipe / 'stage.sh'), str(output)], check=True)
    for name in names:
        shutil.copyfile(patches / name, output / name)
    pkgbuild = output / 'PKGBUILD'
    text = pkgbuild.read_text()
    anchor = '0004-availability-deadline-and-fixture-cleanup.patch'
    digest = repr(hashlib.sha256((output / anchor).read_bytes()).hexdigest())
    checksums = ' '.join(repr(hashlib.sha256((output / name).read_bytes()).hexdigest()) for name in names)
    text = replace_once(text, 'pkgrel=3\n', 'pkgrel=3.1\n')
    text = replace_once(text, repr(anchor) + '\n', repr(anchor) + '\n        ' + ' '.join(map(repr, names)) + '\n')
    text = replace_once(text, f'../{anchor}; do', f'../{anchor} ' + ' '.join(f'../{name}' for name in names) + '; do')
    text = replace_once(text, digest + ' ', f'{digest} {checksums} ')
    pkgbuild.write_text(text)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path, help='existing empty output directory')
    stage(parser.parse_args().output.resolve())
