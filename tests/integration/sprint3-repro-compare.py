#!/usr/bin/env python3
"""Compare two independently built pacman packages file by file (S3-08).

Reports content (SHA-256), mode, owner and symlink-target differences; .PKGINFO
and .BUILDINFO are compared after dropping build-time fields. Exit 0 = identical
payload, 1 = differences, 2 = usage error. Read-only.
"""
import hashlib, sys, tarfile

VOLATILE = ('builddate', 'buildenv', 'installed', 'startdir', 'buildtool', 'buildtoolver', 'packager')

def load(path):
    entries, meta = {}, {}
    with tarfile.open(path, 'r:zst') as archive:
        for m in archive.getmembers():
            if m.name in ('.PKGINFO', '.BUILDINFO'):
                lines = archive.extractfile(m).read().decode().splitlines()
                meta[m.name] = sorted(l for l in lines if not l.split(' =')[0].strip() in VOLATILE)
                continue
            if m.name == '.MTREE':
                continue
            digest = hashlib.sha256(archive.extractfile(m).read()).hexdigest() if m.isfile() else ''
            entries[m.name] = (m.type, oct(m.mode), m.uname, m.gname, m.linkname, digest)
    return entries, meta

def main():
    if len(sys.argv) != 3:
        print(__doc__); return 2
    (a, ma), (b, mb) = load(sys.argv[1]), load(sys.argv[2])
    diffs = []
    for name in sorted(set(a) | set(b)):
        if a.get(name) != b.get(name):
            diffs.append((name, a.get(name), b.get(name)))
    for key in sorted(set(ma) | set(mb)):
        if ma.get(key) != mb.get(key):
            only = sorted(set(ma.get(key, [])) ^ set(mb.get(key, [])))
            diffs.append((key, 'metadata', only[:6]))
    print(f'files A={len(a)} B={len(b)} differing={len(diffs)}')
    for d in diffs[:40]:
        print('DIFF', d[0], '|', str(d[1])[:90], '|', str(d[2])[:90])
    return 1 if diffs else 0

if __name__ == '__main__':
    sys.exit(main())
