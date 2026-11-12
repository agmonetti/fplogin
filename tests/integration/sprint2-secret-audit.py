#!/usr/bin/env python3
"""G16 automated secret-exposure audit (read-only).

Walks the given roots (files, directories and the members of .tar archives)
and reports, per file, which prohibited-content rules matched. It NEVER
prints or stores matched content: only path, rule id and line number.

Rules:
  fixture-credential  test credential strings that must never reach logs
  pam-response        PAM conversation/response or password key=value
  x-cookie            X authority cookies / MIT-MAGIC-COOKIE
  env-dump            a block of many environment assignments (env dump)
  private-key         PEM private keys
  fprint-template     libfprint/fprintd stored print data
  owner-secret        literal strings from --secrets-file (e.g. disposable
                      guest password); compared in memory, never echoed

Images and other binary captures cannot be content-checked here; they are
listed as `needs-visual-review` so the reviewer inspects each one.
Raw disks larger than --max-bytes are listed as `skipped-large` (they must
never leave the private storage anyway).

Exit code: 0 no findings, 1 findings, 2 usage error.
"""
import argparse
import hashlib
import io
import json
import os
import re
import sys
import tarfile
from pathlib import Path

IMAGE_EXT = {'.png', '.ppm', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'}
RULES = [
    ('fixture-credential', re.compile(rb'(private-test-response|superseded-private-response|latest-private-response)')),
    ('pam-response', re.compile(rb'(PAM_PROMPT_ECHO_OFF[^\n]{0,40}(resp|response)\s*[=:]|\bpam[_-]?response\s*[=:]\s*\S|\b(password|passwd|passphrase)\s*[=:]\s*["\']?[^\s"\',;)]{3,})', re.I)),
    ('x-cookie', re.compile(rb'(MIT-MAGIC-COOKIE-1\s+[0-9a-f]{16,}|\bXAUTHORITY=\S+[\s\S]{0,200}MIT-MAGIC-COOKIE)', re.I)),
    ('private-key', re.compile(rb'-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----')),
]
ENV_LINE = re.compile(rb'^(?:\s*(?:export\s+)?)?[A-Z][A-Z0-9_]{2,}=[^\n]*$', re.M)
ENV_KEYS = (b'HOME=', b'PATH=', b'USER=', b'XDG_RUNTIME_DIR=', b'DBUS_SESSION_BUS_ADDRESS=', b'SHELL=')
FPRINT_PATH = re.compile(r'(^|/)var/lib/fprint/')
# Words that legitimately follow "password" in this project's documentation/traces.
BENIGN_PASSWORD = re.compile(rb'(?i)\bpass(word|wd)\s*[=:]\s*["\']?(true|false|none|null|0|1|retained|recovery|role|method|field|helper|0x[0-9a-f]+|\{|\[|<|\$|%)')


def scan_bytes(data, owner_secrets):
    findings = []
    if b'\x00' in data[:4096]:
        return findings, True
    for rule, pattern in RULES:
        for m in pattern.finditer(data):
            if rule == 'pam-response' and BENIGN_PASSWORD.match(data, m.start()):
                continue
            findings.append((rule, data.count(b'\n', 0, m.start()) + 1))
    # Environment dump: >=12 env assignment lines within any 40-line window and >=3 key markers.
    lines = data.split(b'\n')
    for i in range(0, max(1, len(lines) - 39), 20):
        window = b'\n'.join(lines[i:i + 40])
        if len(ENV_LINE.findall(window)) >= 12 and sum(k in window for k in ENV_KEYS) >= 3:
            findings.append(('env-dump', i + 1))
            break
    for secret in owner_secrets:
        pos = data.find(secret)
        if pos >= 0:
            findings.append(('owner-secret', data.count(b'\n', 0, pos) + 1))
    return findings, False


def classify(name, data, owner_secrets, report):
    if FPRINT_PATH.search(name):
        report['findings'].append({'path': name, 'rule': 'fprint-template', 'line': 0, 'line_sha256': ''})
        return
    if Path(name).suffix.lower() in IMAGE_EXT:
        report['needs_visual_review'].append(name)
        return
    findings, binary = scan_bytes(data, owner_secrets)
    if binary:
        report['binary_unscanned'].append(name)
    lines = data.split(b'\n')
    for rule, line in findings:
        # Allowlisting is per exact reviewed line content, never per whole file.
        digest = hashlib.sha256(lines[line - 1].strip() if 0 < line <= len(lines) else b'').hexdigest()[:20]
        report['findings'].append({'path': name, 'rule': rule, 'line': line, 'line_sha256': digest})
    report['scanned'] += 0 if binary else 1


def walk(root, args, owner_secrets, report):
    paths = [root] if root.is_file() else sorted(p for p in root.rglob('*') if p.is_file() and not p.is_symlink())
    for path in paths:
        name = str(path)
        size = path.stat().st_size
        if not os.access(path, os.R_OK):
            report['unreadable'].append(name)
            continue
        if size > args.max_bytes:
            report['skipped_large'].append(name)
            continue
        if tarfile.is_tarfile(path):
            with tarfile.open(path) as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    label = f'{name}!{member.name}'
                    if member.size > args.max_bytes:
                        report['skipped_large'].append(label)
                        continue
                    classify(label, archive.extractfile(member).read(), owner_secrets, report)
            continue
        classify(name, path.read_bytes(), owner_secrets, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('roots', nargs='+', type=Path)
    parser.add_argument('--secrets-file', type=Path, help='one literal secret per line; never echoed')
    parser.add_argument('--max-bytes', type=int, default=64 * 1024 * 1024)
    parser.add_argument('--json', type=Path, help='write the redacted report here')
    parser.add_argument('--allow', type=Path, help='JSON list of {path, rule} accepted after review')
    args = parser.parse_args()
    owner_secrets = []
    if args.secrets_file:
        owner_secrets = [l for l in args.secrets_file.read_bytes().split(b'\n') if len(l) >= 4]
    report = {'roots': [str(r) for r in args.roots], 'owner_secrets_checked': len(owner_secrets),
              'scanned': 0, 'findings': [], 'needs_visual_review': [], 'binary_unscanned': [], 'skipped_large': [], 'unreadable': []}
    for root in args.roots:
        if not root.exists():
            print(f'missing root: {root}', file=sys.stderr)
            return 2
        walk(root, args, owner_secrets, report)
    allowed = set()
    if args.allow:
        allowed = {(a['path'], a['rule'], a['line_sha256']) for a in json.loads(args.allow.read_text())}
    key = lambda f: (f['path'], f['rule'], f['line_sha256'])
    report['accepted'] = [f for f in report['findings'] if key(f) in allowed]
    report['findings'] = [f for f in report['findings'] if key(f) not in allowed]
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + '\n')
    by_rule = {}
    for f in report['findings']:
        by_rule[f['rule']] = by_rule.get(f['rule'], 0) + 1
    print(json.dumps({'scanned_text_files': report['scanned'], 'findings_by_rule': by_rule,
                      'accepted': len(report['accepted']),
                      'needs_visual_review': len(report['needs_visual_review']),
                      'binary_unscanned': len(report['binary_unscanned']),
                      'skipped_large': len(report['skipped_large']),
                      'unreadable': len(report['unreadable']),
                      'owner_secrets_checked': report['owner_secrets_checked']}))
    for f in report['findings']:
        print(f"FINDING {f['rule']} {f['path']}:{f['line']} line_sha256={f['line_sha256']}")
    return 1 if report['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
