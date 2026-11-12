#!/usr/bin/env python3
"""Offline-only G10 check inside the disposable no-network container.

Reuses the exact mock PAM module source from lab/g05-offline-selfcheck.py:
fingerprint authenticate succeeds after 2s; pam_acct_mgmt has no
allow-account argument, so it returns PAM_PERM_DENIED.
"""
import os, re, subprocess, sys
from pathlib import Path
assert Path('/.dockerenv').exists() and os.geteuid() == 0 and Path('/lab').is_dir()
selfcheck = Path('/src/lab/g05-offline-selfcheck.py').read_text()
code = re.search(r"module_code = r'''(.*?)'''", selfcheck, re.S).group(1)
src, mod = Path('/lab/g05-pam.c'), Path('/lab/g05-pam.so')
marker = Path('/lab/g10-account-deny')
for p in ['/lab/g05-session-executions', '/lab/g05-session-pam', '/lab/g05-pam-phases', '/lab/g05-pam-return-ms']:
    Path(p).unlink(missing_ok=True)
src.write_text(code)
subprocess.run(['cc', '-shared', '-fPIC', str(src), '-o', str(mod)], check=True)
Path('/etc/pam.d/sddm').write_text('auth required /lab/g05-pam.so immediate-deny\n')
Path('/etc/pam.d/sddm-fingerprint').write_text(
    'auth required /lab/g05-pam.so\naccount required /lab/g05-pam.so\nsession required /lab/g05-pam.so\n')
session = Path('/lab/g05-session.sh')
session.write_text('#!/bin/sh\nprintf "executed\\n" >> /lab/g05-session-executions\n')
session.chmod(0o700)
marker.write_text('')
try:
    res = subprocess.run(['/build/test/G05IntegratedTest', 'realPamAccountDeniedAfterFingerprintMatch'],
                         capture_output=True, text=True)
    sys.stdout.write(res.stdout)
    for line in res.stderr.splitlines():
        if line.startswith('G10 ') or 'FAIL' in line or 'QWARN' in line:
            print(line)
    print('G10_RESULT', 'PASS' if res.returncode == 0 else f'FAIL rc={res.returncode}')
    sys.exit(res.returncode)
finally:
    for p in [src, mod, marker, session, Path('/lab/g05-session-executions'), Path('/lab/g05-session-pam'),
              Path('/lab/g05-pam-phases'), Path('/lab/g05-pam-return-ms')]:
        p.unlink(missing_ok=True)
