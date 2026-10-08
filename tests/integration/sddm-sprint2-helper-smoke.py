#!/usr/bin/env python3
"""Run the freshly exported helper through genuine Linux-PAM without a reader.

Run only inside the no-network isolated Arch build container; /lab and /evidence
must be project-persistent bind mounts. No host PAM, bus, USB or display mounts.
This proves typed PAM progress and post-auth account denial, not physical login.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import uuid

MODULE = r'''
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <string.h>
static void phase(const char *value) {
    FILE *f = fopen("/lab/pam-smoke-phases", "a");
    if (f) { fprintf(f, "%s\n", value); fclose(f); }
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)flags;
    phase("authenticate");
    pam_error(p, "PRIVATE_PAM_PROSE_MUST_NOT_REACH_PROGRESS");
    if (argc && !strcmp(argv[0], "unavailable")) return PAM_AUTHINFO_UNAVAIL;
    if (argc && !strcmp(argv[0], "failed")) return PAM_AUTH_ERR;
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    phase("account-denied"); return PAM_PERM_DENIED;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    phase("setcred"); return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    phase("open-session"); return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    phase("close-session"); return PAM_SUCCESS;
}
'''

def string(value):
    raw = value.encode('utf-16-be')
    return struct.pack('>I', len(raw)) + raw

class Reader:
    def __init__(self, data): self.data, self.offset = data, 0
    def take(self, length):
        end = self.offset + length
        if end > len(self.data): raise RuntimeError('truncated helper payload')
        value, self.offset = self.data[self.offset:end], end
        return value
    def u32(self): return struct.unpack('>I', self.take(4))[0]
    def u64(self): return struct.unpack('>Q', self.take(8))[0]
    def text(self):
        length = self.u32()
        return '' if length == 0xffffffff else self.take(length).decode('utf-16-be')
    def end(self):
        if self.offset != len(self.data): raise RuntimeError('trailing helper payload')

def receive(peer, length):
    value = bytearray()
    while len(value) < length:
        chunk = peer.recv(length - len(value))
        if not chunk:
            if not value: return None
            raise RuntimeError('truncated helper frame')
        value.extend(chunk)
    return bytes(value)

def run_case(helper, mode):
    path = Path('/lab/helper-pam-smoke.socket')
    path.unlink(missing_ok=True)
    phase_file = Path('/lab/pam-smoke-phases')
    phase_file.write_text('')
    Path('/etc/pam.d/sddm-fingerprint').write_text(
        f'auth required /lab/pam-smoke.so {mode}\n'
        'account required /lab/pam-smoke.so\n'
        'session required /lab/pam-smoke.so\n')
    request = str(uuid.uuid4())
    progress, success, session = [], False, False
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path)); server.listen(1); server.settimeout(10)
        process = subprocess.Popen([str(helper), '--socket', str(path), '--id', '42',
            '--user', 'root', '--request-id', request, '--method', '1', '--defer-auth',
            '--start', '/bin/true'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            peer, _ = server.accept()
            with peer:
                peer.settimeout(10)
                while True:
                    header = receive(peer, 8)
                    if header is None: break
                    length = struct.unpack('=q', header)[0]
                    if not 0 < length <= 1024 * 1024: raise RuntimeError('invalid frame size')
                    data = receive(peer, length)
                    if data is None: raise RuntimeError('missing payload')
                    reader = Reader(data)
                    opcode = reader.u32()
                    if opcode == 1:
                        if reader.u64() != 42 or reader.text() != request or reader.u32() != 1:
                            raise RuntimeError('HELLO identity mismatch')
                    else:
                        if reader.text() != request or reader.u32() != 1:
                            raise RuntimeError('helper identity mismatch')
                        if opcode == 8:
                            if reader.text() != 'root': raise RuntimeError('progress user mismatch')
                            state, detail = reader.u32(), reader.text()
                            if state not in (0, 2, 3, 5): raise RuntimeError('helper asserted daemon state')
                            if detail not in ('scanning', 'try_again', 'authentication_failed', 'authentication_unavailable'):
                                raise RuntimeError('unallowlisted progress detail (redacted)')
                            progress.append(state)
                        elif opcode == 5:
                            user = reader.text()
                            success = user == 'root'
                            if user not in ('', 'root'): raise RuntimeError('authentication user mismatch')
                            if success:
                                payload = struct.pack('>I', 9) + string(request) + struct.pack('>I', 1) + b'\x01' + struct.pack('>II', 0, 0)
                                peer.sendall(struct.pack('=q', len(payload)) + payload)
                        elif opcode == 6:
                            session = bool(reader.take(1)[0])
                            payload = struct.pack('>I', 6) + string(request) + struct.pack('>I', 1)
                            peer.sendall(struct.pack('=q', len(payload)) + payload)
                        else:
                            raise RuntimeError(f'unexpected helper opcode {opcode} (prose redacted)')
                    reader.end()
            stderr = process.communicate(timeout=10)[1]
            if b'PRIVATE_PAM_PROSE_MUST_NOT_REACH_PROGRESS' in stderr:
                raise RuntimeError('raw fingerprint prose leaked to helper logs')
            phases = phase_file.read_text().splitlines()
            expected = [2, 3] if mode == 'account-denied' else [2, 3, 0 if mode == 'unavailable' else 5]
            if progress != expected: raise RuntimeError(f'wrong typed progress {progress}')
            if success != (mode == 'account-denied') or session or process.returncode == 0:
                raise RuntimeError('PAM failure incorrectly completed login')
            if phases != (['authenticate', 'account-denied'] if success else ['authenticate']):
                raise RuntimeError('credential/session boundary crossed after failed policy')
            return {'case': mode, 'progress': progress, 'pam_authenticated': success,
                    'phases': phases, 'session_started': session, 'exit': process.returncode}
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=5)
            path.unlink(missing_ok=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').exists() or os.geteuid() != 0 or not Path('/lab').is_dir():
        raise RuntimeError('requires root in the isolated disposable container, never host execution')
    source = Path('/lab/pam-smoke.c')
    source.write_text(MODULE)
    try:
        subprocess.run(['cc', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', str(source),
                        '-lpam', '-o', '/lab/pam-smoke.so'], check=True)
        results = [run_case(args.helper, mode) for mode in ('unavailable', 'failed', 'account-denied')]
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / 'helper-pam-smoke.json').write_text(json.dumps({
            'status': 'passed-synthetic-PAM-no-physical-reader-no-sprint-acceptance',
            'results': results}, indent=2) + '\n')
        print(json.dumps(results, indent=2))
    finally:
        for name in ('pam-smoke.c', 'pam-smoke.so', 'pam-smoke-phases'):
            Path('/lab', name).unlink(missing_ok=True)

if __name__ == '__main__':
    main()
