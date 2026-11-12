#!/usr/bin/env python3
"""Offline-only Sprint 2 integrated cases (real daemon objects + real sddm-helper).

Runs ONLY inside the disposable no-network lab container (/.dockerenv, root,
/lab bound to persistent disposable storage). It writes container-local
/etc/pam.d/sddm and /etc/pam.d/sddm-fingerprint; never run on the host.

Mock PAM module arguments (auth):
  immediate-deny  -> PAM_AUTH_ERR at once
  term-aware      -> waits until a signal interrupts the sleep, then records and
                     returns PAM_AUTHINFO_UNAVAIL (9), like pam_fprintd on cancel
  (none)          -> sleeps 2 s, returns PAM_SUCCESS
account: allow-account -> PAM_SUCCESS, otherwise PAM_PERM_DENIED.
Every pam_end is recorded through a pam_set_data cleanup callback.
"""
import os, subprocess, sys
from pathlib import Path

assert Path('/.dockerenv').exists() and os.geteuid() == 0 and Path('/lab').is_dir()
MODULE = r'''
#include <security/pam_modules.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
static long long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void record(const char *what, int rc) {
    FILE *out = fopen("/lab/sprint2-pam-log", "a");
    if (out) { fprintf(out, "%s pid=%ld ms=%lld rc=%d\n", what, (long)getpid(), now_ms(), rc); fclose(out); }
}
static void on_end(pam_handle_t *p, void *data, int status) { (void)p; (void)data; record("end", status); }
static int has(int n, const char **a, const char *want) {
    for (int i = 0; i < n; ++i) if (a[i] && !strcmp(a[i], want)) return 1;
    return 0;
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *p, int f, int n, const char **a) {
    (void)f;
    pam_set_data(p, "fplogin-sprint2-mock", (void *)1, on_end);
    record("authenticate-enter", 0);
    if (has(n, a, "immediate-deny")) { record("authenticate-return", PAM_AUTH_ERR); return PAM_AUTH_ERR; }
    if (has(n, a, "term-aware")) {
        struct timespec d = { 60, 0 };
        while (clock_nanosleep(CLOCK_MONOTONIC, 0, &d, &d) == 0) { d.tv_sec = 60; d.tv_nsec = 0; }
        record("authenticate-return", PAM_AUTHINFO_UNAVAIL);
        return PAM_AUTHINFO_UNAVAIL;
    }
    struct timespec end; clock_gettime(CLOCK_MONOTONIC, &end); end.tv_sec += 2;
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &end, NULL) == EINTR) { }
    record("authenticate-return", PAM_SUCCESS);
    return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *p, int f, int n, const char **a) {
    (void)p; (void)f;
    int rc = has(n, a, "allow-account") ? PAM_SUCCESS : PAM_PERM_DENIED;
    record("account", rc); return rc;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *p, int f, int n, const char **a) {
    (void)p; (void)f; (void)n; (void)a; return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int f, int n, const char **a) {
    (void)p; (void)f; (void)n; (void)a; record("open", 0); return PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int f, int n, const char **a) {
    (void)p; (void)f; (void)n; (void)a; record("close", 0); return PAM_SUCCESS;
}
'''
M = '/lab/sprint2-pam.so'
PROFILES = {
    # case: (sddm password service, sddm-fingerprint service)
    'realPamDeadlineNormalCleanup': (
        f'auth required {M} immediate-deny\n',
        f'auth required {M} term-aware\naccount required {M}\n'),
    'realPamPasswordFailureFingerprintContinues': (
        f'auth required {M} immediate-deny\n',
        f'auth required {M}\naccount required {M} allow-account\nsession required {M}\n'),
    'realPamContextReplacementWaitsForNormalExit': (
        f'auth required {M} immediate-deny\n',
        f'auth required {M} term-aware\naccount required {M}\n'),
}
SCRATCH = ['/lab/sprint2-pam-log', '/lab/g05-session-executions', '/lab/g05-session-pam']
Path('/lab/sprint2-pam.c').write_text(MODULE)
subprocess.run(['cc', '-shared', '-fPIC', '/lab/sprint2-pam.c', '-o', M], check=True)
session = Path('/lab/g05-session.sh')
session.write_text('#!/bin/sh\nprintf "executed\\n" >> /lab/g05-session-executions\n')
session.chmod(0o700)
cases = sys.argv[1:] or list(PROFILES)
failed = 0
try:
    for case in cases:
        for p in SCRATCH:
            Path(p).unlink(missing_ok=True)
        password, fingerprint = PROFILES[case]
        Path('/etc/pam.d/sddm').write_text(password)
        Path('/etc/pam.d/sddm-fingerprint').write_text(fingerprint)
        res = subprocess.run(['/build/test/G05IntegratedTest', case], capture_output=True, text=True)
        for line in (res.stdout + res.stderr).splitlines():
            if line.startswith(('S2 ', 'FAIL', 'PASS', 'Totals', '   Loc', '   Actual', '   Expected')):
                print(line)
        log = Path('/lab/sprint2-pam-log')
        print(f'--- {case} pam-log')
        print(log.read_text() if log.exists() else '(none)')
        ok = res.returncode == 0
        failed += not ok
        print('CASE_RESULT', case, 'PASS' if ok else f'FAIL rc={res.returncode}')
finally:
    for p in SCRATCH + ['/lab/sprint2-pam.c', M, str(session)]:
        Path(p).unlink(missing_ok=True)
sys.exit(1 if failed else 0)
