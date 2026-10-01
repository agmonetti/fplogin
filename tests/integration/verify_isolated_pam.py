#!/usr/bin/env python3
"""Verify a private PAM policy, with an optional real fprintd cancellation.

Prerequisites: Linux-PAM headers and libpam with pam_start_confdir, cc, Python 3,
installed pam_permit.so and pam_deny.so. For --fingerprint: pam_fprintd.so,
a working fprintd/reader, and an enrolled finger for the invoking non-root user.
Do NOT touch the reader while this script runs: authentication must remain blocked.

From the repository root, as the enrolled ordinary user (never sudo):
    python3 tests/integration/verify_isolated_pam.py
    python3 tests/integration/verify_isolated_pam.py --fingerprint

The first command checks auth success followed by account denial. The second
also waits for a real fingerprint prompt, cancels the blocked client (SIGTERM,
then SIGKILL after 5 seconds), and requires a subsequent client to obtain a
prompt. A new prompt is a reader-reuse proxy, not proof of device idle state
or of the patched SDDM daemon's own process/barrier behavior. The script never
reads /etc/pam.d or changes host PAM, packages, display-manager state, or
fingerprint enrollment. It never records credentials or PAM message text.
"""

import argparse
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time

SOURCE = Path(__file__).with_name("isolated_pam_client.c")
SAFE_LINE = re.compile(
    r"(?:START rc=\d+|READY|AUTH_ENTER|AUTH_RETURN rc=\d+ term=[01]|"
    r"ACCOUNT_ENTER|ACCOUNT_RETURN rc=\d+|SETCRED_ENTER|SETCRED_RETURN rc=\d+|"
    r"SESSION_ENTER|SESSION_RETURN rc=\d+|PROMPT style=\d+|SIGTERM_SEEN)"
)
PROMPT = re.compile(r"PROMPT style=4")


class CheckFailed(Exception):
    pass


class Client:
    def __init__(self, executable, mode, confdir, service, user):
        self.process = subprocess.Popen(
            [str(executable), mode, str(confdir), service, user],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.pending = bytearray()
        self.lines = []

    def collect(self, seconds):
        """Drain output with a finite deadline; discard anything not a known trace."""
        end = time.monotonic() + seconds
        while self.selector.get_map() and time.monotonic() < end:
            events = self.selector.select(min(0.1, max(0.0, end - time.monotonic())))
            for key, _ in events:
                fragment = os.read(key.fd, 4096)
                if not fragment:
                    self.selector.unregister(key.fileobj)
                    continue
                self.pending.extend(fragment)
                if len(self.pending) > 8192:
                    raise CheckFailed("PAM client produced oversized output")
                while b"\n" in self.pending:
                    raw, _, self.pending = self.pending.partition(b"\n")
                    line = raw.decode("ascii", errors="replace")
                    if not SAFE_LINE.fullmatch(line):
                        raise CheckFailed("PAM client produced unexpected output (redacted)")
                    self.lines.append(line)
                    print(line, flush=True)
            if self.process.poll() is not None and not events and not self.selector.get_map():
                break

    def await_line(self, predicate, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if any(predicate(line) for line in self.lines):
                return True
            if self.process.poll() is not None:
                self.collect(0.2)
                return any(predicate(line) for line in self.lines)
            self.collect(min(0.15, max(0.0, deadline - time.monotonic())))
        return any(predicate(line) for line in self.lines)

    def stop(self, require_blocked=False):
        """Terminate within five seconds, then force-kill and reap the client."""
        was_running = self.process.poll() is None and not any(
            line.startswith("AUTH_RETURN") for line in self.lines
        )
        started = time.monotonic()
        try:
            if was_running:
                try:
                    os.killpg(self.process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    was_running = False
                deadline = time.monotonic() + 5.0
                while self.process.poll() is None and time.monotonic() < deadline:
                    self.collect(min(0.1, max(0.0, deadline - time.monotonic())))
                if self.process.poll() is None:
                    print("CANCEL forced=SIGKILL", flush=True)
                    os.killpg(self.process.pid, signal.SIGKILL)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise CheckFailed("client did not exit within cancellation bound")
            self.collect(0.2)
            if require_blocked and not was_running:
                raise CheckFailed("fingerprint client completed before cancellation")
            if require_blocked and (
                any(line.startswith("AUTH_RETURN rc=0 ") for line in self.lines)
                or (self.process.returncode == 0 and "SIGTERM_SEEN" not in self.lines)
            ):
                raise CheckFailed("fingerprint authentication finished without proven cancellation")
            print(f"CANCEL exited signal={-self.process.returncode if self.process.returncode < 0 else 0} elapsed_ms={int((time.monotonic() - started) * 1000)}", flush=True)
        finally:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=2)
            self.selector.close()
            self.process.stdout.close()


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fingerprint", action="store_true", help="require real pam_fprintd prompts and reader reuse")
    parser.add_argument("--prompt-timeout", type=float, default=15.0, help="seconds to wait for each reader prompt")
    args = parser.parse_args()
    if os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise CheckFailed("run as an ordinary user without sudo or setuid")
    if args.prompt_timeout <= 0:
        raise CheckFailed("prompt timeout must be positive")
    user = pwd.getpwuid(os.getuid()).pw_name
    with tempfile.TemporaryDirectory(prefix="fplogin-pam-") as directory:
        root = Path(directory)
        confdir = root / "pam.d"
        confdir.mkdir(mode=0o700)
        # No includes, substacks, or fallback service: all four PAM stacks are
        # specified here and exist only inside the private temporary directory.
        (confdir / "fplogin-denied").write_text(
            "auth required pam_permit.so\n"
            "account required pam_deny.so\n"
            "password required pam_deny.so\n"
            "session required pam_deny.so\n"
        )
        (confdir / "fplogin-fingerprint").write_text(
            "auth required pam_fprintd.so timeout=30\n"
            "account required pam_deny.so\n"
            "password required pam_deny.so\n"
            "session required pam_deny.so\n"
        )
        executable = root / "isolated_pam_client"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-lpam", "-o", str(executable)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        print("POLICY source=private-confdir (no host service includes)", flush=True)
        denied = Client(executable, "denied", confdir, "fplogin-denied", user)
        try:
            if not denied.await_line(lambda line: line.startswith("ACCOUNT_RETURN"), 5):
                raise CheckFailed("denied-account PAM transaction did not complete")
            denied.process.wait(timeout=2)
            denied.collect(0.2)
            expected = ["START rc=0", "READY", "AUTH_ENTER", "AUTH_RETURN rc=0 term=0",
                        "ACCOUNT_ENTER"]
            account_denied = len(denied.lines) == 6 and re.fullmatch(
                r"ACCOUNT_RETURN rc=[1-9]\d*", denied.lines[5]
            )
            if denied.lines[:5] != expected or not account_denied or denied.process.returncode != 0:
                raise CheckFailed("expected auth success and account denial only")
            print("PASS denied account: no credential or session phase entered", flush=True)
        finally:
            if denied.process.poll() is None:
                denied.stop()
            else:
                denied.selector.close()
                denied.process.stdout.close()
        if not args.fingerprint:
            print("NOT_RUN physical reader (add --fingerprint to require it)", flush=True)
            return
        for attempt in (1, 2):
            client = Client(executable, "fingerprint", confdir, "fplogin-fingerprint", user)
            saw_prompt = False
            try:
                if not client.await_line(lambda line: bool(PROMPT.fullmatch(line)), args.prompt_timeout):
                    raise CheckFailed(f"attempt {attempt}: no fprintd prompt; reader/enrollment/module unavailable or authentication ended")
                if client.process.poll() is not None:
                    raise CheckFailed(f"attempt {attempt}: client was not blocked when prompt arrived")
                saw_prompt = True
                print(f"READER_PROMPT attempt={attempt}", flush=True)
            finally:
                client.stop(require_blocked=saw_prompt)
        print("PASS fingerprint: blocked client cancelled within bound; subsequent prompt observed", flush=True)
        print("LIMIT subsequent prompt is not physical-reader idle attestation or SDDM end-to-end proof", flush=True)


def interrupted(signum, frame):
    del signum, frame
    raise CheckFailed("verification interrupted; cleaning up client")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        run()
    except KeyboardInterrupt:
        print("FAIL interrupted; client cleanup attempted", file=sys.stderr)
        sys.exit(130)
    except (CheckFailed, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
