#!/usr/bin/env python3
"""Capture identifier-only SDDM lab events; never persist a raw journal.

Live capture is restricted to the booted lab VM. --journal normalizes an existing
journalctl JSON stream offline and does not claim the source was an isolated VM.
PID associations are scoped to the journal boot ID and replaced at helper start.
Missing associations remain null; timestamp proximity is not a request binding.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

TRACE_VALUES = {
    "event": {
        "helper-start", "helper-startup", "helper-launch", "helper-exit",
        "helper-exit-result", "helper-process-error", "process-error",
        "session-open-success", "session-open-failure", "session-result",
        "authorization-permit", "authorization-deny", "authorization-received",
        "kill-handshake-timeout", "terminate-intent", "kill-intent",
        "cancel-fingerprint", "cancel-attempt", "winner-authorize",
        "winner-selected", "loser-barrier-wait", "loser-barrier-release",
        "fingerprint-start-sent", "fingerprint-start-accepted",
        "probe-start", "probe-activation-request", "probe-activation-return",
        "probe-owner-pinned", "probe-owner-change", "probe-result", "probe-invalidate",
    },
    "role": {"greeter", "autologin", "password", "fingerprint"},
    "exit_status": {"normal", "crash"},
    "permit": {"true", "false"},
    "success": {"true", "false"},
    "phase": {"authenticate", "account", "setcred", "open-session", "close-session", "end"},
    "edge": {"enter", "return"},
    "reason": {
        "available", "service_unavailable", "reader_unavailable",
        "not_enrolled", "availability_unavailable",
    },
}
NUMERIC_KEYS = {
    "helper_pid", "auth_id", "generation", "method", "exit_code", "rc",
    "flags", "winner_method", "loser_method", "loser_generation", "process_error",
    "serial", "probe_generation",
}
OWNER_KEYS = {"owner", "old_owner", "new_owner"}
TRACE_KEYS = set(TRACE_VALUES) | NUMERIC_KEYS | OWNER_KEYS | {"request"}
TOKEN = re.compile(r"([a-z_]+)=([A-Za-z0-9_.:+-]+)")
SESSION_NEW = re.compile(r"New session '?([A-Za-z0-9_-]+)'? of user .+\.")
SESSION_END = re.compile(r"(?:Removed session|Session) '?([A-Za-z0-9_-]+)'?(?:\.| logged out\..*)")
DISPATCHER_WARNING = (
    "QBasicTimer::start: current thread's event dispatcher has already been destroyed"
)
SERVICE_MESSAGES = {
    "Starting Fingerprint Authentication Daemon...": "starting",
    "Started Fingerprint Authentication Daemon.": "started",
    "Stopping Fingerprint Authentication Daemon...": "stopping",
    "Stopped Fingerprint Authentication Daemon.": "stopped",
    "fprintd.service: Deactivated successfully.": "deactivated-successfully",
    "No devices in use, exit": "idle-exit",
}


def require_guest():
    marker = Path("/etc/fplogin-lab/host-machine-id")
    if not marker.is_file():
        raise RuntimeError("live capture requires the isolated lab VM marker")
    host_id = marker.read_text().strip()
    guest_id = Path("/etc/machine-id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{32}", host_id) or not re.fullmatch(r"[0-9a-f]{32}", guest_id) or host_id == guest_id:
        raise RuntimeError("invalid or shared host/guest machine identity")
    if os.geteuid() != 0 or Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("live capture requires root in a booted systemd guest")
    result = subprocess.run(
        ["systemd-detect-virt", "--vm"], capture_output=True, text=True, timeout=5,
        check=False,
    )
    if result.returncode != 0 or result.stdout.strip() not in {"qemu", "kvm"}:
        raise RuntimeError("live capture requires the QEMU lab VM")


def fields(payload):
    result = {}
    for token in payload.split():
        match = TOKEN.fullmatch(token)
        if not match or match[1] not in TRACE_KEYS or match[1] in result:
            return None
        key, value = match[1], match[2]
        if key in TRACE_VALUES and value not in TRACE_VALUES[key]:
            return None
        if key in NUMERIC_KEYS and not re.fullmatch(r"-?\d+", value):
            return None
        if key == "request" and not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value):
            return None
        if key in OWNER_KEYS and value != "none" and not re.fullmatch(r":\d+\.\d+", value):
            return None
        result[key] = value
    return result if "event" in result or {"phase", "edge"} <= result.keys() else None


class Capture:
    def __init__(self, guest_queries=False):
        self.helpers = {}
        self.sessions = {}
        self.guest_queries = guest_queries

    def normalize(self, record):
        message = record.get("MESSAGE")
        boot = record.get("_BOOT_ID")
        pid = record.get("_PID")
        monotonic = record.get("__MONOTONIC_TIMESTAMP")
        if not isinstance(message, str) or not isinstance(boot, str) or not re.fullmatch(r"[0-9a-f]{32}", boot):
            return None
        if not isinstance(pid, str) or not pid.isdecimal() or not isinstance(monotonic, str) or not monotonic.isdecimal():
            return None
        event = {
            "boot_id": boot, "monotonic_us": int(monotonic), "emitter_pid": int(pid),
        }
        for prefix in ("FPLOGIN_TRACE ", "FPLOGIN_PAM "):
            # SDDM's message handler may prepend a timestamp/category.
            position = message.find(prefix)
            if position < 0:
                continue
            data = fields(message[position + len(prefix):])
            if data is None:
                return None
            event.update(data)
            event["source"] = "pam" if prefix == "FPLOGIN_PAM " else "sddm"
            request = data.get("request")
            helper_pid = data.get("helper_pid")
            if data.get("event") in {"helper-start", "helper-startup"} and request and re.fullmatch(r"[0-9a-fA-F-]{36}", request) and helper_pid and helper_pid.isdecimal() and int(helper_pid) > 0:
                previous = self.helpers.get((boot, helper_pid), {})
                identity = previous.copy() if previous.get("request") == request else {}
                identity["request"] = request
                for key in ("role", "method", "generation"):
                    if key in data:
                        identity[key] = data[key]
                self.helpers[(boot, helper_pid)] = identity
            identity = self.helpers.get((boot, helper_pid or pid), {})
            for key in ("request", "role", "method", "generation"):
                event.setdefault(key, identity.get(key))
            return event
        if record.get("UNIT") == "fprintd.service" or record.get("_SYSTEMD_UNIT") == "fprintd.service":
            event.update(source="fprintd", event=SERVICE_MESSAGES.get(message, "message-suppressed"))
            for key in ("MESSAGE_ID", "INVOCATION_ID", "_SYSTEMD_INVOCATION_ID"):
                value = record.get(key)
                if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value):
                    event[key.lower().lstrip("_")] = value
            # Do not copy manager messages, service prose or arbitrary metadata.
            for key, allowed in (
                ("RESULT", {"success", "exit-code", "signal", "core-dump", "timeout", "watchdog", "resources"}),
                ("JOB_TYPE", {"start", "stop", "restart", "reload"}),
                ("JOB_RESULT", {"done", "failed", "timeout", "canceled", "dependency", "skipped"}),
                ("EXIT_CODE", {"exited", "killed", "dumped"}),
            ):
                value = record.get(key)
                if isinstance(value, str) and value in allowed:
                    event[key.lower()] = value
            status = record.get("EXIT_STATUS")
            if isinstance(status, str) and re.fullmatch(r"\d{1,3}", status):
                event["exit_status"] = status
            return event
        if DISPATCHER_WARNING in message:
            event.update(source="qt", event="dispatcher-destroyed", **self.helpers.get((boot, pid), {}))
            return event
        if record.get("_SYSTEMD_UNIT") == "systemd-logind.service":
            new = SESSION_NEW.fullmatch(message)
            ended = SESSION_END.fullmatch(message)
            if new or ended:
                session = (new or ended)[1]
                event.update(source="logind", event="session-new" if new else "session-ended", session=session)
                if new and self.guest_queries:
                    try:
                        result = subprocess.run(
                            ["loginctl", "show-session", session, "--property=Leader", "--value"],
                            capture_output=True, text=True, timeout=2, check=False,
                        )
                    except subprocess.TimeoutExpired:
                        result = None
                    leader = result.stdout.strip() if result is not None else ""
                    if result is not None and result.returncode == 0 and leader.isdecimal():
                        self.sessions[(boot, session)] = {
                            "leader_pid": int(leader),
                            **self.helpers.get((boot, leader), {}),
                        }
                event.update(self.sessions.get((boot, session), {}))
                # Unobserved leader/request bindings remain explicitly unknown.
                event.setdefault("request", None)
                return event
        return None


def consume(stream, output, guest_queries=False):
    capture = Capture(guest_queries=guest_queries)
    for line in stream:
        try:
            record = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError("invalid journal JSON (content suppressed)") from None
        if not isinstance(record, dict):
            raise RuntimeError("journal entry is not an object")
        event = capture.normalize(record)
        if event is not None:
            output.write(json.dumps(event, sort_keys=True) + "\n")
            output.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--journal", type=Path, help="offline journalctl JSON input; '-' reads stdin")
    parser.add_argument("--output", required=True, type=Path, help="new private JSONL evidence file (never overwritten)")
    args = parser.parse_args()
    process = None
    try:
        if args.journal is None:
            require_guest()
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            if args.journal is not None:
                if str(args.journal) == "-":
                    consume(sys.stdin, output)
                else:
                    with args.journal.open() as stream:
                        consume(stream, output)
            else:
                process = subprocess.Popen(
                    ["journalctl", "--boot", "--follow", "--output=json", "--no-pager",
                     "_SYSTEMD_UNIT=sddm-lab.service", "+",
                     "_EXE=/usr/local/libexec/sddm-helper", "+",
                     "_EXE=/usr/local/bin/sddm-greeter-qt6", "+",
                     "_SYSTEMD_UNIT=systemd-logind.service", "+",
                     "_SYSTEMD_UNIT=fprintd.service", "+", "UNIT=fprintd.service"],
                    stdout=subprocess.PIPE, text=True,
                )
                consume(process.stdout, output, guest_queries=True)
                if process.wait() != 0:
                    raise RuntimeError("journalctl failed")
    except KeyboardInterrupt:
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"capture failed: {error}", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            process.stdout.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
