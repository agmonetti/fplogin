#!/usr/bin/env python3
"""Capture an allowlisted logind snapshot or verify one guest-only keyring trial."""
import argparse
import json
import re
import subprocess
import time
import uuid
from pathlib import Path

BOOT = Path('/proc/sys/kernel/random/boot_id')
MARKER = Path('/etc/fplogin-lab/host-machine-id')
IDENT = r'[A-Za-z0-9_-]{1,32}'
PROPERTIES = ('Id', 'Name', 'Seat', 'Service', 'Type', 'Class', 'Active', 'Leader')
EXPECTED = {'Seat': 'seat0', 'Service': 'sddm-fingerprint', 'Type': 'wayland',
            'Class': 'user', 'Active': 'yes'}
HEALTH = re.compile(r'(heartbeat|end) ([1-9][0-9]{0,18})')
HOOK = re.compile(r'(enter|return) (pam|gnome|kwallet) ([1-9][0-9]{0,18}) '
                  r'([1-9][0-9]{0,9}) ([1-9][0-9]{0,9})(?: (-?[0-9]{1,10}))?')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def boot_id(text):
    return uuid.UUID(text.strip()).hex


def snapshot(session, user):
    require(re.fullmatch(IDENT, session) and re.fullmatch(IDENT, user), 'invalid session/user identifier')
    require(MARKER.is_file() and MARKER.read_text().strip() !=
            Path('/etc/machine-id').read_text().strip(), 'not a marked disposable lab guest')
    boot = boot_id(BOOT.read_text())
    observed_ns = time.monotonic_ns()
    data = subprocess.check_output(['loginctl', 'show-session', '--no-pager',
                                    *[f'--property={p}' for p in PROPERTIES], '--', session],
                                   text=True, timeout=5, stderr=subprocess.DEVNULL)
    props = {}
    for line in data.splitlines():
        key, sep, value = line.partition('=')
        require(bool(sep) and key in PROPERTIES and key not in props, 'invalid logind response')
        props[key] = value
    require(boot == boot_id(BOOT.read_text()), 'boot changed during snapshot')
    require(props.get('Id') == session and props.get('Name') == user and
            all(props.get(k) == v for k, v in EXPECTED.items()) and
            re.fullmatch(r'[1-9][0-9]{0,9}', props.get('Leader', '')), 'not the expected active fingerprint session')
    require(Path(f'/proc/{props["Leader"]}/exe').readlink() == Path('/usr/lib/sddm/sddm-helper'),
            'session leader is not the installed SDDM helper')
    return {'boot': boot, 'observed_ns': observed_ns, **{p: props[p] for p in PROPERTIES}}


def verify(directory, user):
    require(re.fullmatch(IDENT, user), 'invalid user identifier')
    require((directory / 'trace.stderr').stat().st_size == 0 and
            (directory / 'trace.status').read_text().strip() == '0', 'tracer failure, warnings or lost events')
    boot = boot_id((directory / 'boot.before').read_text())
    require(boot == boot_id((directory / 'boot.after').read_text()), 'capture boot mismatch')
    require((directory / 'trace.txt').stat().st_size <= 64_000, 'capture exceeds single-attempt bounds')
    session = json.loads((directory / 'session.json').read_text())
    require(isinstance(session, dict) and session.get('boot') == boot and session.get('Name') == user and
            all(session.get(k) == v for k, v in EXPECTED.items()) and
            isinstance(session.get('Id'), str) and re.fullmatch(IDENT, session['Id']) and
            isinstance(session.get('Leader'), str) and re.fullmatch(r'[1-9][0-9]{0,9}', session['Leader']) and
            type(session.get('observed_ns')) is int, 'missing or mismatched logind snapshot')
    leader = int(session['Leader'])
    heartbeats, ends, records = [], [], {}
    with (directory / 'trace.txt').open(encoding='ascii') as f:
        for i, line in enumerate(f):
            require(i < 500 and len(line) < 128, 'capture exceeds single-attempt bounds')
            health = HEALTH.fullmatch(line.rstrip('\n'))
            if health:
                (heartbeats if health[1] == 'heartbeat' else ends).append(int(health[2]))
                continue
            row = HOOK.fullmatch(line.rstrip('\n'))
            if row is None:
                raise ValueError('unrecognized trace record')
            phase, target, ns, pid, tid, rc = row.groups()
            require((phase == 'return') == (rc is not None), 'malformed hook result')
            # SDDM may invoke the same hooks for its greeter, not the user session.
            if int(pid) == leader:
                require((target, phase) not in records, 'ambiguous repeated hook on leader')
                records[target, phase] = (int(ns), int(tid), None if rc is None else int(rc))

    def pair(target):
        enter = records.get((target, 'enter'))
        leave = records.get((target, 'return'))
        if enter is None or leave is None:
            raise ValueError(f'{target} call/return missing')
        require(enter[0] < leave[0] and enter[1] == leave[1], f'{target} call/return mismatch')
        return enter, leave

    start, finish = pair('pam')
    require(finish[2] == 0, 'pam_open_session did not return PAM_SUCCESS')
    require(len(ends) == 1 and len(heartbeats) >= 2, 'missing capture health/end markers')
    times = sorted(heartbeats)
    require(times[0] < start[0] and finish[0] < session['observed_ns'] < times[-1] < ends[0] and
            all(0 < b - a <= 3_000_000_000 for a, b in zip(times[:-1], times[1:], strict=True)),
            'unhealthy capture or session snapshot outside trace coverage')
    results = {}
    spans = []
    for target in ('gnome', 'kwallet'):
        enter, leave = pair(target)
        require(start[0] < enter[0] < leave[0] < finish[0] and enter[1] == start[1],
                f'{target} hook not nested in this PAM transaction')
        results[target] = {'enter_ns': enter[0], 'return_ns': leave[0], 'rc': leave[2]}
        spans.append((enter[0], leave[0]))
    spans.sort()
    require(spans[0][1] < spans[1][0], 'overlapping PAM module hooks')
    return {'invocations': 'verified', 'boot': boot, 'session': session['Id'], 'helper_pid': leader,
            'pam_open_session_rc': 0, 'hooks': results, 'operator_prompt': 'not inferred'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    capture = sub.add_parser('snapshot')
    capture.add_argument('session')
    capture.add_argument('user')
    offline = sub.add_parser('verify')
    offline.add_argument('directory', type=Path)
    offline.add_argument('user')
    args = parser.parse_args()
    try:
        result = (snapshot(args.session, args.user) if args.command == 'snapshot'
                  else verify(args.directory, args.user))
    except ValueError as exc:
        # Do not echo parser errors: an unexpected record may contain private data.
        if isinstance(exc, (UnicodeError, json.JSONDecodeError)):
            parser.exit(1, 'BLOCKED: unreadable evidence\n')
        parser.exit(1, f'BLOCKED: {exc}\n')
    except (OSError, subprocess.SubprocessError, TypeError, KeyError):
        parser.exit(1, 'BLOCKED: unavailable or malformed evidence\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
