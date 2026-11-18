#!/usr/bin/env python3
"""Judge a single isolated no-touch trial; never infer a timer from elapsed time."""
import argparse
import json
import re
from itertools import pairwise
from pathlib import Path


def judge(text, daemon, helper):
    def need(ok, why):
        if not ok:
            raise ValueError(why)

    data = {}
    ticks = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = re.fullmatch(r'(tick|end|arm|fire|stop|disarm|enter|exit|pam_timeout|pam_return) (\d+)(?: (\d+))?(?: (-?\d+))?', line)
        if m is None:
            raise ValueError('unexpected trace line')
        name, stamp, pid, value = m.groups()
        t = int(stamp)
        if name == 'tick':
            need(not pid and not value, 'invalid heartbeat')
            ticks.append(t)
            continue
        need(name not in data, 'multiple events: ' + name)
        if name != 'end':
            need(pid and int(pid) == (daemon if name in ('arm', 'fire', 'stop', 'disarm') else helper), 'PID mismatch')
        else:
            need(pid is None, 'invalid end')
        need((value is not None) == (name in ('arm', 'pam_return')), 'invalid value')
        if name == 'arm':
            need(value == '30000', 'unexpected daemon setting')
        if name == 'pam_return':
            need(int(value) > 0, 'unexpected PAM result')
        data[name] = t
    need({'arm','disarm','enter','exit','end'} <= data.keys(), 'incomplete capture')
    need(ticks and min(ticks) < min(data.values()) and max(ticks) >= data['exit'], 'missing capture boundary')
    need(max(ticks) <= data['end'] and all(b-a <= 3_000_000_000 for a,b in pairwise(sorted(ticks))), 'heartbeat gap')
    need(data['arm'] < data['disarm'] and data['enter'] < data['exit'] < data['end'], 'invalid lifecycle')
    if 'pam_return' in data:
        need(data['enter'] < data['pam_return'] < data['exit'], 'invalid PAM ordering')
    if 'pam_timeout' in data:
        need(data['enter'] < data['pam_timeout'] < data.get('pam_return', data['exit']), 'invalid PAM timer ordering')
    if 'fire' in data:
        need(data['enter'] < data['fire'], 'daemon fired before PAM entry')
        need('stop' in data and data['arm'] < data['fire'] < data['disarm'] < data['stop'] < data['exit'], 'incomplete daemon stop')
        need(data['fire'] < data.get('pam_return',data['exit']), 'PAM had already returned')
        need(data['fire'] < data.get('pam_timeout',data['exit']), 'PAM timeout preceded daemon firing')
        return 'DAEMON_DEADLINE_FIRST'
    need('stop' not in data and 'pam_timeout' in data and 'pam_return' in data, 'no attributable deadline')
    need(data['pam_return'] < data['disarm'], 'ambiguous disarm')
    return 'PAM_BACKSTOP_FIRST (daemon deadline gate NOT passed)'


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('directory', type=Path)
    d = p.parse_args().directory
    meta = json.loads((d/'target.json').read_text())
    if (d/'stderr').read_text().strip() or not (d/'negative-ok').is_file():
        raise SystemExit('INCONCLUSIVE: tracer diagnostic or missing no-session/exit checks')
    try:
        verdict = judge((d/'events').read_text(), meta['daemon'], meta['helper'])
    except ValueError as e:
        raise SystemExit('INCONCLUSIVE: ' + str(e)) from e
    print(verdict)
    raise SystemExit(0 if verdict == 'DAEMON_DEADLINE_FIRST' else 2)
