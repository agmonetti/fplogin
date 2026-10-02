#!/usr/bin/env python3
"""Guest-only recovery guard; this is not physical-reader acceptance evidence."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

MARKER = Path('/etc/fplogin-lab')
ACK = Path('/run/fplogin-lab/recovery-checked')


def checked(command):
    return subprocess.check_output(command, text=True).strip()


def identity():
    if os.geteuid() != 0:
        raise RuntimeError('guest root is required')
    marker = json.loads((MARKER / 'identity.json').read_text())
    guest_id = Path('/etc/machine-id').read_text().strip()
    host_id = (MARKER / 'host-machine-id').read_text().strip()
    if guest_id != marker['guest_machine_id'] or guest_id == host_id:
        raise RuntimeError('guest/host machine identity guard failed')
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise RuntimeError('PID 1 is not guest systemd')
    if f"fplogin.lab={marker['lab_id']}" not in Path('/proc/cmdline').read_text().split():
        raise RuntimeError('not booted with the isolated lab kernel command line')
    if checked(['systemd-detect-virt', '--vm']) != 'qemu':
        raise RuntimeError('not running inside the QEMU guest')
    if Path('/proc/sys/kernel/hostname').read_text().strip() != 'fplogin-lab':
        raise RuntimeError('unexpected guest hostname')
    # The prepared emulator has no NIC. Reject any other guest configuration.
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise RuntimeError('guest network hardware exists; recovery guard refused')
    if checked(['systemctl', 'is-active', 'systemd-logind.service']) != 'active':
        raise RuntimeError('guest logind is not active')
    seat = checked(['loginctl', 'show-seat', 'seat0', '--property=CanGraphical'])
    if seat != 'CanGraphical=yes':
        raise RuntimeError('guest logind seat0 is not graphical')
    return marker


def require_recovery(marker):
    if not ACK.is_file() or ACK.read_text().strip() != marker['lab_id']:
        raise RuntimeError('exercise ttyS0 login and run fplogin-lab recovery-check first')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['identity', 'recovery-check', 'require-recovery',
                                          'start-sddm', 'status'])
    args = parser.parse_args()
    marker = identity()
    if args.command == 'recovery-check':
        if not sys.stdin.isatty() or os.ttyname(sys.stdin.fileno()) != '/dev/ttyS0':
            raise RuntimeError('acknowledgment must run from the independent ttyS0 root login')
        ACK.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        ACK.write_text(marker['lab_id'] + '\n')
        ACK.chmod(0o600)
        print('RECOVERY_CHECKED ttyS0 root; SDDM may now be started manually')
    elif args.command in ('require-recovery', 'start-sddm'):
        require_recovery(marker)
        if args.command == 'start-sddm':
            subprocess.run(['systemctl', 'start', 'sddm-lab.service'], check=True)
            print('SDDM_STARTED guest-only; physical-reader acceptance remains NOT_READY')
    elif args.command == 'status':
        print('NOT_READY no physical reader assigned to this VM; no enrollment or exclusivity proven')
        print('No USB transfer mode exists. Administrative ownership evidence is required first.')
        return 2
    else:
        print(f"IDENTITY guest={marker['guest_machine_id']} host={marker['host_machine_id']} different=yes")
        print('PID1=systemd VIRTUALIZATION=qemu NETWORK=loopback-only SEAT=guest-seat0')
        print(checked(['loginctl', 'seat-status', 'seat0']))
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
        sys.exit(1)
