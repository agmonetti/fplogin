#!/usr/bin/env python3
"""Private image entrypoint: file-only disk creation, QEMU, and serial/QMP clients."""
import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import termios
import tty

LAB = Path('/lab')


def prepare():
    request = json.loads((LAB / 'request.json').read_text())
    uid, gid = request['owner_uid'], request['owner_gid']
    with tempfile.TemporaryDirectory(prefix='fplogin-root-') as directory:
        root = Path(directory)
        # Docker root is a package-populated tree, not a host root. No mounts,
        # host HOME, credentials, or enrollment are imported into this tree.
        exclude = ['lab', 'proc', 'sys', 'dev', 'run', 'tmp', 'root', 'home',
                   'build', 'source', 'setup.sh', 'boot.sh', 'client.cpp',
                   'opt/fplogin-lab', 'var/lib/fprint', '.dockerenv', '.dockerinit']
        command = ['tar', '--one-file-system', '-C', '/']
        command.extend(f'--exclude=./{name}' for name in exclude)
        command.extend(['-cf', '-', '.'])
        producer = subprocess.Popen(command, stdout=subprocess.PIPE)
        try:
            subprocess.run(['tar', '-C', directory, '-xf', '-'], stdin=producer.stdout, check=True)
        finally:
            producer.stdout.close()
        if producer.wait() != 0:
            raise RuntimeError('guest root export failed')
        for name in ['dev', 'proc', 'sys', 'run', 'tmp', 'root', 'home/fplab', 'var/lib/fprint']:
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / 'tmp').chmod(0o1777)
        (root / 'root').chmod(0o700)
        # Only the newly locked guest identity gets a home directory.
        import pwd
        account = pwd.getpwnam('fplab')
        shutil.copytree('/home/fplab', root / 'home/fplab', dirs_exist_ok=True)
        for path in [root / 'home/fplab', *(root / 'home/fplab').rglob('*')]:
            os.chown(path, account.pw_uid, account.pw_gid)
        (root / 'etc/machine-id').write_text(request['guest_machine_id'] + '\n')
        (root / 'etc/hostname').write_text('fplogin-lab\n')
        (root / 'etc/hosts').write_text('127.0.0.1 localhost fplogin-lab\n::1 localhost\n')
        (root / 'etc/resolv.conf').write_text('')
        dbus_id = root / 'var/lib/dbus/machine-id'
        dbus_id.parent.mkdir(parents=True, exist_ok=True)
        if dbus_id.is_symlink() or dbus_id.exists():
            dbus_id.unlink()
        dbus_id.symlink_to('/etc/machine-id')
        marker = root / 'etc/fplogin-lab'
        marker.mkdir(mode=0o755)
        (marker / 'host-machine-id').write_text(request['host_machine_id'] + '\n')
        (marker / 'identity.json').write_text(json.dumps({
            key: request[key] for key in ['lab_id', 'guest_machine_id', 'host_machine_id']
        }, indent=2) + '\n')
        (root / 'etc/fstab').write_text('/dev/vda / ext4 defaults 0 1\n')
        # These IDs/logs belong to the build container, not the guest.
        for name in ['var/log/journal', 'var/lib/systemd/random-seed', 'etc/ssh']:
            path = root / name
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()
        disk = LAB / 'guest.ext4'
        with disk.open('xb') as stream:
            stream.truncate(request['disk_gib'] * 1024**3)
        subprocess.run(['mke2fs', '-q', '-t', 'ext4', '-F', '-m', '0',
                        '-d', directory, str(disk)], check=True)
    for source, target in [('vmlinuz', 'vmlinuz'), ('initramfs.img', 'initramfs.img'),
                           ('runtime.sha256', 'runtime.sha256')]:
        shutil.copyfile(Path('/opt/fplogin-lab') / source, LAB / target)
    for name in ['guest.ext4', 'vmlinuz', 'initramfs.img', 'runtime.sha256']:
        path = LAB / name
        path.chmod(0o600)
        os.chown(path, uid, gid)
    print('PREPARED ext4 direct-boot disk; no reader assigned; NOT_READY for acceptance')


def boot(args):
    marker = json.loads((LAB / 'manifest.json').read_text())
    for name in ['serial.sock', 'qmp.sock']:
        path = LAB / name
        if path.exists():
            path.unlink()
    os.umask(0o077)
    command = [
        'qemu-system-x86_64', '-nodefaults', '-machine', 'q35,accel=tcg',
        '-cpu', 'max', '-smp', str(args.cpus), '-m', str(args.memory_mib),
        '-kernel', '/lab/vmlinuz', '-initrd', '/lab/initramfs.img',
        '-append', 'root=/dev/vda rootfstype=ext4 rw console=tty0 console=ttyS0,115200 '
                   f"systemd.unit=multi-user.target loglevel=4 fplogin.lab={marker['lab_id']}",
        '-drive', 'if=none,id=root,format=raw,file=/lab/guest.ext4',
        '-device', 'virtio-blk-pci,drive=root', '-device', 'virtio-vga',
        '-device', 'qemu-xhci', '-device', 'usb-kbd', '-device', 'usb-tablet',
        '-nic', 'none', '-display', 'none', '-vnc', '0.0.0.0:0',
        '-serial', 'unix:/lab/serial.sock,server=on,wait=off',
        '-qmp', 'unix:/lab/qmp.sock,server=on,wait=off',
        '-monitor', 'none', '-no-reboot',
    ]
    os.execvp(command[0], command)


def serial():
    if not sys.stdin.isatty():
        raise RuntimeError('serial recovery requires an interactive terminal')
    connection = socket.socket(socket.AF_UNIX)
    connection.connect('/lab/serial.sock')
    original = termios.tcgetattr(sys.stdin.fileno())
    print('Private disposable guest root console. Ctrl-] detaches; no serial transcript is saved.', flush=True)
    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            readable, _, _ = select.select([connection, sys.stdin], [], [])
            if connection in readable:
                data = connection.recv(65536)
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
            if sys.stdin in readable:
                data = os.read(sys.stdin.fileno(), 4096)
                if not data:
                    break
                if b'\x1d' in data:
                    data = data.split(b'\x1d', 1)[0]
                    if data:
                        connection.sendall(data)
                    break
                connection.sendall(data)
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, original)
        connection.close()


def powerdown():
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(5)
        connection.connect('/lab/qmp.sock')
        stream = connection.makefile('rwb')
        greeting = json.loads(stream.readline())
        if 'QMP' not in greeting:
            raise RuntimeError('invalid QMP greeting')
        for command in ['qmp_capabilities', 'system_powerdown']:
            stream.write((json.dumps({'execute': command}) + '\n').encode())
            stream.flush()
            while True:
                response = json.loads(stream.readline())
                if 'error' in response:
                    raise RuntimeError(str(response['error']))
                if 'return' in response:
                    break
    print('ACPI powerdown requested')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare', 'boot', 'serial', 'powerdown'])
    parser.add_argument('--memory-mib', type=int, default=3072)
    parser.add_argument('--cpus', type=int, default=2)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare()
    elif args.command == 'boot':
        boot(args)
    elif args.command == 'serial':
        serial()
    else:
        powerdown()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'LAB ERROR: {error}', file=sys.stderr)
        sys.exit(1)
