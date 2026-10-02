#!/usr/bin/env python3
"""Build and run a disposable Arch/QEMU-TCG guest inside ordinary Docker.

Host requirements: Python 3, Docker CLI/daemon usable by the ordinary user,
8+ GiB free disk (12 GiB sparse guest disk by default), and sufficient RAM.
No sudo, host D-Bus/X sockets, host HOME, or KVM. No host devices by default.
Optional --reader passes only an administrator-dedicated Synaptics 06cb:00bd.
The runtime image must already contain installed patched /usr/local SDDM.
Image builds download Arch packages; the booted guest has no network hardware.
The only published endpoint is the graphical VNC console on host loopback.
The passwordless root recovery login is intentionally restricted to the private
Unix serial socket of this disposable, no-network guest. Artifact directory
access and local Docker access therefore grant guest root access.

Commands (from the repository root, never sudo):
  python3 tests/integration/sddm_lab_vm.py prepare --lab-dir /tmp/fplogin-vm --runtime-image INSTALLED_IMAGE
  python3 tests/integration/sddm_lab_vm.py start --lab-dir /tmp/fplogin-vm
  python3 tests/integration/sddm_lab_vm.py recovery --lab-dir /tmp/fplogin-vm
  python3 tests/integration/sddm_lab_vm.py status --lab-dir /tmp/fplogin-vm
  python3 tests/integration/sddm_lab_vm.py stop --lab-dir /tmp/fplogin-vm
On ttyS0: fplogin-lab identity; fplogin-lab recovery-check;
          passwd fplab; fplogin-lab start-sddm
Readiness remains NOT_READY even with explicit --reader /dev/bus/usb/001/004:
presence is not enrollment, exclusivity, or acceptance matrix evidence.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import stat
import sys
import uuid

ASSETS = Path(__file__).resolve().parent
IMAGE_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/:@-]{0,200}')
ID_PATTERN = re.compile(r'[0-9a-f]{32}')
FILES = ['guest.ext4', 'vmlinuz', 'initramfs.img', 'runtime.sha256']
READER_PATTERN = re.compile(r'/dev/bus/usb/([0-9]{3})/([0-9]{3})')


def reader_path(value):
    match = READER_PATTERN.fullmatch(value) if isinstance(value, str) else None
    if not match or not (1 <= int(match[1]) <= 255 and 1 <= int(match[2]) <= 127):
        raise ValueError('reader must be a canonical /dev/bus/usb/BBB/DDD node')
    return value


def validate_reader(value):
    reader_path(value)
    node = Path(value)
    if node.resolve(strict=True) != node:
        raise RuntimeError('reader path must not contain symlinks')
    device = node.stat()
    bus, address = (int(part) for part in node.parts[-2:])
    if (not stat.S_ISCHR(device.st_mode) or os.major(device.st_rdev) != 189
            or os.minor(device.st_rdev) != (bus - 1) * 128 + address - 1
            or not os.access(node, os.R_OK | os.W_OK)):
        raise RuntimeError('reader must be the matching USB character device with user rw access')
    sysfs = Path(f'/sys/dev/char/{os.major(device.st_rdev)}:{os.minor(device.st_rdev)}')
    if ((sysfs / 'idVendor').read_text().strip() != '06cb'
            or (sysfs / 'idProduct').read_text().strip() != '00bd'
            or int((sysfs / 'busnum').read_text()) != bus
            or int((sysfs / 'devnum').read_text()) != address):
        raise RuntimeError('reader sysfs identity must match Synaptics 06cb:00bd and bus/address')
    result = run(['systemctl', 'show', 'fprintd.service',
                  '--property=LoadState,UnitFileState,ActiveState,SubState'],
                 text=True, stdout=subprocess.PIPE)
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if (properties.get('LoadState') != 'masked'
            or properties.get('UnitFileState') != 'masked-runtime'
            or properties.get('ActiveState') != 'inactive'
            or properties.get('SubState') != 'dead'):
        raise RuntimeError('administrator must runtime-mask and stop host fprintd before reader start')


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def image_name(value):
    if not IMAGE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError('invalid Docker image reference')
    return value


def bounded(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f'value must be between {low} and {high}')
        return number
    return parse


def directory(raw, create=False):
    path = Path(raw).absolute()
    if any(part == '..' for part in path.parts) or ',' in str(path) or '\n' in str(path):
        raise RuntimeError('lab path must be explicit, without commas, newlines, or parent traversal')
    for ancestor in [path, *path.parents]:
        if ancestor.is_symlink():
            raise RuntimeError('lab directory path must not contain symlinks')
    if path == Path('/') or path == Path.home():
        raise RuntimeError('never mount the host root or host HOME')
    if create:
        path.mkdir(mode=0o700)
    status = path.stat()
    if not path.is_dir() or status.st_uid != os.getuid() or status.st_mode & 0o077:
        raise RuntimeError('lab directory must be owned by the invoking user and private (0700)')
    return path


def load(path):
    manifest_path = path / 'manifest.json'
    if manifest_path.is_symlink():
        raise RuntimeError('manifest must not be a symlink')
    marker = json.loads(manifest_path.read_text())
    if marker.get('schema') != 1:
        raise RuntimeError('unknown lab manifest')
    for key in ['lab_id', 'guest_machine_id', 'host_machine_id']:
        if not ID_PATTERN.fullmatch(marker[key]):
            raise RuntimeError(f'invalid {key}')
    if marker['host_machine_id'] != Path('/etc/machine-id').read_text().strip():
        raise RuntimeError('lab was prepared for a different host machine')
    if marker['guest_machine_id'] == marker['host_machine_id']:
        raise RuntimeError('guest and host machine IDs must differ')
    image_name(marker['image'])
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', marker['image_id']):
        raise RuntimeError('invalid pinned lab image ID')
    if marker.get('reader') is not None:
        reader_path(marker['reader'])
    for name in FILES:
        asset = path / name
        if asset.is_symlink() or not asset.is_file() or asset.stat().st_uid != os.getuid():
            raise RuntimeError(f'unsafe or missing private lab asset: {name}')
    return marker


def container_name(marker):
    return 'fplogin-lab-' + marker['lab_id']


def inspect_container(path, marker, missing_ok=False):
    name = container_name(marker)
    result = subprocess.run(['docker', 'container', 'inspect', name], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        if missing_ok and 'No such container' in result.stderr:
            return None
        raise RuntimeError(result.stderr.strip() or 'cannot inspect lab container')
    item = json.loads(result.stdout)[0]
    config = item['HostConfig']
    all_mounts = item['Mounts']
    mounts = [mount for mount in all_mounts if mount.get('Type') != 'tmpfs']
    unexpected_tmpfs = any(mount.get('Type') == 'tmpfs'
                           and mount.get('Destination') not in ('/tmp', '/run')
                           for mount in all_mounts)
    bindings = config.get('PortBindings') or {}
    ports = bindings.get('5900/tcp', [])
    reader = marker.get('reader')
    devices = ([{'PathOnHost': reader, 'PathInContainer': reader, 'CgroupPermissions': 'rw'}]
               if reader else [])
    expected_mounts = {('/lab', str(path))}
    if reader:
        expected_mounts.add((reader, reader))
    if (item['Config'].get('Labels', {}).get('org.fplogin.lab') != marker['lab_id']
            or item['Image'] != marker['image_id']
            or config['Privileged'] or (config.get('Devices') or []) != devices
            or config.get('DeviceRequests') or config.get('DeviceCgroupRules')
            or config.get('NetworkMode') != 'bridge'
            or config.get('PidMode') or config.get('IpcMode') == 'host'
            or config.get('CapAdd') or 'ALL' not in (config.get('CapDrop') or [])
            or not config.get('ReadonlyRootfs')
            or unexpected_tmpfs or set(config.get('Tmpfs') or {}) != {'/tmp', '/run'}
            or item['Config'].get('User') != f'{os.getuid()}:{os.getgid()}'
            or len(mounts) != len(expected_mounts)
            or any(mount.get('Type') != 'bind' for mount in mounts)
            or {(mount.get('Destination'), mount.get('Source')) for mount in mounts} != expected_mounts
            or set(bindings) != {'5900/tcp'} or len(ports) != 1
            or ports[0].get('HostIp') != '127.0.0.1'):
        raise RuntimeError('container isolation contract mismatch; refusing to operate')
    return item


def build(runtime_image, tag):
    run(['docker', 'build', '--build-arg', f'RUNTIME_IMAGE={runtime_image}',
         '--tag', tag, '--file', str(ASSETS / 'sddm-lab.Dockerfile'), str(ASSETS)])


def prepare(args):
    # Validate identity/options before creating artifacts or contacting Docker.
    host_id = Path('/etc/machine-id').read_text().strip()
    if not ID_PATTERN.fullmatch(host_id):
        raise RuntimeError('host machine ID unavailable or malformed')
    path = directory(args.lab_dir, create=True)
    lab_id = uuid.uuid4().hex
    guest_id = uuid.uuid4().hex
    image = 'fplogin-sddm-lab:' + lab_id
    request = {'schema': 1, 'lab_id': lab_id, 'host_machine_id': host_id,
               'guest_machine_id': guest_id, 'disk_gib': args.disk_gib,
               'owner_uid': os.getuid(), 'owner_gid': os.getgid(), 'image': image}
    (path / 'request.json').write_text(json.dumps(request, indent=2) + '\n')
    (path / 'request.json').chmod(0o600)
    build(args.runtime_image, image)
    request['image_id'] = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', image],
                              text=True, stdout=subprocess.PIPE).stdout.strip()
    run(['docker', 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
         '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'FOWNER',
         '--security-opt', 'no-new-privileges', '--mount', f'type=bind,src={path},dst=/lab',
         request['image_id'], 'prepare'])
    (path / 'manifest.json').write_text(json.dumps(request, indent=2) + '\n')
    (path / 'manifest.json').chmod(0o600)
    print(f'PREPARED {path}\nimage={image}\nguest_machine_id={guest_id}')
    print('NOT_READY: no physical reader, enrollment, or reader exclusivity evidence')


def start(args, path, marker):
    if inspect_container(path, marker, missing_ok=True) is not None:
        raise RuntimeError('lab container already exists; use stop before restarting')
    if args.reader:
        validate_reader(args.reader)
    marker['reader'] = args.reader
    (path / 'manifest.json').write_text(json.dumps(marker, indent=2) + '\n')
    # --device grants the cgroup permission, but runc recreates its node without
    # named-user ACLs. Bind only this node to preserve the administrator's ACL.
    device_options = (['--device', f'{args.reader}:{args.reader}:rw',
                       '--mount', f'type=bind,src={args.reader},dst={args.reader}']
                      if args.reader else [])
    boot_options = ['--reader', args.reader] if args.reader else []
    run(['docker', 'run', '--detach', '--name', container_name(marker),
         '--label', 'org.fplogin.lab=' + marker['lab_id'],
         '--user', f'{os.getuid()}:{os.getgid()}', '--read-only',
         '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
         '--pids-limit', '256', '--memory', str(args.memory_mib + 1024) + 'm',
         '--network', 'bridge', '--publish', f'127.0.0.1:{args.vnc_port}:5900',
         '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m',
         '--tmpfs', '/run:rw,nosuid,nodev,size=16m',
         '--mount', f'type=bind,src={path},dst=/lab', *device_options, marker['image_id'],
         'boot', '--memory-mib', str(args.memory_mib), '--cpus', str(args.cpus), *boot_options])
    print(f'STARTED QEMU TCG; VNC=127.0.0.1:{args.vnc_port}; guest network=none')
    print('Recovery: run recovery --lab-dir, press Enter, then fplogin-lab identity and recovery-check.')
    print('SDDM remains disabled until the independent recovery login is checked.')
    print(f'READER {args.reader or "none"}; NOT_READY: enrollment, exclusivity and matrix unverified')


def stop(path, marker):
    item = inspect_container(path, marker, missing_ok=True)
    if item is None:
        print('STOPPED: no lab container exists; private guest disk retained')
        return
    name = container_name(marker)
    graceful = False
    if item['State']['Running']:
        try:
            run(['docker', 'exec', name, 'python3', '/opt/fplogin-lab/container.py', 'powerdown'])
            result = run(['docker', 'wait', name], timeout=45, stdout=subprocess.PIPE, text=True)
            graceful = result.stdout.strip() == '0'
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            graceful = False
            run(['docker', 'stop', '--time', '10', name])
    run(['docker', 'rm', name])
    print('STOPPED: ' + ('guest ACPI powerdown completed' if graceful else
                         'bounded container stop used; guest graceful shutdown not proven'))
    print('Private disk retained; delete the dedicated lab directory only when no longer needed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)
    build_parser = commands.add_parser('build-image', help='build tooling image from installed patched runtime')
    build_parser.add_argument('--runtime-image', type=image_name, required=True)
    build_parser.add_argument('--tag', type=image_name, required=True)
    prep = commands.add_parser('prepare', help='build lab image and new private ext4 disk; no loop mount')
    prep.add_argument('--lab-dir', required=True)
    prep.add_argument('--runtime-image', type=image_name, required=True)
    prep.add_argument('--disk-gib', type=bounded(8, 64), default=12)
    for name in ['start', 'recovery', 'status', 'stop']:
        command = commands.add_parser(name)
        command.add_argument('--lab-dir', required=True)
        if name == 'start':
            command.add_argument('--vnc-port', type=bounded(1024, 65535), default=5905)
            command.add_argument('--memory-mib', type=bounded(2048, 16384), default=3072)
            command.add_argument('--cpus', type=bounded(1, 8), default=2)
            command.add_argument('--reader', type=reader_path,
                                 help='opt in to one dedicated Synaptics 06cb:00bd USB node')
    args = parser.parse_args()
    if os.geteuid() == 0 or os.getuid() != os.geteuid():
        raise RuntimeError('run as an ordinary user; never sudo or setuid')
    if not shutil.which('docker'):
        raise RuntimeError('Docker CLI is required')
    if args.command == 'build-image':
        build(args.runtime_image, args.tag)
        return 0
    if args.command == 'prepare':
        prepare(args)
        return 0
    path = directory(args.lab_dir)
    marker = load(path)
    if args.command == 'start':
        start(args, path, marker)
    elif args.command == 'stop':
        stop(path, marker)
    else:
        item = inspect_container(path, marker, missing_ok=args.command == 'status')
        if args.command == 'recovery':
            if not item['State']['Running']:
                raise RuntimeError('lab container is not running')
            if not sys.stdin.isatty():
                raise RuntimeError('recovery needs a terminal (docker exec -it)')
            run(['docker', 'exec', '-it', container_name(marker), 'python3',
                 '/opt/fplogin-lab/container.py', 'serial'])
        else:
            state = item['State']['Status'] if item else 'not-started'
            print(f'INFRASTRUCTURE {state}; lab={marker["lab_id"]}')
            print(f'READER recorded={marker.get("reader") or "none"}; '
                  'NOT_READY enrollment/exclusivity and acceptance matrix unverified')
            return 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'REFUSED: {error}', file=sys.stderr)
        sys.exit(1)
