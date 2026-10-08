#!/usr/bin/env python3
"""Exercise the freshly exported greeter/QML on private Xvfb with a daemon peer.

Container-only synthetic transport smoke: no PAM login, reader or acceptance.
Captures empty password fields only; no password/PAM prose in evidence.
"""
import argparse
import ctypes as C
import ctypes.util
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import time
import zlib


def string(value):
    raw = value.encode('utf-16-be')
    return struct.pack('>I', len(raw)) + raw

class Peer:
    def __init__(self, connection): self.connection, self.buffer = connection, bytearray()
    def send(self, data): self.connection.sendall(data)
    def read(self, seconds=5):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                data, frame = bytes(self.buffer), {}
                offset = 0
                def take(size):
                    nonlocal offset
                    if offset + size > len(data): raise EOFError
                    value = data[offset:offset + size]; offset += size
                    return value
                def u32(): return struct.unpack('>I', take(4))[0]
                def u64(): return struct.unpack('>Q', take(8))[0]
                def text():
                    length = u32()
                    return '' if length == 0xffffffff else take(length).decode('utf-16-be')
                opcode = u32(); frame['opcode'] = opcode
                if opcode in (0, 9): pass
                elif opcode == 10:
                    frame['serial'], frame['has_context'] = u64(), u32()
                    if frame['has_context']: frame.update(user=text(), session_type=u32(), session_file=text())
                elif opcode == 11: frame.update(serial=u64(), method=u32())
                elif opcode == 12: frame.update(serial=u64(), request=text(), method=u32())
                elif opcode == 1:
                    frame['user'] = text()
                    # Deliberately never retain/log the password field.
                    password = text()
                    if password: raise RuntimeError('smoke should submit an empty field')
                    frame.update(session_type=u32(), session_file=text())
                else: raise RuntimeError(f'unexpected greeter opcode {opcode}')
                del self.buffer[:offset]
                return frame
            except EOFError:
                ready, _, _ = select.select([self.connection], [], [], max(0, end - time.monotonic()))
                if not ready: break
                fragment = self.connection.recv(65536)
                if not fragment: raise RuntimeError('greeter disconnected')
                self.buffer.extend(fragment)
        raise TimeoutError('greeter frame deadline')


def acknowledge(peer, frame, clear=False):
    serial = frame['serial']
    payload = struct.pack('>IQI', 8, serial, 1)
    if clear:
        payload += string('') + string('') + struct.pack('>I', 0) + string('') + struct.pack('>II', 2, 0) + string('cleared')
    else:
        payload += string('11111111-1111-4111-8111-111111111111') + string(frame['user'])
        payload += struct.pack('>I', frame['session_type']) + string(frame['session_file'])
        payload += struct.pack('>II', 1, 0) + string('available')
    peer.send(payload)


class XImage(C.Structure):
    _fields_ = [('width', C.c_int), ('height', C.c_int), ('xoffset', C.c_int), ('format', C.c_int),
                ('data', C.c_void_p), ('byte_order', C.c_int), ('bitmap_unit', C.c_int),
                ('bitmap_bit_order', C.c_int), ('bitmap_pad', C.c_int), ('depth', C.c_int),
                ('bytes_per_line', C.c_int), ('bits_per_pixel', C.c_int),
                ('red_mask', C.c_ulong), ('green_mask', C.c_ulong), ('blue_mask', C.c_ulong)]


class XKeyEvent(C.Structure):
    _fields_ = [
        ('type', C.c_int),
        ('serial', C.c_ulong),
        ('send_event', C.c_int),
        ('display', C.c_void_p),
        ('window', C.c_ulong),
        ('root', C.c_ulong),
        ('subwindow', C.c_ulong),
        ('time', C.c_ulong),
        ('x', C.c_int),
        ('y', C.c_int),
        ('x_root', C.c_int),
        ('y_root', C.c_int),
        ('state', C.c_uint),
        ('keycode', C.c_uint),
        ('same_screen', C.c_int),
    ]


X11 = C.CDLL(ctypes.util.find_library('X11') or 'libX11.so.6')
X11.XOpenDisplay.argtypes = [C.c_char_p]
X11.XOpenDisplay.restype = C.c_void_p
X11.XCloseDisplay.argtypes = [C.c_void_p]
X11.XCloseDisplay.restype = C.c_int
X11.XDefaultRootWindow.argtypes = [C.c_void_p]
X11.XDefaultRootWindow.restype = C.c_ulong
X11.XGetImage.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_int, C.c_uint, C.c_uint, C.c_ulong, C.c_int]
X11.XGetImage.restype = C.POINTER(XImage)
X11.XDestroyImage.argtypes = [C.POINTER(XImage)]
X11.XDestroyImage.restype = C.c_int
X11.XGetInputFocus.argtypes = [C.c_void_p, C.POINTER(C.c_ulong), C.POINTER(C.c_int)]
X11.XGetInputFocus.restype = C.c_int
X11.XQueryTree.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_ulong), C.POINTER(C.c_ulong),
                           C.POINTER(C.POINTER(C.c_ulong)), C.POINTER(C.c_uint)]
X11.XQueryTree.restype = C.c_int
X11.XKeysymToKeycode.argtypes = [C.c_void_p, C.c_ulong]
X11.XKeysymToKeycode.restype = C.c_uint
X11.XSendEvent.argtypes = [C.c_void_p, C.c_ulong, C.c_int, C.c_long, C.c_void_p]
X11.XSendEvent.restype = C.c_int
X11.XSync.argtypes = [C.c_void_p, C.c_int]
X11.XSync.restype = C.c_int
X11.XFree.argtypes = [C.c_void_p]
X11.XFree.restype = C.c_int


def screenshot(path):
    display = X11.XOpenDisplay(b':88')
    if not display: raise RuntimeError('private display unavailable')
    root = X11.XDefaultRootWindow(display)
    image = X11.XGetImage(display, root, 0, 0, 1280, 800, C.c_ulong(-1).value, 2)
    if not image or image.contents.bits_per_pixel != 32: raise RuntimeError('unexpected private display format')
    info = image.contents
    raw = C.string_at(info.data, info.bytes_per_line * info.height)
    rows = bytearray()
    for y in range(info.height):
        rows.append(0)
        for offset in range(y * info.bytes_per_line, y * info.bytes_per_line + info.width * 4, 4):
            pixel = int.from_bytes(raw[offset:offset + 4], 'little' if info.byte_order == 0 else 'big')
            rows.extend(((pixel >> 16) & 255, (pixel >> 8) & 255, pixel & 255))
    def chunk(kind, data): return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', info.width, info.height, 8, 2, 0, 0, 0))
    path.write_bytes(png + chunk(b'IDAT', zlib.compress(bytes(rows))) + chunk(b'IEND', b''))
    X11.XDestroyImage(image)
    X11.XCloseDisplay(display)


def press_return():
    display = X11.XOpenDisplay(b':88')
    if not display: raise RuntimeError('cannot open display :88')
    root = X11.XDefaultRootWindow(display)
    focus_win = C.c_ulong()
    revert_to = C.c_int()
    X11.XGetInputFocus(display, C.byref(focus_win), C.byref(revert_to))
    target = focus_win.value
    if target <= 1:
        root_ret = C.c_ulong()
        parent_ret = C.c_ulong()
        children_ret = C.POINTER(C.c_ulong)()
        nchildren_ret = C.c_uint()
        if X11.XQueryTree(display, root, C.byref(root_ret), C.byref(parent_ret), C.byref(children_ret), C.byref(nchildren_ret)):
            if nchildren_ret.value > 0:
                target = children_ret[nchildren_ret.value - 1]
            if children_ret:
                X11.XFree(children_ret)
        if target <= 1:
            target = root
    key = X11.XKeysymToKeycode(display, 0xff0d)
    for etype in (2, 3):
        ev = XKeyEvent()
        ev.type = etype
        ev.display = display
        ev.window = target
        ev.root = root
        ev.subwindow = 0
        ev.time = 0
        ev.x = 1
        ev.y = 1
        ev.x_root = 1
        ev.y_root = 1
        ev.state = 0
        ev.keycode = key
        ev.same_screen = 1
        mask = (1 << 0) if etype == 2 else (1 << 1)
        X11.XSendEvent(display, target, True, mask, C.byref(ev))
    X11.XSync(display, 0)
    X11.XCloseDisplay(display)

def run_case(greeter, theme, evidence, fallback=False, scale=1):
    name = 'fallback' if fallback else ('theme' if scale == 1 else 'theme-scaled')
    path = Path('/lab/greeter-smoke.socket'); path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(path)); server.listen(1); server.settimeout(10)
        environment = dict(os.environ, DISPLAY=':88', QT_QPA_PLATFORM='xcb', QT_QUICK_BACKEND='software',
                           QT_QUICK_CONTROLS_STYLE='Basic', QT_IM_MODULE='', QT_SCALE_FACTOR=str(scale),
                           QT_LOGGING_RULES='qt.qml.binding.removal.info=false',
                           QT_FORCE_STDERR_LOGGING='1')
        process = subprocess.Popen([str(greeter), '--test-mode', '--socket', str(path), '--theme', str(theme)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=environment)
        frames = []
        try:
            connection, _ = server.accept()
            with connection:
                peer = Peer(connection)
                if peer.read()['opcode'] != 0 or peer.read()['opcode'] != 9: raise RuntimeError('missing capability query')
                peer.send(struct.pack('>II', 5, 2))
                if not fallback:
                    context = peer.read()
                    if context['opcode'] != 10 or context['has_context'] != 1: raise RuntimeError('no concrete initial context')
                    frames.append(context)
                    acknowledge(peer, context)
                    start = peer.read()
                    if start['opcode'] != 11 or start['serial'] != context['serial']: raise RuntimeError('no automatic reader intent')
                    frames.append(start)
                    payload = struct.pack('>IQ', 9, context['serial']) + string('11111111-1111-4111-8111-111111111111')
                    payload += struct.pack('>I', 1) + string(context['user']) + struct.pack('>I', context['session_type'])
                    payload += string(context['session_file']) + struct.pack('>II', 2, 1) + string('scanning')
                    peer.send(payload)
                else:
                    try:
                        clear = peer.read(1)
                    except TimeoutError:
                        clear = None  # No method context was ever opted into.
                    if clear is not None:
                        if clear['opcode'] != 10 or clear['has_context'] != 0:
                            raise RuntimeError('embedded fallback tried method activation')
                        frames.append(clear)
                        peer.send(struct.pack('>I', 3))
                        acknowledge(peer, clear, clear=True)
                time.sleep(1)
                if process.poll() is not None: raise RuntimeError('greeter exited during surface smoke')
                screenshot(evidence / f'{name}-empty-field.png')
                press_return()
                login = peer.read()
                if login['opcode'] != 1: raise RuntimeError('focused password Enter did not submit')
                if login['user'] != 'fplogin-smoke': raise RuntimeError('login identity changed')
                frames.append(login)
            process.terminate()
            output = process.communicate(timeout=10)[0].decode(errors='replace')
            if 'TypeError' in output or 'ReferenceError' in output or 'binding loop' in output.lower():
                raise RuntimeError('QML runtime error: ' + output)
            if fallback and output.count('Fallback to embedded theme') != 1: raise RuntimeError('fallback recursion or missing fallback')
            (evidence / f'{name}-greeter.log').write_text(output)
            return {'case': name, 'frames': frames, 'screenshot': f'{name}-empty-field.png', 'exit': process.returncode}
        finally:
            if process.poll() is None: process.kill(); process.wait(timeout=5)
            path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--greeter', type=Path, required=True)
    parser.add_argument('--theme', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').exists() or os.geteuid() != 0 or not Path('/lab').is_dir():
        raise RuntimeError('isolated container only, never host execution')
    subprocess.run(['useradd', '-u', '25000', '-M', '-s', '/bin/bash', 'fplogin-smoke'], check=True)
    Path('/lab/session.desktop').write_text('[Desktop Entry]\nName=Smoke Desktop\nExec=/bin/true\nTryExec=/bin/true\nType=Application\n')
    config = '[X11]\nSessionDir=/lab\n[Wayland]\nSessionDir=\n[Users]\nMinimumUid=25000\nMaximumUid=25000\n'
    Path('/etc/sddm.conf').write_text(config)
    Path('/usr/local/etc').mkdir(parents=True, exist_ok=True)
    Path('/usr/local/etc/sddm.conf').write_text(config)
    missing = Path('/lab/nonexistent-theme')
    args.evidence.mkdir(parents=True, exist_ok=True)
    xvfb = subprocess.Popen(['Xvfb', ':88', '-screen', '0', '1280x800x24', '-nolisten', 'tcp'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1)
        results = [run_case(args.greeter, args.theme, args.evidence),
                   run_case(args.greeter, args.theme, args.evidence, scale=2.5),
                   run_case(args.greeter, missing, args.evidence, fallback=True)]
        (args.evidence / 'greeter-surface-smoke.json').write_text(json.dumps({
            'status': 'passed-synthetic-peer-no-PAM-no-reader-no-sprint-acceptance', 'results': results}, indent=2) + '\n')
        print(json.dumps(results, indent=2))
    finally:
        xvfb.terminate(); xvfb.wait(timeout=5)
        Path('/lab/session.desktop').unlink(missing_ok=True)

if __name__ == '__main__': main()
