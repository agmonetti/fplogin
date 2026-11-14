#!/usr/bin/env python3
"""Container-only installed-package rendering smoke. No peer, PAM or real login.

Run as an unprivileged user on a fresh Xvfb display after installing the inspected
archive. A mapped PID-owned window corroborates QQuickView::Ready (showFullScreen
is called only after Ready); fallback/errors still fail the very same check.
"""
import argparse
import configparser
import ctypes as C
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

X11 = C.CDLL('libX11.so.6')
X11.XOpenDisplay.argtypes = [C.c_char_p]
X11.XOpenDisplay.restype = C.c_void_p
X11.XDefaultRootWindow.argtypes = [C.c_void_p]
X11.XDefaultRootWindow.restype = C.c_ulong
X11.XQueryTree.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(C.c_ulong), C.POINTER(C.c_ulong),
                         C.POINTER(C.POINTER(C.c_ulong)), C.POINTER(C.c_uint)]
X11.XInternAtom.argtypes = [C.c_void_p, C.c_char_p, C.c_int]
X11.XInternAtom.restype = C.c_ulong
X11.XGetWindowProperty.argtypes = [C.c_void_p, C.c_ulong, C.c_ulong, C.c_long, C.c_long, C.c_int, C.c_ulong,
                                 C.POINTER(C.c_ulong), C.POINTER(C.c_int), C.POINTER(C.c_ulong),
                                 C.POINTER(C.c_ulong), C.POINTER(C.POINTER(C.c_ubyte))]
X11.XFree.argtypes = [C.c_void_p]
X11.XCloseDisplay.argtypes = [C.c_void_p]


class Attributes(C.Structure):
    _fields_ = [('x', C.c_int), ('y', C.c_int), ('width', C.c_int), ('height', C.c_int),
                ('border_width', C.c_int), ('depth', C.c_int), ('visual', C.c_void_p),
                ('root', C.c_ulong), ('window_class', C.c_int), ('bit_gravity', C.c_int),
                ('win_gravity', C.c_int), ('backing_store', C.c_int), ('backing_planes', C.c_ulong),
                ('backing_pixel', C.c_ulong), ('save_under', C.c_int), ('colormap', C.c_ulong),
                ('map_installed', C.c_int), ('map_state', C.c_int), ('all_event_masks', C.c_long),
                ('your_event_mask', C.c_long), ('do_not_propagate_mask', C.c_long),
                ('override_redirect', C.c_int), ('screen', C.c_void_p)]


X11.XGetWindowAttributes.argtypes = [C.c_void_p, C.c_ulong, C.POINTER(Attributes)]


def mapped_windows(pid):
    display = X11.XOpenDisplay(b':88')
    if not display:
        raise RuntimeError('cannot open isolated display')
    windows = []
    children = C.POINTER(C.c_ulong)()
    try:
        root = X11.XDefaultRootWindow(display)
        root_return, parent = C.c_ulong(), C.c_ulong()
        count = C.c_uint()
        if not X11.XQueryTree(display, root, C.byref(root_return), C.byref(parent), C.byref(children), C.byref(count)):
            raise RuntimeError('XQueryTree failed')
        for index in range(count.value):
            window = children[index]
            actual, size, remaining = C.c_ulong(), C.c_ulong(), C.c_ulong()
            fmt = C.c_int()
            data = C.POINTER(C.c_ubyte)()
            status = X11.XGetWindowProperty(display, window, X11.XInternAtom(display, b'_NET_WM_PID', 0),
                                           0, 1, 0, 6, C.byref(actual), C.byref(fmt), C.byref(size),
                                           C.byref(remaining), C.byref(data))
            try:
                owner = C.cast(data, C.POINTER(C.c_ulong))[0] if status == 0 and fmt.value == 32 and size.value == 1 else None
                attrs = Attributes()
                if owner == pid and X11.XGetWindowAttributes(display, window, C.byref(attrs)) and attrs.map_state == 2:
                    windows.append({'id': window, 'pid': owner, 'width': attrs.width, 'height': attrs.height})
            finally:
                if data:
                    X11.XFree(data)
    finally:
        if children:
            X11.XFree(children)
        X11.XCloseDisplay(display)
    return windows


def validate(log, theme, module, windows, alive):
    if not alive or not windows:
        raise ValueError('no live mapped greeter root')
    if f'Loading file://{theme}/Main.qml...' not in log:
        raise ValueError('expected theme not selected')
    diagnostics(log)
    if re.search(r'/(?:repo|src|build|home/builder)/', log):
        raise ValueError('source/build path leaked into runtime resolution')
    if module and not re.search(re.escape(module) + r'/\w+\.qml', log):
        raise ValueError('no packaged SddmComponents resolution')


def diagnostics(log):
    expected = []
    deprecation = re.compile(
        r'^file:///(?:usr/lib/qt/qml/SddmComponents/LayoutBox.qml|usr/share/sddm/themes/(?:elarun|maldives|maya)/Main.qml)'
        r':\d+:\d+: QML Connections: Implicitly defined onFoo properties in Connections are deprecated\. '
        r'Use this syntax instead: function onFoo\(<arguments>\) \{ \.\.\. \}$')
    for line in log.splitlines():
        if line == 'Socket error:  "QLocalSocket::connectToServer: Invalid name"' or deprecation.fullmatch(line):
            expected.append(line)
            continue
        if re.search(r'fallback|qrc:/theme|error|warning|binding loop|is not installed|is not a type|No such file|Cannot assign|Unable to assign|failed to load|unsupported image', line, re.I) or re.match(r'^(?:file:|qrc:).*:\d+(?::\d+)?:', line):
            raise ValueError('unexpected QML/runtime diagnostic: ' + line)
    return expected


def environment(runtime):
    # Whitelist, never inherit QML/Qt paths, plugin overrides or preload settings.
    return {'PATH': '/usr/bin', 'HOME': str(runtime), 'LANG': 'C.UTF-8', 'DISPLAY': ':88',
            'XDG_RUNTIME_DIR': str(runtime), 'QT_QPA_PLATFORM': 'xcb', 'QT_QUICK_BACKEND': 'software',
            'QT_QUICK_CONTROLS_STYLE': 'Basic', 'QT_IM_MODULE': '', 'QML_IMPORT_TRACE': '1',
            'QT_FORCE_STDERR_LOGGING': '1'}


def run_theme(binary, theme, evidence, env, name, module=None):
    log_path = evidence / f'{name}.log'
    windows = []
    with log_path.open('w') as log:
        process = subprocess.Popen([binary, '--test-mode', '--theme', str(theme)], stdout=log,
                                   stderr=subprocess.STDOUT, env=env)
        try:
            end = time.monotonic() + 10
            while time.monotonic() < end and process.poll() is None:
                windows = mapped_windows(process.pid)
                if windows:
                    break
                time.sleep(0.1)
            time.sleep(2)
            alive = process.poll() is None
            windows = mapped_windows(process.pid) if alive else []
            log.flush()
            validate(log_path.read_text(), theme, module, windows, alive)
            executable = os.readlink(f'/proc/{process.pid}/exe')
            if executable != binary:
                raise ValueError('wrong running executable')
            svg_plugin = '/usr/lib/qt/plugins/imageformats/libqsvg.so'
            svg_loaded = svg_plugin in Path(f'/proc/{process.pid}/maps').read_text()
            if name == 'maya' and not svg_loaded:
                raise ValueError('Maya did not load installed Qt5 SVG image plugin')
            return {'theme': str(theme), 'binary': binary, 'pid': process.pid, 'executable': executable,
                    'mapped_windows': windows, 'live_after_mapping_seconds': 2,
                    'termination': 'intentional SIGTERM after bounded rendering observation', 'log': log_path.name,
                    'expected_warnings': diagnostics(log_path.read_text()), 'exit_before_termination': process.poll(),
                    'qt5_svg_plugin_mapped': svg_plugin if svg_loaded else None}
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inspection', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if not Path('/.dockerenv').exists() or os.geteuid() == 0:
        raise RuntimeError('unprivileged disposable container only')
    args.evidence.mkdir(parents=True, exist_ok=True)
    inspection = json.loads(args.inspection.read_text())
    for name, expected in inspection['payload_files'].items():
        if hashlib.sha256((Path('/') / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f'installed file mismatch: {name}')
    runtime = args.evidence / 'runtime'
    runtime.mkdir(mode=0o700)
    env = environment(runtime)
    linkage = subprocess.run(['readelf', '-d', '/usr/lib/qt6/bin/qml'], capture_output=True, text=True, check=True).stdout
    if 'libQt6Core.so.6' not in linkage or 'libQt5' in linkage:
        raise ValueError('module fixture runner is not Qt6')
    results = []
    for name, major in [('elarun', 5), ('maldives', 5), ('maya', 5), ('fplogin', 6)]:
        theme = Path('/usr/share/sddm/themes') / name
        meta = configparser.ConfigParser()
        meta.read(theme / 'metadata.desktop')
        if meta.getint('SddmGreeterTheme', 'QtVersion', fallback=5) != major:
            raise ValueError(f'unexpected QtVersion: {name}')
        binary = '/usr/bin/sddm-greeter' + ('-qt6' if major == 6 else '')
        results.append(run_theme(binary, theme, args.evidence, env, name,
                                 '/usr/lib/qt/qml/SddmComponents' if major == 5 else None))
    # fplogin does not import SddmComponents; instantiate the installed Qt6 module separately.
    fixture = args.evidence / 'module-qt6.qml'
    fixture.write_text('import QtQuick\nimport SddmComponents 2.0\nTextBox { Component.onCompleted: { console.log("E4_QT6_MODULE_READY"); Qt.quit() } }\n')
    module_env = dict(env, QML_IMPORT_PATH='/usr/lib/qt6/qml')
    module = subprocess.run(['/usr/lib/qt6/bin/qml', str(fixture)], env=module_env,
                            capture_output=True, text=True, timeout=15)
    module_log = module.stdout + module.stderr
    (args.evidence / 'module-qt6.log').write_text(module_log)
    diagnostics(module_log)
    if module.returncode != 0 or 'E4_QT6_MODULE_READY' not in module_log or '/usr/lib/qt6/qml/SddmComponents/TextBox.qml' not in module_log:
        raise ValueError('packaged Qt6 module did not instantiate')
    # Broken fixture uses the identical validator, so a surviving embedded fallback cannot pass.
    broken = args.evidence / 'broken-theme'
    broken.mkdir()
    (broken / 'Main.qml').write_text('import MissingE4Module 99.0\nItem {}\n')
    try:
        run_theme('/usr/bin/sddm-greeter', broken, args.evidence, env, 'negative-broken-theme')
    except ValueError:
        negative = (args.evidence / 'negative-broken-theme.log').read_text()
        if 'MissingE4Module' not in negative or 'Fallback to embedded theme' not in negative:
            raise ValueError('negative control did not exercise QML failure/fallback') from None
    else:
        raise ValueError('broken theme incorrectly passed')
    result = {'status': 'PASS - installed package rendering only; no protocol/password/PAM login',
              'candidate_sha256': inspection['candidate_sha256'], 'uid': os.geteuid(),
              'installed_payload_hashes_verified': len(inspection['payload_files']), 'results': results,
              'qt6_module': 'TextBox completion marker + installed path trace; qml is Qt6-linked',
              'negative_control': 'broken module rejected by same mapped-root/theme validator'}
    (args.evidence / 'runtime.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
