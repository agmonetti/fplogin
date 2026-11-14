#!/usr/bin/env python3
"""Fail-closed Qt5 additions to a canonical Qt6 package; manifests stay outside it."""
import hashlib
import json
import os
import shutil
import stat
import sys
from pathlib import Path

ALLOWLIST = ("usr/bin/sddm-greeter", "usr/lib/qt/qml/SddmComponents",
             "usr/share/sddm/translations-qt5")


def inventory(root):
    result = {}

    def visit(path):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        name = path.relative_to(root).as_posix()
        if stat.S_ISLNK(info.st_mode):
            result[name] = ["link", mode, os.readlink(path)]
        elif stat.S_ISREG(info.st_mode):
            result[name] = ["file", mode, hashlib.sha256(path.read_bytes()).hexdigest()]
        elif stat.S_ISDIR(info.st_mode):
            result[name] = ["dir", mode]
            for child in sorted(path.iterdir()):
                visit(child)
        else:
            raise ValueError(f"special file: {path}")

    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError(f"not a real directory: {root}")
    visit(root)
    return result


def independent_roots(*paths):
    resolved = []
    for path in paths:
        absolute = Path(os.path.abspath(path))
        for ancestor in (absolute, *absolute.parents):
            if ancestor.is_symlink():
                raise ValueError(f"symlink ancestor: {ancestor}")
        resolved.append(absolute)
    for index, path in enumerate(resolved):
        for other in resolved[index + 1:]:
            if path == other or path in other.parents or other in path.parents:
                raise ValueError(f"overlapping roots: {path}, {other}")


def verify(before, after, additions):
    if any(after.get(name) != value for name, value in before.items()):
        raise ValueError("canonical entry changed or removed")
    if set(after) - set(before) != set(additions):
        raise ValueError("unexpected package additions")
    if any(after[name] != value for name, value in additions.items()):
        raise ValueError("Qt5 addition changed")


def merge(package, private, before):
    independent_roots(package, private)
    current = inventory(package)
    if current != before:
        raise ValueError("canonical tree changed before merge")
    source = inventory(private)
    additions = {}
    for root in ALLOWLIST:
        entry = source.get(root)
        expected = "file" if root == ALLOWLIST[0] else "dir"
        if entry is None or entry[0] != expected:
            raise ValueError(f"missing or invalid allowlist root: {root}")
        if expected == "file" and not entry[1] & 0o111:
            raise ValueError("Qt5 greeter is not executable")
        selected = {name: value for name, value in source.items()
                    if name == root or name.startswith(root + "/")}
        if expected == "dir" and not any(value[0] == "file" for value in selected.values()):
            raise ValueError(f"empty allowlist root: {root}")
        for name, value in selected.items():
            if value[0] not in ("dir", "file"):
                raise ValueError(f"symlink addition: {name}")
            if name in current:
                raise ValueError(f"destination collision: {name}")
            additions[name] = value
        for parent in Path(root).parents:
            name = parent.as_posix()
            if name == ".":
                continue
            if source.get(name, [None])[0] != "dir":
                raise ValueError(f"invalid source ancestor: {name}")
            if name in current:
                if current[name][0] != "dir":
                    raise ValueError(f"invalid destination ancestor: {name}")
            else:
                additions[name] = source[name]
    # Validate the entire delta before writing; never overwrite canonical entries.
    for name, value in sorted(additions.items(), key=lambda item: (item[0].count("/"), item[0])):
        target = package / name
        if value[0] == "dir":
            target.mkdir(mode=value[1])
            target.chmod(value[1])
        else:
            with (private / name).open("rb") as src, target.open("xb") as dst:
                shutil.copyfileobj(src, dst)
            target.chmod(value[1])
    after = inventory(package)
    verify(before, after, additions)
    return {"allowlist": ALLOWLIST, "private_path": str(private), "private_inventory": source,
            "before": before, "additions": additions, "after": after}


def main():
    action, package_arg, *args = sys.argv[1:]
    package = Path(package_arg)
    if action == "snapshot":
        output = Path(args[0])
        independent_roots(package, output)
        output.write_text(json.dumps(inventory(package), indent=2, sort_keys=True) + "\n")
    elif action == "merge":
        private, snapshot, output = map(Path, args)
        independent_roots(package, private, snapshot, output)
        try:
            before = json.loads(snapshot.read_text())
        except (OSError, ValueError) as error:
            raise ValueError(f"cannot read canonical snapshot: {snapshot}") from error
        result = merge(package, private, before)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        print(f"Qt5 merge: {len(result['additions'])} additions; {len(result['before'])} canonical entries unchanged")
    else:
        raise ValueError(f"unknown action: {action}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as error:
        sys.exit(f"Qt5 merge rejected: {error}")
