#!/bin/bash
# Read-only guard for the pinned stock x86_64 SDDM fixture. Refuse customized
# package backups: pacman replacement can move the active file to .pacsave.
set -euo pipefail
stock=$1
printf '%s  %s\n' 927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a "$stock" | sha256sum -c --status
info=$(bsdtar -xOf "$stock" .PKGINFO)
paths=$(awk -F ' = ' '$1=="backup" {print $2}' <<<"$info")
[[ -n $paths ]]
while IFS= read -r path; do
    [[ -f /$path && $(realpath -e "/$path") == "/$path" ]] || exit 1
    bsdtar -xOf "$stock" "$path" | cmp -s - "/$path" || { echo "Refusing stock replacement: /$path differs" >&2; exit 1; }
done <<<"$paths"
