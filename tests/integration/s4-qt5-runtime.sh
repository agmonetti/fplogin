#!/bin/bash
# F05: verify the archived Qt5 closure, not the candidate or an install.
set -euo pipefail
export LC_ALL=C
root=$(cd "$(dirname "$0")/../.." && pwd)
lab=$root/.work/labs/sprint3
guest=$lab/e6-qt5-openssl3/rootfs
pins=$root/platforms/arch/sddm-fplogin/qt5-compatibility.json
cd "$lab/theme-candidate/runtime"
archives=() expected=()
for name in qt5-base qt5-declarative qt5-quickcontrols2 qt5-svg qt5-translations; do
    row=$(jq -er --arg n "$name" '.e6_openssl3_runtime.packages[$n] | [.filename,.sha256,.signature_sha256,.version] | @tsv' "$pins")
    IFS=$'\t' read -r file digest signature version <<<"$row"
    printf '%s  %s\n' "$digest" "$file" "$signature" "$file.sig" | sha256sum --check
    gpgv --keyring "$guest/etc/pacman.d/gnupg/pubring.gpg" --status-fd 1 "$file.sig" "$file" |
        grep -F '[GNUPG:] VALIDSIG 1519D5ABA65BF6FC2B73C7567A4E76095D8A52E4 '
    archives+=("$file") expected+=("$name $version")
done
# Empty config: resolve against the fixture DB only, never host repositories.
actual=$(pacman --config /dev/null --dbpath "$guest/var/lib/pacman" -Up --print-format '%n %v' -- "${archives[@]}")
diff <(printf '%s\n' "${expected[@]}" | sort) <(sort <<<"$actual")
