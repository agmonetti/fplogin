#!/bin/bash
# Offline F05 probe for the Sprint 3 x86_64 fixture, not an installer.
# Inputs must be immutable for the run. Supply a dedicated approved candidate
# signer keyring, not one delivered with the package; never use the host DB.
set -eu -o pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
lab=$root/.work/labs/sprint3
candidate=$lab/theme-candidate/sddm-fplogin-0.21.0-3.1-x86_64.pkg.tar.zst
stock=$lab/e6-abi/stock/sddm-0.21.0-7-x86_64.pkg.tar.zst
guest=$lab/e6-qt5-openssl3/rootfs
db=$guest/var/lib/pacman
export LC_ALL=C
check_archive() {
    local archive=$1 digest=$2 name=$3 version=$4 info
    printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status || return 1
    info=$(bsdtar -xOf "$archive" .PKGINFO) || return 1
    # Require one exact value for each identity field (not just a matching line).
    [[ $(awk -F ' = ' '$1=="pkgname" {print $2}' <<<"$info") == "$name" &&
       $(awk -F ' = ' '$1=="pkgver" {print $2}' <<<"$info") == "$version" &&
       $(awk -F ' = ' '$1=="arch" {print $2}' <<<"$info") == x86_64 ]]
}
check_archive "$stock" 927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a sddm 0.21.0-7
[[ $(pacman --dbpath "$db" -Q sddm) == 'sddm 0.21.0-7' ]]
gpgv --keyring "$guest/etc/pacman.d/gnupg/pubring.gpg" --status-fd 1 "$stock.sig" "$stock" | grep -F '[GNUPG:] VALIDSIG 1519D5ABA65BF6FC2B73C7567A4E76095D8A52E4 '
check_archive "$candidate" 675904869fa349291eddd348e47fa376b5e07dace2e3f8d86d3bf60390e31be0 sddm-fplogin 0.21.0-3.1
info=$(bsdtar -xOf "$candidate" .PKGINFO)
mapfile -t deps < <(awk -F ' = ' '$1=="depend" {print $2}' <<<"$info")
expected=(bash glibc libgcc libstdc++ libxau libxcb pam qt6-base qt6-declarative qt5-base qt5-declarative qt5-quickcontrols2 qt5-svg systemd-libs ttf-font xorg-server xorg-xauth fprintd)
diff <(printf '%s\n' "${expected[@]}" | sort) <(printf '%s\n' "${deps[@]}" | sort)
failed=0
pacman --dbpath "$db" -T -- "${expected[@]}" || failed=1
if [[ ! -f $candidate.sig ]]; then
    echo 'Missing detached candidate signature' >&2
    failed=1
elif [[ ${1:-} != /* || ! -f $1 ]]; then
    echo 'Missing approved candidate signer keyring (absolute path required)' >&2
    failed=1
else
    gpgv --keyring "$1" "$candidate.sig" "$candidate" || failed=1
fi
exit "$failed"
