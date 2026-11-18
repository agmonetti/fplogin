#!/usr/bin/env bash
# Run as an ordinary user in an isolated Arch build environment with build dependencies installed.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
recipe="${repo}/platforms/arch/PKGBUILD"
bash -n "${recipe}"
commit="$(bash -c 'source "$1"; printf "%s\n" "${_commit}"' _ "${recipe}")"
mkdir -p "${repo}/target"
stage="$(mktemp -d "${repo}/target/arch-package.XXXXXXXX")"
cp "${recipe}" "${stage}/PKGBUILD"
git -C "${repo}" archive --format=tar --prefix=fplogin/ -o "${stage}/fplogin-${commit}.tar" "${commit}"
cd "${stage}"
export GOTOOLCHAIN=local GOPROXY=off
makepkg --noconfirm
makepkg --packagelist
