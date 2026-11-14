#!/bin/sh
# Usage (disposable container only; network used inside the container for mirrors/GitHub):
#   stage.sh <dir>/src ; docker run --rm -e OUT=out-A [-e SDE=<SOURCE_DATE_EPOCH>] \
#     --entrypoint /bin/sh -v <dir>:/pkg archlinux:base-devel /pkg/clean-build.sh
# To verify reproducibility, rebuild with SDE set to the builddate in the first package .BUILDINFO.
# Clean Arch build environment (Sprint 3, unaccepted): fresh base-devel, deps from
# Arch mirrors, sources fetched by makepkg (git commit pinned in the PKGBUILD).
set -eu
pacman -Syu --noconfirm --needed git cmake extra-cmake-modules qt6-tools qt6-base qt6-declarative \
  qt5-tools qt5-base qt5-declarative qt5-quickcontrols2 python python-docutils \
  pam systemd-libs libxcb libxau xorg-server xorg-xauth ttf-dejavu fprintd > "/pkg/${OUT}.dependencies.log" 2>&1 || { rc=$?; tail -20 "/pkg/${OUT}.dependencies.log"; exit "$rc"; }
pacman -Q git cmake qt6-base qt6-declarative qt5-base qt5-declarative qt5-quickcontrols2 extra-cmake-modules gcc
useradd -m builder
cp -r /pkg/src /home/builder/pkg && chown -R builder /home/builder/pkg
if su builder -c "cd /home/builder/pkg && SOURCE_DATE_EPOCH=${SDE:-} PKGDEST=/home/builder/out makepkg --noconfirm" > /home/builder/makepkg.log 2>&1; then
  rc=0
else
  rc=$?
fi
# Retain the original makepkg status even when exporting its log fails.
cp /home/builder/makepkg.log "/pkg/${OUT}.makepkg.log" || { test "$rc" -ne 0 || exit 1; }
tail -25 /home/builder/makepkg.log || :
test "$rc" -eq 0 || exit "$rc"
mkdir -p "/pkg/$OUT"
cp /home/builder/out/*.pkg.tar.* "/pkg/$OUT/"
echo BUILD_DONE
