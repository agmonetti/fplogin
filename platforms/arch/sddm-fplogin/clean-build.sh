#!/bin/sh
# Usage (disposable container only; network used inside the container for mirrors/GitHub):
#   stage.sh <dir>/src ; docker run --rm -e OUT=out-A [-e SDE=<SOURCE_DATE_EPOCH>] \
#     --entrypoint /bin/sh -v <dir>:/pkg archlinux:base-devel /pkg/clean-build.sh
# To verify reproducibility, rebuild with SDE set to the builddate in the first package .BUILDINFO.
# Clean Arch build environment (S3-08 preparation): fresh base-devel, deps from
# Arch mirrors, sources fetched by makepkg (git commit pinned in the PKGBUILD).
set -eu
pacman -Syu --noconfirm --needed git cmake extra-cmake-modules qt6-tools qt6-base qt6-declarative python-docutils \
  pam systemd-libs libxcb libxau xorg-server xorg-xauth ttf-dejavu fprintd >/tmp/pacman.log 2>&1 || { tail -20 /tmp/pacman.log; exit 3; }
pacman -Q git cmake qt6-base qt6-declarative extra-cmake-modules gcc | tr '\n' ' '; echo
useradd -m builder
cp -r /pkg/src /home/builder/pkg && chown -R builder /home/builder/pkg
su builder -c "cd /home/builder/pkg && SOURCE_DATE_EPOCH=${SDE:-} PKGDEST=/home/builder/out makepkg --noconfirm 2>&1 | tail -25"
mkdir -p /pkg/$OUT && cp /home/builder/out/*.pkg.tar.* /pkg/$OUT/
echo BUILD_DONE
