#!/bin/sh
# Stage a self-contained sddm-fplogin build directory from this repository.
# Usage: platforms/arch/sddm-fplogin/stage.sh <empty-output-dir>
set -eu
root=$(cd "$(dirname "$0")/../../.." && pwd)
out=$1
test -d "$out" && test -z "$(ls -A "$out")" || { echo "output must be an empty directory"; exit 2; }
here=$root/platforms/arch/sddm-fplogin
cp "$here/0000-cmake-raise-required-version.patch" "$out/"
cp "$root/adapters/sddm/patches/0001-concurrent-authentication-methods.patch" "$out/"
cp "$root/adapters/sddm/patches/0002-greeter-api-and-theme-lifecycle.patch" "$out/"
cp "$root/platforms/arch/pam/sddm-fingerprint" "$out/"
for f in Main.qml metadata.desktop theme.conf LICENSE; do
  cp "$root/adapters/sddm/assets/theme/$f" "$out/fplogin-$(echo "$f" | sed 's/^theme\.conf$/theme.conf/')"
done
sums=""
for f in 0000-cmake-raise-required-version.patch 0001-concurrent-authentication-methods.patch \
         0002-greeter-api-and-theme-lifecycle.patch sddm-fingerprint fplogin-Main.qml \
         fplogin-metadata.desktop fplogin-theme.conf fplogin-LICENSE; do
  sums="$sums'$(sha256sum "$out/$f" | cut -d' ' -f1)' "
done
sed "s|@CHECKSUMS@|$sums|" "$here/PKGBUILD.in" > "$out/PKGBUILD"
echo "staged $out"
