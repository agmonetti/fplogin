#!/bin/sh
# Inspect a built sddm-fplogin package against the stock Arch sddm package.
# Runs only inside a disposable container (needs pacman). Read-only on the package.
# Usage: sprint3-package-inspect.sh /path/sddm-fplogin-*.pkg.tar.zst
set -eu
pkg=$1
echo "== metadata"; pacman -Qip "$pkg" | grep -E '^(Name|Version|Provides|Conflicts With|Depends On|Backup Files)'
echo "== fplogin-specific files"
pacman -Qlp "$pkg" | awk '{print $2}' | grep -E 'pam.d/sddm-fingerprint|themes/fplogin|licenses/sddm-fplogin' 
echo "== theme root check"
pacman -Qlp "$pkg" | awk '{print $2}' | grep -q '^/usr/share/sddm/themes/fplogin/Main.qml$' && echo "Main.qml at theme root: OK" || { echo "Main.qml NOT at theme root"; exit 1; }
! pacman -Qlp "$pkg" | awk '{print $2}' | grep -q 'themes/fplogin/theme/' && echo "no nested theme/ directory: OK"
echo "== modes of sensitive files"
tmp=$(mktemp -d); bsdtar -xf "$pkg" -C "$tmp" etc/pam.d usr/share/sddm/themes/fplogin usr/bin/sddm usr/lib/sddm/sddm-helper 2>/dev/null || true
stat -c '%a %U:%G %n' "$tmp"/etc/pam.d/* "$tmp"/usr/share/sddm/themes/fplogin/* "$tmp"/usr/bin/sddm "$tmp"/usr/lib/sddm/sddm-helper 2>/dev/null | sed "s|$tmp||"
bsdtar -tvf "$pkg" etc/pam.d 2>/dev/null | awk '{print $1, $3":"$4, $NF}'
echo "== installed sddm-fingerprint matches repository file"
sha256sum "$tmp"/etc/pam.d/sddm-fingerprint | cut -d' ' -f1
echo "== file-list parity with stock sddm (paths only)"
if pacman -Qi sddm >/dev/null 2>&1; then
  pacman -Ql sddm | awk '{print $2}' | sort > "$tmp/stock"
  pacman -Qlp "$pkg" | awk '{print $2}' | sort > "$tmp/ours"
  echo "only in stock: $(comm -23 "$tmp/stock" "$tmp/ours" | wc -l)"; comm -23 "$tmp/stock" "$tmp/ours" | head -40
  echo "only in ours:  $(comm -13 "$tmp/stock" "$tmp/ours" | wc -l)"; comm -13 "$tmp/stock" "$tmp/ours" | grep -v '/translations/' | head -40
fi
rm -rf "$tmp"
