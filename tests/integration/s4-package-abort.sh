#!/bin/bash
# Inner half of the disposable F05 container probe. Never run on a host.
set -euo pipefail
export LC_ALL=C
[[ -f /.dockerenv && ! -e /run/systemd/system && $(id -u) == 0 && ! -e /etc/machine-id ]]
[[ $(findmnt -n -o FSTYPE /) == overlay && -f /f05-verified-inputs ]]
systemd-machine-id-setup
cd /inputs
sha256sum -c /f05-verified-inputs
cp -r /public-keyring /run/f05-keys
printf '[options]\nArchitecture = auto\nLocalFileSigLevel = Required TrustedOnly\n' >/run/f05.conf
pkg=(pacman --config /run/f05.conf --gpgdir /run/f05-keys)
qt=(qt5-{translations,base,declarative,quickcontrols2,svg}-*.pkg.tar.zst)
[[ ${#qt[@]} == 5 && $(pacman -Q sddm) == 'sddm 0.21.0-7' ]]
for file in "${qt[@]}"; do ! pacman -Q "$(pacman -Qp "$file" | cut -d' ' -f1)" >/dev/null 2>&1 || exit 1; done
snapshot() {
    pacman -Q; pacman -Qqe; sha256sum /usr/bin/sddm
    find /etc -maxdepth 1 -type f -name sddm.conf -exec sha256sum '{}' +
    find /etc/pam.d /etc/sddm.conf.d -type f -exec sha256sum '{}' + | sort
    systemctl is-enabled sddm.service || [[ $? == 1 ]]
}
mkdir -p /etc/sddm.conf.d
stock=/var/cache/pacman/pkg/sddm-0.21.0-7-x86_64.pkg.tar.zst
bash /stock-guard "$stock"
cp -p /etc/pam.d/sddm /run/clean-pam
printf '\n# F05 local PAM customization\n' >> /etc/pam.d/sddm
if bash /stock-guard "$stock"; then exit 1; fi
# Reset the deliberately modified test input before the separate clean case.
cp -p /run/clean-pam /etc/pam.d/sddm
bash /stock-guard "$stock"
printf '# F05 unrelated local setting\n' > /etc/sddm.conf.d/10-local.conf
sha256sum /etc/pam.d/sddm /etc/sddm.conf.d/10-local.conf >/run/local-pins
snapshot >/run/before
"${pkg[@]}" -U --noconfirm "${qt[@]}"
mkdir -p /etc/pacman.d/hooks
printf '[Trigger]\nOperation = Install\nType = Package\nTarget = sddm-fplogin\n[Action]\nDescription = F05 controlled package refusal\nWhen = PreTransaction\nExec = /usr/bin/false\nAbortOnFail\n' > /etc/pacman.d/hooks/01-f05-refuse.hook
if "${pkg[@]}" -U sddm-fplogin-*.pkg.tar.zst <<< $'y\ny' >/run/refusal 2>&1; then exit 1; fi
grep -F 'F05 controlled package refusal' /run/refusal
[[ $(pacman -Q sddm) == 'sddm 0.21.0-7' ]]
"${pkg[@]}" -R --noconfirm qt5-{translations,base,declarative,quickcontrols2,svg}
snapshot >/run/after
diff -u /run/before /run/after
echo 'PASS: real package refusal after Qt install; package inventory, explicit reasons and sampled baseline restored (no service activation).'
# Second case: verification fails after stock has actually been replaced.
rm /etc/pacman.d/hooks/01-f05-refuse.hook
bash /stock-guard "$stock"
printf '%s  %s\n' 927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a "$stock" | sha256sum -c
gpgv --keyring /etc/pacman.d/gnupg/pubring.gpg "$stock.sig" "$stock"
"${pkg[@]}" -U "${qt[@]}" sddm-fplogin-*.pkg.tar.zst <<< $'y\ny'
[[ $(pacman -Q sddm-fplogin) == 'sddm-fplogin 0.21.0-3.1' ]]
pacman -Qq >/run/installed-names
if grep -Fx sddm /run/installed-names; then exit 1; fi
sha256sum -c /run/local-pins
# Deliberately withhold the required configuration. There must be no activation.
[[ ! -e /etc/sddm.conf.d/90-fplogin.conf ]]
"${pkg[@]}" -U "$stock" <<< $'y\ny'
"${pkg[@]}" -R --noconfirm qt5-{translations,base,declarative,quickcontrols2,svg}
snapshot >/run/restored
diff -u /run/before /run/restored
echo 'PASS: signed stock reinstalled after replacement; sampled baseline restored.'
