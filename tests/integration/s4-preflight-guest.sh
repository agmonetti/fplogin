#!/usr/bin/bash
set -Eeuo pipefail
export LC_ALL=C
grep -qw 'fplogin.f03=1' /proc/cmdline
systemd-detect-virt --vm
[[ $(cat /proc/1/comm) == systemd ]]
trap 'echo "MATRIX FAIL line $LINENO"; systemctl --no-block poweroff' ERR
uname -r
systemctl --version | head -1
pacman -Q fplogin-git sddm
systemctl start dbus.service
user() { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
user id
snap() {
    pacman -Q
    systemctl list-unit-files --type=service --no-pager --no-legend
    systemctl list-units --all --no-pager --no-legend --plain '*sddm*' '*greetd*' 'display-manager.service' 'custom-dm.service'
    for p in /etc /var/lib/fplogin /usr/lib/fplogin; do
        if [[ -e $p ]]; then
            find "$p" -printf '%y %m %U %G %p %l\n' | sort
            find "$p" -type f -print0 | sort -z | xargs -0r sha256sum
        else
            echo "absent: $p"
        fi
    done
}
match() { grep -F -- "$1" <<< "$out"; }
not_match() { if grep -Fq -- "$1" <<< "$out"; then return 1; fi; }
preview() {
    local case=$1 rc=0 inventory first
    echo "CASE $case"
    snap > /run/f03-before
    local target=org.fplogin.adapter.sddm/sddm-local
    inventory=$(user fplogin install --dry-run 2>&1) || rc=$?
    printf '%s\n' "$inventory"
    if [[ $case == unknown ]]; then
        [[ $rc == 1 ]]
        out=$inventory
        match 'unclassified graphical.target service "custom-dm.service"'
        match 'No changes were made.'
        not_match 'Preview SHA-256:'
        rc=0
        out=$(user fplogin install --dry-run --target "$target" 2>&1) || rc=$?
        [[ $rc == 1 ]]
        match 'unclassified graphical.target service "custom-dm.service"'
        not_match 'Preview SHA-256:'
    else
        [[ $rc == 0 ]]
        out=$inventory
        match "Selectable preview: $target"
        not_match 'Preview SHA-256:'
        out=$(user fplogin install --dry-run --target "$target" 2>&1) || { echo "$out"; return 1; }
        printf '%s\n' "$out"
        first=$(grep -F 'Preview SHA-256:' <<< "$out")
        test "$first" = "$(user fplogin install --dry-run --target "$target" | grep -F 'Preview SHA-256:')"
        match 'Conditional preview only'
        match 'hardware.fingerprint_reader": unknown'
        match '"/etc/sddm.conf.d/90-fplogin.conf"'
        case $case in
            stock) match 'replaces stock sddm 0.21.0-7'; not_match 'would require separate approval';;
            fresh) not_match 'replaces stock sddm'; not_match 'would require separate approval';;
            enabled-inactive) match 'installed=yes enabled=yes active=no'; match 'disable_service "greetd.service"'; match 'would require separate approval'; not_match 'stop_service';;
            enabled-active) match 'installed=yes enabled=yes active=yes'; match 'stop_service "greetd.service"'; match 'disable_service "greetd.service"'; match 'would require separate approval';;
            active-disabled) match 'installed=yes enabled=no active=yes'; match 'stop_service "greetd.service"'; not_match 'disable_service "greetd.service"';;
        esac
    fi
    snap > /run/f03-after
    diff -u /run/f03-before /run/f03-after
    sha256sum /run/f03-before /run/f03-after
    echo "PASS $case"
}
mkdir -p /etc/sddm.conf.d /var/lib/fplogin/transactions
printf '[Theme]\nCurrent=stock\n' >/etc/sddm.conf.d/10-stock.conf
printf 'manifest sentinel\n' >/var/lib/fplogin/manifest.json
printf 'journal sentinel\n' >/var/lib/fplogin/transactions/sentinel.json
systemctl enable sddm.service
systemctl show -p LoadState,ActiveState,UnitFileState sddm.service display-manager.service
preview stock
systemctl disable --now sddm.service
pacman -Rdd --noconfirm sddm
systemctl daemon-reload
preview fresh
echo 'CASE ambiguous'
components=/usr/lib/fplogin/adapters
install -m644 /opt/f03/fixture.json "$components/fixture.json"
install -m755 /opt/f03/fplogin-adapter-fixture "$components/bin/fplogin-adapter-fixture"
snap > /run/f03-before
out=$(user fplogin install --dry-run)
printf '%s\n' "$out"
[[ $(grep -Fc 'Selectable preview:' <<< "$out") == 2 ]]
match 'Selectable preview: org.fplogin.adapter.sddm/sddm-local'
match 'Selectable preview: org.fplogin.adapter.fixture/sddm-local'
not_match 'Preview SHA-256:'
out=$(user fplogin install --dry-run --target org.fplogin.adapter.fixture/sddm-local)
match 'Preview SHA-256:'
snap > /run/f03-after
diff -u /run/f03-before /run/f03-after
sha256sum /run/f03-before /run/f03-after
echo 'PASS ambiguous'
rm "$components/fixture.json" "$components/bin/fplogin-adapter-fixture"
pacman -U --noconfirm /opt/f03/greetd*.pkg.tar.zst
systemctl enable greetd.service
systemctl show -p LoadState,ActiveState,UnitFileState greetd.service display-manager.service
preview enabled-inactive
systemctl start greetd.service
sleep 2
systemctl show -p LoadState,ActiveState,UnitFileState greetd.service display-manager.service
systemctl is-active --quiet greetd.service
preview enabled-active
systemctl disable greetd.service
systemctl show -p LoadState,ActiveState,UnitFileState greetd.service
preview active-disabled
systemctl stop greetd.service
printf '[Service]\nExecStart=/usr/bin/true\n' >/etc/systemd/system/custom-dm.service
ln -s custom-dm.service /etc/systemd/system/display-manager.service
systemctl daemon-reload
preview unknown
for cmd in install uninstall; do
    rc=0
    user fplogin "$cmd" || rc=$?
    [[ $rc == 1 ]]
done
echo 'MATRIX PASS'
systemctl --no-block poweroff
