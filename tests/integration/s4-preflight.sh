#!/usr/bin/env bash
# Offline Arch smoke: real pacman queries, controlled systemctl observations.
set -euo pipefail
cd "$(dirname "$0")/../.."
root=$PWD
stage=$(mktemp -d "$root/.work/build/sprint4-f03.XXXXXXXX")
chmod 755 "$stage"
mkdir -p "$stage"/{platforms,adapters}/{bin,assets}
CGO_ENABLED=0 go build -o "$stage/fplogin" ./cmd/fplogin
CGO_ENABLED=0 go build -o "$stage/platforms/bin/fplogin-platform-arch" ./cmd/fplogin-platform-arch
CGO_ENABLED=0 go build -o "$stage/adapters/bin/fplogin-adapter-sddm" ./cmd/fplogin-adapter-sddm
cp platforms/arch/platform.json "$stage/platforms/"
cp adapters/sddm/adapter.json "$stage/adapters/"

image=${1:-archlinux:base-devel}
run() {
    docker run --rm --pull never --network none --cap-drop ALL --cap-add SETUID --cap-add SETGID \
      --security-opt no-new-privileges --mount "type=bind,src=$stage,dst=/stage,readonly" \
      "$@"
}
run "$image" /bin/bash -ec '
    cp -r /stage /usr/lib/fplogin
    rc=0
    out=$(setpriv --reuid 65534 --regid 65534 --clear-groups /stage/fplogin install --dry-run 2>&1) || rc=$?
    printf "%s\n" "$out"
    test "$rc" -eq 1
    grep -Fq "list-units" <<< "$out"
    grep -Fq "No changes were made" <<< "$out"
'

run -i "$image" /bin/bash -es <<'GUEST'
cp -r /stage /usr/lib/fplogin
cat >/usr/bin/systemctl <<'FIXTURE'
#!/bin/bash
set -eu
case="$(</run/preflight-case)"
args=" $* "
if [[ "$args" == *' list-unit-files '* ]]; then
    case "$case" in
        stock) printf 'sddm.service enabled disabled\ndisplay-manager.service alias -\n';;
        alternate|active) printf 'gdm.service enabled disabled\ndisplay-manager.service alias -\n';;
        unknown) printf 'display-manager.service alias -\n';;
    esac
elif [[ "$args" == *' list-units '* ]]; then
    printf 'dbus.service loaded active running D-Bus\n'
elif [[ "$args" == *' graphical.target ' ]]; then
    printf 'Requires=multi-user.target\nWants=display-manager.service\n'
elif [[ "$args" == *' show '* ]]; then
    case "$case" in
        stock) unit=sddm; state=active;;
        alternate) unit=gdm; state=inactive;;
        active) unit=gdm; state=active;;
        unknown) unit=custom; state=inactive;;
        *) exit 9;;
    esac
    printf 'Id=%s.service\nLoadState=loaded\nActiveState=%s\nUnitFileState=enabled\n' "$unit" "$state"
else
    exit 9
fi
FIXTURE
chmod 755 /usr/bin/systemctl
mkdir -p /etc/sddm.conf.d /var/lib/fplogin
printf '[Theme]\nCurrent=stock\n' >/etc/sddm.conf.d/10-stock.conf
printf 'manifest sentinel\n' >/var/lib/fplogin/manifest.json
printf 'journal sentinel\n' >/var/lib/fplogin/journal.json
snapshot() {
    /usr/bin/pacman --config /dev/null -Q
    find /etc/sddm.conf.d /var/lib/fplogin /etc/systemd/system -printf '%y %m %P %l\n' | sort
    find /etc/sddm.conf.d /var/lib/fplogin /etc/systemd/system -type f -print0 | sort -z | xargs -0 -r sha256sum
}
user() { setpriv --reuid=65534 --regid=65534 --clear-groups /stage/fplogin "$@"; }
package_fixture() {
    mkdir "/var/lib/pacman/local/$1-$2"
    printf '%%NAME%%\n%s\n\n%%VERSION%%\n%s\n\n%%PROVIDES%%\ndisplay-manager\n' "$1" "$2" >"/var/lib/pacman/local/$1-$2/desc"
}
for case in fresh stock alternate active unknown; do
    echo "$case" >/run/preflight-case
    case "$case" in
        stock) package_fixture sddm 0.21.0-7;;
        alternate) rm -r /var/lib/pacman/local/sddm-0.21.0-7; package_fixture gdm 49.0-1;;
        unknown) rm -r /var/lib/pacman/local/gdm-49.0-1;;
    esac
    snapshot >/run/before
    if [[ "$case" == unknown ]]; then
        rc=0
        out=$(user install --dry-run 2>&1) || rc=$?
        test "$rc" -eq 1
        grep -Fq 'unknown display-manager unit' <<< "$out"
    else
        select=$(user install --dry-run)
        grep -Fq 'Selectable preview: org.fplogin.adapter.sddm/sddm-local' <<< "$select"
        if grep -Fq 'Preview SHA-256:' <<< "$select"; then exit 1; fi
        out=$(user install --dry-run --target org.fplogin.adapter.sddm/sddm-local)
        grep -Fq 'Preview SHA-256:' <<< "$out"
        grep -Fq 'Conditional preview only' <<< "$out"
        grep -Fq 'hardware.fingerprint_reader"' <<< "$out"
        grep -Fq '"/etc/sddm.conf.d/90-fplogin.conf"' <<< "$out"
        case "$case" in
            stock) grep -Fq 'replaces stock sddm 0.21.0-7' <<< "$out";;
            alternate)
                grep -Fq 'installed=yes enabled=yes active=no' <<< "$out"
                grep -Fq 'disable_service "gdm.service"' <<< "$out"
                grep -Fq 'would require separate approval' <<< "$out"
                if grep -Fq 'stop_service' <<< "$out"; then exit 1; fi;;
            active) grep -Fq 'stop_service "gdm.service"' <<< "$out";;
        esac
        identity=$(grep -F 'Preview SHA-256:' <<< "$out")
        test "$identity" = "$(user install --dry-run --target org.fplogin.adapter.sddm/sddm-local | grep -F 'Preview SHA-256:')"
        test "$identity" != "${prior_identity:-}"
        prior_identity=$identity
    fi
    printf '\nCASE %s\n%s\n' "$case" "$out"
    snapshot >/run/after
    cmp /run/before /run/after
    echo 'before/after identical'
done
if /stage/fplogin install --dry-run; then exit 1; fi
GUEST
