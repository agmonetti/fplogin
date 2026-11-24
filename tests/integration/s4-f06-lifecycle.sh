#!/bin/bash
# Verify S4-F06 manifest publication, repeat operations (reinstall/repair),
# adapter-independent transactional uninstall (modified file preservation,
# shared dependency preservation, failed service restore keeping manifest),
# and SIGKILL crash recovery at manifest publication/removal/completion
# inside disposable networkless Arch x86_64 containers. Never modifies the host.
set -euo pipefail
cd "$(dirname "$0")/../.."
lab=$PWD/.work/labs/sprint4/f05-baseline
stage=$(mktemp -d "$lab/f06.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
guest=/var/lib/fplogin/archives

for file in "$lab"/inputs/*.zst "$PWD"/.work/labs/sprint3/e6-abi/stock/*.zst; do
    sum=$(sha256sum "$file" | cut -d' ' -f1)
    name=${file##*/}; printf '%s' "${name%-*-*-*}" > "$stage/$sum.name"
    cp "$file" "$stage/$sum"; cp "$file.sig" "$stage/$sum.sig"
done
CGO_ENABLED=0 go build -o "$lab/platform-arch" ./cmd/fplogin-platform-arch
printf '[options]\nArchitecture = auto\nLocalFileSigLevel = Required TrustedOnly\n' > "$stage/pacman.conf"
CGO_ENABLED=0 go test -tags f05lab -c -o "$lab/installer-test" ./internal/core/install

run_container() {
    docker run --rm --network none -i \
        -v "$stage:/cache:ro" \
        -v "$lab/installer-test:/installer-test:ro" \
        -v "$PWD/contracts/platform/v1/examples/request.valid.json:/request.json:ro" \
        -v "$PWD/platforms/arch/platform.json:/provider-descriptor.json:ro" \
        -v "$stage:$guest:ro" \
        -v "$stage/pacman.conf:/etc/fplogin/f05-lab/pacman.conf:ro" \
        -v "$PWD/.work/labs/sprint4/f05-signer/pacman:/etc/fplogin/f05-lab/public:ro" \
        -v "$lab/platform-arch:/provider:ro" \
        -v "$PWD/.work/labs/sprint4/f05-signer/approved.gpg:/etc/fplogin/f05-lab/candidate.gpg:ro" \
        sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c "$@"
}

common_setup='
set -euo pipefail
export LC_ALL=C
install -d -m 0755 /usr/lib/fplogin /usr/lib/fplogin/platforms /usr/lib/fplogin/platforms/bin /usr/lib/fplogin/platforms/assets /etc/sddm.conf.d
install -m 0644 /provider-descriptor.json /usr/lib/fplogin/platforms/platform.json
install -m 0755 /provider /usr/lib/fplogin/platforms/bin/fplogin-platform-arch
mkdir -p /var/lib/fplogin && chmod 0700 /var/lib/fplogin
printf "# F06 unrelated local setting\n" > /etc/sddm.conf.d/10-local.conf
sha256sum /etc/pam.d/sddm /etc/sddm.conf.d/10-local.conf > /run/local-pins
snapshot() {
    pacman -Q
    pacman -Qqe
    sha256sum /usr/bin/sddm
    find /etc -maxdepth 1 -type f -name sddm.conf -exec sha256sum "{}" +
    find /etc/pam.d /etc/sddm.conf.d -type f -exec sha256sum "{}" + | sort
    systemctl is-enabled sddm.service || [[ $? == 1 ]]
}
'

echo "=== Case 1: Fresh install (over prior 0640 file) -> Reinstall -> Repair -> Adapter-less Uninstall -> Repeat Uninstall ==="
run_container /bin/bash -ec "$common_setup"'
printf "[Theme]\nCurrent=stock\n" > /etc/sddm.conf.d/90-fplogin.conf
chmod 0640 /etc/sddm.conf.d/90-fplogin.conf
orig_sha=$(sha256sum /etc/sddm.conf.d/90-fplogin.conf | cut -d" " -f1)

F06_CASE=fresh-install /installer-test -test.run "^TestF06LabLifecycle$" -test.v
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
[[ $(systemctl is-enabled sddm.service) == "enabled" ]]
[[ $(stat -c %a /var/lib/fplogin/manifest.json) == "600" ]]

# Repeat install (reinstall): zero unintended changes and same inode
snapshot > /run/before-reinstall
ino_before=$(stat -c %i /etc/sddm.conf.d/90-fplogin.conf)
F06_CASE=reinstall /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-reinstall
diff -u /run/before-reinstall /run/after-reinstall
[[ $(stat -c %i /etc/sddm.conf.d/90-fplogin.conf) == "$ino_before" ]]

# Repair after deleting theme drop-in
rm -f /etc/sddm.conf.d/90-fplogin.conf
F06_CASE=repair /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-repair
diff -u /run/before-reinstall /run/after-repair

# Uninstall WITHOUT adapter: restores pre-fresh-install 0640 file, stock sddm, disables sddm.service, keeps qt5-*
F06_CASE=uninstall-default /installer-test -test.run "^TestF06LabLifecycle$" -test.v
[[ $(pacman -Q sddm) == "sddm 0.21.0-7" ]]
! pacman -Qq | grep -Fx sddm-fplogin
[[ $(pacman -Q qt5-base) == "qt5-base 5.15.19+kde+r96-1" ]]
[[ $(sha256sum /etc/sddm.conf.d/90-fplogin.conf | cut -d" " -f1) == "$orig_sha" ]]
[[ $(stat -c %a /etc/sddm.conf.d/90-fplogin.conf) == "640" ]]
sha256sum -c /run/local-pins

# Repeat uninstall makes no unintended changes
snapshot > /run/before-repeat-uninstall
F06_CASE=uninstall-repeat /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-repeat-uninstall
diff -u /run/before-repeat-uninstall /run/after-repeat-uninstall
'

echo "=== Case 2: Modified file preserved by default + Opt-in RemoveSharedDependencies full snapshot restoration ==="
run_container /bin/bash -ec "$common_setup"'
snapshot > /run/clean-baseline
F06_CASE=fresh-install /installer-test -test.run "^TestF06LabLifecycle$" -test.v
printf "# local user override\n" > /etc/sddm.conf.d/90-fplogin.conf
local_sha=$(sha256sum /etc/sddm.conf.d/90-fplogin.conf | cut -d" " -f1)

# Refuse policy leaves everything unchanged
snapshot > /run/before-refuse
F06_CASE=uninstall-modified-refuse /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-refuse
diff -u /run/before-refuse /run/after-refuse

# Default preserve policy keeps modified file while restoring stock sddm and disabling sddm.service
F06_CASE=uninstall-modified-preserve /installer-test -test.run "^TestF06LabLifecycle$" -test.v
[[ $(sha256sum /etc/sddm.conf.d/90-fplogin.conf | cut -d" " -f1) == "$local_sha" ]]
[[ $(pacman -Q sddm) == "sddm 0.21.0-7" ]]
[[ $(pacman -Q qt5-base) == "qt5-base 5.15.19+kde+r96-1" ]]

# Re-run clean install + opt-in RemoveSharedDependencies -> exact match with clean-baseline
rm -f /etc/sddm.conf.d/90-fplogin.conf
# Clean qt5-* left from previous default uninstall so fresh install records them as newly installed
pacman -R --noconfirm qt5-svg qt5-quickcontrols2 qt5-declarative qt5-base qt5-translations >/dev/null
diff -u /run/clean-baseline <(snapshot)
F06_CASE=fresh-install /installer-test -test.run "^TestF06LabLifecycle$" -test.v
F06_CASE=uninstall-remove-shared /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-full-remove
diff -u /run/clean-baseline /run/after-full-remove
'

echo "=== Case 3: Failed service restore during uninstall keeps manifest and rolls back real package/file/service ==="
run_container /bin/bash -ec "$common_setup"'
mkdir -p /etc/systemd/system
cat > /etc/systemd/system/lightdm.service <<EOF
[Unit]
Description=F06 dummy prior DM
[Service]
ExecStart=/usr/bin/true
[Install]
Alias=display-manager.service
EOF
systemctl enable lightdm.service >/dev/null 2>&1
[[ $(systemctl is-enabled lightdm.service) == "enabled" ]]

F06_CASE=install-with-prior-lightdm /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/installed-snap

# Fail re-enabling lightdm.service AFTER sddm.service disabled, 90-fplogin.conf removed, and stock sddm installed
F06_CASE=uninstall-service-fail /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-failed-uninstall
diff -u /run/installed-snap /run/after-failed-uninstall
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
[[ -f /var/lib/fplogin/manifest.json ]]

# Retry without fault restores lightdm.service, stock sddm, removes 90-fplogin.conf & manifest
F06_CASE=uninstall-prior-lightdm /installer-test -test.run "^TestF06LabLifecycle$" -test.v
[[ $(pacman -Q sddm) == "sddm 0.21.0-7" ]]
[[ ! -f /etc/sddm.conf.d/90-fplogin.conf ]]
[[ $(systemctl is-enabled lightdm.service) == "enabled" ]]
sha256sum -c /run/local-pins
'

echo "=== Case 4: SIGKILL after manifest publication (before journal checkpoint), then RecoverPending ==="
run_container /bin/bash -ec "$common_setup"'
mkfifo /run/child-in /run/child-out
F06_CASE=sigkill-after-publish /installer-test -test.run "^TestF06LabLifecycle$" < /run/child-in > /run/child-out 2>&1 &
pid=$!
exec 3> /run/child-in
grep -m1 -Fx "F06_READY" /run/child-out
kill -9 "$pid"
wait "$pid" || true
exec 3>&-
[[ -f /var/lib/fplogin/manifest.json ]]
F06_CASE=recover-pending /installer-test -test.run "^TestF06LabLifecycle$" -test.v
[[ -f /var/lib/fplogin/manifest.json ]]
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
[[ $(systemctl is-enabled sddm.service) == "enabled" ]]
sha256sum -c /run/local-pins
'

echo "=== Case 5: SIGKILL before manifest removal (after uninstall ops), then RecoverPending rolls back ==="
run_container /bin/bash -ec "$common_setup"'
F06_CASE=fresh-install /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/installed-snap
mkfifo /run/child-in /run/child-out
F06_CASE=sigkill-before-remove /installer-test -test.run "^TestF06LabLifecycle$" < /run/child-in > /run/child-out 2>&1 &
pid=$!
exec 3> /run/child-in
grep -m1 -Fx "F06_READY" /run/child-out
kill -9 "$pid"
wait "$pid" || true
exec 3>&-
[[ -f /var/lib/fplogin/manifest.json ]]
[[ $(pacman -Q sddm) == "sddm 0.21.0-7" ]]
F06_CASE=recover-pending /installer-test -test.run "^TestF06LabLifecycle$" -test.v
snapshot > /run/after-recover
diff -u /run/installed-snap /run/after-recover
[[ -f /var/lib/fplogin/manifest.json ]]
'

echo "=== Case 6: SIGKILL after manifest removal (before journal checkpoint), then RecoverPending completes ==="
run_container /bin/bash -ec "$common_setup"'
F06_CASE=fresh-install /installer-test -test.run "^TestF06LabLifecycle$" -test.v
mkfifo /run/child-in /run/child-out
F06_CASE=sigkill-after-remove /installer-test -test.run "^TestF06LabLifecycle$" < /run/child-in > /run/child-out 2>&1 &
pid=$!
exec 3> /run/child-in
grep -m1 -Fx "F06_READY" /run/child-out
kill -9 "$pid"
wait "$pid" || true
exec 3>&-
[[ ! -f /var/lib/fplogin/manifest.json ]]
F06_CASE=recover-pending /installer-test -test.run "^TestF06LabLifecycle$" -test.v
[[ ! -f /var/lib/fplogin/manifest.json ]]
[[ $(pacman -Q sddm) == "sddm 0.21.0-7" ]]
[[ $(systemctl is-enabled sddm.service) == "disabled" ]]
sha256sum -c /run/local-pins
'

echo "ALL F06 CONTAINER CASES PASSED"
