#!/usr/bin/bash
# Build a fresh disposable Arch x86_64 ext4 guest from the offline F05 baseline,
# boot it under QEMU/KVM with real systemd PID 1 (no network, no USB reader),
# run tests/integration/s4-f07-guest.sh, and preserve the secret-free serial log.
# Never modifies the host or any existing Sprint 3/4 disk.
set -euo pipefail
cd "$(dirname "$0")/../.."

avail_kb=$(df -Pk . | awk 'NR==2 {print $4}')
avail_gib=$((avail_kb / 1024 / 1024))
echo "Free space on repository filesystem: ${avail_gib} GiB"
if (( avail_gib < 15 )); then
    echo "ERROR: fewer than 15 GiB available; refusing to create disposable guest disk"
    exit 1
fi

lab_base=$PWD/.work/labs/sprint4/f05-baseline
f03_dir=$PWD/.work/labs/sprint4/f03
signer_dir=$PWD/.work/labs/sprint4/f05-signer
run_stamp=$(date -u +%Y%m%dT%H%M%SZ)
work_dir=$(mktemp -d "$PWD/.work/labs/sprint4/f07-${run_stamp}.XXXXXX")
ev_dir="$PWD/.work/evidence/sprint4/f07-${run_stamp}"
mkdir -p "$ev_dir"

cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

echo "Building Go binaries for disposable guest..."
CGO_ENABLED=0 go build -o "$work_dir/platform-arch" ./cmd/fplogin-platform-arch
CGO_ENABLED=0 go test -tags f05lab -c -o "$work_dir/installer-test" ./internal/core/install

# Stage content-addressed archives + signatures for the guest.
mkdir -p "$work_dir/cache"
for file in "$lab_base"/inputs/*.zst "$PWD"/.work/labs/sprint3/e6-abi/stock/*.zst; do
    sum=$(sha256sum "$file" | cut -d' ' -f1)
    name=${file##*/}
    printf '%s' "${name%-*-*-*}" > "$work_dir/cache/$sum.name"
    cp "$file" "$work_dir/cache/$sum"
    cp "$file.sig" "$work_dir/cache/$sum.sig"
done
printf '[options]\nArchitecture = auto\nLocalFileSigLevel = Required TrustedOnly\n' > "$work_dir/pacman.conf"

# Create disposable lab-only password (never printed, deleted inside guest on exit).
lab_pass="f07-lab-$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
printf '%s\n' "$lab_pass" > "$work_dir/lab-pass"
chmod 0600 "$work_dir/lab-pass"

# Copy extra packages needed inside the guest for scenarios 2, 3, and 4.
cp "$PWD"/.work/labs/sprint3/e6-abi/stock/sddm-0.21.0-7-x86_64.pkg.tar.zst "$work_dir/stock-sddm.pkg.tar.zst"
cp "$PWD"/.work/labs/sprint3/e6-abi/stock/sddm-0.21.0-7-x86_64.pkg.tar.zst.sig "$work_dir/stock-sddm.pkg.tar.zst.sig"
cp "$lab_base"/inputs/qt5-translations-*.pkg.tar.zst "$work_dir/qt5-translations.pkg.tar.zst"
cp "$lab_base"/inputs/qt5-base-*.pkg.tar.zst "$work_dir/qt5-base.pkg.tar.zst"
cp "$f03_dir"/greetd-*.pkg.tar.zst "$f03_dir"/greetd-*.pkg.tar.zst.sig "$work_dir/"

echo "Creating fresh disposable Arch ext4 guest image (no network, no USB)..."
docker run --rm --network none -i \
    -v "$lab_base/rootfs.tar:/src/rootfs.tar:ro" \
    -v "$work_dir:/work" \
    -v "$PWD/contracts/platform/v1/examples/request.valid.json:/src/request.json:ro" \
    -v "$PWD/platforms/arch/platform.json:/src/platform.json:ro" \
    -v "$signer_dir/pacman:/src/public:ro" \
    -v "$signer_dir/approved.gpg:/src/candidate.gpg:ro" \
    -v "$PWD/tests/integration/s4-f07-guest.sh:/src/s4-f07-guest.sh:ro" \
    sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c \
    /bin/bash -euo pipefail -c '
root=/tmp/guest-root
mkdir -p "$root"
tar -xf /src/rootfs.tar -C "$root"

# Install fplogin provider, descriptor, lab trust, and test harness inside guest root.
install -d -m 0755 "$root/usr/lib/fplogin/platforms/bin" "$root/usr/lib/fplogin/platforms/assets" "$root/etc/fplogin/f05-lab" "$root/opt/f07" "$root/cache" "$root/var/lib/fplogin"
chmod 0700 "$root/var/lib/fplogin"
install -m 0644 /src/platform.json "$root/usr/lib/fplogin/platforms/platform.json"
install -m 0755 /work/platform-arch "$root/usr/lib/fplogin/platforms/bin/fplogin-platform-arch"
install -m 0644 /src/request.json "$root/request.json"
install -m 0644 /work/pacman.conf "$root/etc/fplogin/f05-lab/pacman.conf"
install -m 0644 /src/candidate.gpg "$root/etc/fplogin/f05-lab/candidate.gpg"
cp -a /src/public "$root/etc/fplogin/f05-lab/public"
cp -a /work/cache/. "$root/cache/"

install -m 0755 /work/installer-test "$root/opt/f07/installer-test"
install -m 0755 /src/s4-f07-guest.sh "$root/opt/f07/s4-f07-guest.sh"
install -m 0644 /work/stock-sddm.pkg.tar.zst "$root/opt/f07/stock-sddm.pkg.tar.zst"
install -m 0644 /work/stock-sddm.pkg.tar.zst.sig "$root/opt/f07/stock-sddm.pkg.tar.zst.sig"
install -m 0644 /work/qt5-translations.pkg.tar.zst "$root/opt/f07/qt5-translations.pkg.tar.zst"
install -m 0644 /work/qt5-base.pkg.tar.zst "$root/opt/f07/qt5-base.pkg.tar.zst"
cp /work/greetd-*.pkg.tar.zst /work/greetd-*.pkg.tar.zst.sig "$root/opt/f07/"

# Set disposable lab-only password on fplab inside the disposable guest only.
pw=$(cat /work/lab-pass)
pw_hash=$(openssl passwd -6 "$pw")
usermod -R "$root" -p "$pw_hash" fplab
install -m 0600 /work/lab-pass "$root/run-f07-pass"

# Machine ID and fstab so systemd boots cleanly without firstboot prompts.
printf "f0700000000000000000000000000001\n" > "$root/etc/machine-id"
printf "/dev/vda / ext4 rw,relatime 0 1\n" > "$root/etc/fstab"

# Systemd oneshot unit to run the F07 lifecycle suite on boot and power off cleanly.
mkdir -p "$root/etc/systemd/system/multi-user.target.wants"
cat > "$root/etc/systemd/system/f07.service" <<EOF
[Unit]
Description=S4-F07 Arch Lifecycle Verification
After=dbus.service systemd-user-sessions.service
Wants=dbus.service

[Service]
Type=oneshot
ExecStartPre=/usr/bin/mv /run-f07-pass /run/f07-lab-pass
ExecStart=/opt/f07/s4-f07-guest.sh
StandardOutput=journal+console
StandardError=inherit

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/f07.service "$root/etc/systemd/system/multi-user.target.wants/f07.service"

truncate -s 5G /work/guest.ext4
mke2fs -q -t ext4 -d "$root" /work/guest.ext4
'

echo "Booting disposable Arch x86_64 KVM guest (systemd PID 1, no network, no USB)..."
serial_log="$ev_dir/serial.log"
docker run --rm --network none --device /dev/kvm \
    -v "$work_dir:/work" \
    -v "$f03_dir/vmlinuz:/boot/vmlinuz:ro" \
    -v "$f03_dir/initramfs.img:/boot/initramfs.img:ro" \
    sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c \
    /usr/sbin/qemu-system-x86_64 \
        -enable-kvm -cpu host -m 2048 -smp 2 \
        -nodefaults -display none -vga std -no-reboot \
        -serial stdio \
        -kernel /boot/vmlinuz \
        -initrd /boot/initramfs.img \
        -append "root=/dev/vda rw console=ttyS0 systemd.show_status=auto fplogin.f07=1" \
        -drive file=/work/guest.ext4,format=raw,if=virtio \
    | tee "$serial_log"

grep -Fq 'F07 GUEST LIFECYCLE PASS' "$serial_log"
if grep -Fq "$lab_pass" "$serial_log"; then
    echo "ERROR: disposable password leaked to serial log!"
    exit 1
fi
sha256sum "$serial_log"
echo "S4-F07 REAL-SYSTEMD GUEST LIFECYCLE PASSED"
