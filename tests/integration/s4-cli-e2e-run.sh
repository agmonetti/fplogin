#!/usr/bin/bash
# Build a fresh disposable Arch x86_64 ext4 guest from the offline F05 baseline,
# install the real built fplogin-git package (creating fplogin-adapter via
# systemd-sysusers), configure /etc/fplogin/trust (production offline trust root)
# and human-named signed .pkg.tar.zst + .sig archives, boot under QEMU/KVM with
# real systemd PID 1 (no network, no USB reader), and run s4-cli-e2e-guest.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."

pkg=${1:-}
if [[ -z "$pkg" ]]; then
    pkg=$(ls -1t target/arch-package.*/fplogin-git-*-x86_64.pkg.tar.zst 2>/dev/null | grep -v -- '-debug-' | head -n1 || true)
fi
if [[ -z "$pkg" || ! -f "$pkg" ]]; then
    echo "ERROR: built fplogin-git package not found; run 'make package' first or pass package path" >&2
    exit 1
fi
pkg=$(realpath "$pkg")

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
work_dir=$(mktemp -d "$PWD/.work/labs/sprint4/cli-e2e-${run_stamp}.XXXXXX")
ev_dir="$PWD/.work/evidence/sprint4/cli-e2e-${run_stamp}"
mkdir -p "$ev_dir"

cleanup() {
    rm -rf -- "$work_dir"
}
trap cleanup EXIT

echo "Staging packaged fplogin-git ($pkg) and human-named signed artifacts..."
cp "$pkg" "$work_dir/fplogin-git.pkg.tar.zst"
mkdir -p "$work_dir/artifacts" "$work_dir/artifacts-nodm"
for file in "$lab_base"/inputs/*.zst; do
    cp "$file" "$file.sig" "$work_dir/artifacts/"
    cp "$file" "$file.sig" "$work_dir/artifacts-nodm/"
done
cp "$PWD"/.work/labs/sprint3/e6-abi/stock/sddm-0.21.0-7-x86_64.pkg.tar.zst \
   "$PWD"/.work/labs/sprint3/e6-abi/stock/sddm-0.21.0-7-x86_64.pkg.tar.zst.sig \
   "$work_dir/artifacts/"
cp "$f03_dir"/greetd-*.pkg.tar.zst "$f03_dir"/greetd-*.pkg.tar.zst.sig "$work_dir/"
printf '[options]\nArchitecture = auto\nLocalFileSigLevel = Required TrustedOnly\n' > "$work_dir/pacman.conf"
printf 'CBFAD8C1A4FDE6D8FE5FA8F59911358499AA1EA6\n' > "$work_dir/candidate.fpr"

# Create disposable lab-only password (never printed, deleted inside guest on exit).
lab_pass="clie2e-$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')"
printf '%s\n' "$lab_pass" > "$work_dir/lab-pass"
chmod 0600 "$work_dir/lab-pass"

echo "Creating fresh disposable Arch ext4 guest image (no network, no USB)..."
docker run --rm --network none -i \
    -v "$lab_base/rootfs.tar:/src/rootfs.tar:ro" \
    -v "$work_dir:/work" \
    -v "$signer_dir/pacman:/src/public:ro" \
    -v "$signer_dir/approved.gpg:/src/candidate.gpg:ro" \
    -v "$PWD/tests/integration/s4-cli-e2e-guest.sh:/src/s4-cli-e2e-guest.sh:ro" \
    sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c \
    /bin/bash -euo pipefail -c '
root=/tmp/guest-root
mkdir -p "$root"
tar -xf /src/rootfs.tar -C "$root"

# Install the real built fplogin-git package into the guest root using pacman.
printf "[options]\nArchitecture = auto\nSigLevel = Never\n" > /tmp/tools-install.conf
pacman --root "$root" --config /tmp/tools-install.conf --noconfirm -U /work/fplogin-git.pkg.tar.zst
# Provision system user fplogin-adapter from packaged sysusers.d file.
systemd-sysusers --root="$root"

# Configure production offline trust root /etc/fplogin/trust (root-owned, safe perms).
install -d -m 0755 "$root/etc/fplogin" "$root/etc/fplogin/trust" "$root/opt/cli-e2e" "$root/opt/artifacts" "$root/opt/artifacts-nodm"
install -m 0644 /work/pacman.conf "$root/etc/fplogin/trust/pacman.conf"
install -m 0644 /src/candidate.gpg "$root/etc/fplogin/trust/candidate.gpg"
install -m 0644 /work/candidate.fpr "$root/etc/fplogin/trust/candidate.fpr"
cp -a /src/public "$root/etc/fplogin/trust/public"
chown -R 0:0 "$root/etc/fplogin"
chmod 0755 "$root/etc/fplogin/trust/public"

cp -a /work/artifacts/. "$root/opt/artifacts/"
cp -a /work/artifacts-nodm/. "$root/opt/artifacts-nodm/"
cp /work/greetd-*.pkg.tar.zst /work/greetd-*.pkg.tar.zst.sig "$root/opt/cli-e2e/"
install -m 0755 /src/s4-cli-e2e-guest.sh "$root/opt/cli-e2e/s4-cli-e2e-guest.sh"

# Disposable password for fplab inside disposable guest only.
pw=$(cat /work/lab-pass)
pw_hash=$(openssl passwd -6 "$pw")
usermod -R "$root" -p "$pw_hash" fplab
install -m 0600 /work/lab-pass "$root/run-cli-e2e-pass"

printf "clie2e00000000000000000000000001\n" > "$root/etc/machine-id"
printf "/dev/vda / ext4 rw,relatime 0 1\n" > "$root/etc/fstab"

mkdir -p "$root/etc/systemd/system/multi-user.target.wants"
cat > "$root/etc/systemd/system/cli-e2e.service" <<EOF
[Unit]
Description=S4 Packaged CLI E2E Verification
After=dbus.service systemd-user-sessions.service
Wants=dbus.service

[Service]
Type=oneshot
ExecStartPre=/usr/bin/mv /run-cli-e2e-pass /run/cli-e2e-pass
ExecStart=/opt/cli-e2e/s4-cli-e2e-guest.sh
StandardOutput=journal+console
StandardError=inherit

[Install]
WantedBy=multi-user.target
EOF
ln -sf /etc/systemd/system/cli-e2e.service "$root/etc/systemd/system/multi-user.target.wants/cli-e2e.service"

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
        -append "root=/dev/vda rw console=ttyS0 systemd.show_status=auto fplogin.clie2e=1" \
        -drive file=/work/guest.ext4,format=raw,if=virtio \
    | tee "$serial_log"

grep -Fq 'PACKAGED CLI E2E GUEST PASS' "$serial_log"
if grep -Fq "$lab_pass" "$serial_log"; then
    echo "ERROR: disposable password leaked to serial log!"
    exit 1
fi
sha256sum "$serial_log"
echo "S4 PACKAGED CLI E2E REAL-SYSTEMD GUEST PASSED"
