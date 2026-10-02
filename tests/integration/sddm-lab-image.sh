#!/bin/bash
# Runs only while building the disposable image, never against the host root.
set -euo pipefail
test -x /usr/local/bin/sddm
test -x /usr/local/libexec/sddm-helper
sha256sum /usr/local/bin/sddm /usr/local/libexec/sddm-helper > /opt/fplogin-lab/runtime.sha256
pacman -Syu --noconfirm --needed linux mkinitcpio systemd systemd-sysvcompat \
    dbus dbus-broker fprintd polkit xorg-server xorg-xauth xorg-xinit \
    hyprland mesa python qemu-desktop e2fsprogs libarchive
# An inherited hand-written PAM file may be retained as a .pacnew by pacman.
# Extract the exact package payload instead. Never install source-tree PAM here.
# Only replace the known shared assets installed by the source build. Keep the
# patched /usr/local daemon/helper intact; their hashes are checked below.
pacman -S --noconfirm --overwrite \
    'usr/lib/qt6/qml/SddmComponents/*,usr/lib/systemd/system/sddm.service,usr/lib/sysusers.d/sddm.conf,usr/lib/tmpfiles.d/sddm.conf' sddm
version=$(pacman -Q sddm)
version=${version#sddm }
packages=(/var/cache/pacman/pkg/sddm-"$version"-*.pkg.tar.zst)
test "${#packages[@]}" = 1
test -f "${packages[0]}"
for name in sddm sddm-greeter sddm-autologin; do
    bsdtar -xOf "${packages[0]}" "etc/pam.d/$name" > "/etc/pam.d/$name"
    chmod 644 "/etc/pam.d/$name"
    rm -f "/etc/pam.d/$name.pacnew"
done
bsdtar -xOf "${packages[0]}" usr/share/dbus-1/system.d/sddm_org.freedesktop.DisplayManager.conf \
    > /usr/share/dbus-1/system.d/sddm_org.freedesktop.DisplayManager.conf
rm -f /usr/local/share/dbus-1/system.d/org.freedesktop.DisplayManager.conf \
    /usr/share/dbus-1/system.d/org.freedesktop.DisplayManager.conf
sha256sum -c /opt/fplogin-lab/runtime.sha256
# Remove inherited test identities; no inherited password or enrollment enters the guest.
if getent passwd livecheck >/dev/null; then userdel -r livecheck; fi
usermod --password '!' root
if ! getent passwd fplab >/dev/null; then useradd -m -s /bin/bash fplab; fi
systemd-sysusers
usermod --password '!' fplab
rm -rf /var/lib/fprint/*
printf 'fplogin-lab\n' > /etc/hostname
printf 'LANG=C.UTF-8\n' > /etc/locale.conf
printf '127.0.0.1 localhost fplogin-lab\n::1 localhost\n' > /etc/hosts
cat > /etc/pam.d/sddm-fingerprint <<'EOF'
auth required pam_fprintd.so timeout=30
account include sddm
session include sddm
EOF
chmod 644 /etc/pam.d/sddm-fingerprint
mkdir -p /etc/sddm.conf.d
rm -f /etc/sddm.conf
cat > /etc/sddm.conf.d/90-fplogin-lab.conf <<'EOF'
[General]
DisplayServer=x11
GreeterEnvironment=QT_QUICK_BACKEND=software,LIBGL_ALWAYS_SOFTWARE=1
[X11]
ServerPath=/usr/bin/Xorg
SessionDir=/usr/share/xsessions,/usr/local/share/xsessions
[Wayland]
SessionDir=/usr/share/wayland-sessions,/usr/local/share/wayland-sessions
[Users]
MinimumUid=1000
EOF
# No production service or default target starts the DM. The lab service also
# checks a per-boot acknowledgment made only on the real recovery tty.
systemctl disable sddm.service
systemctl set-default multi-user.target
cat > /etc/systemd/system/sddm-lab.service <<'EOF'
[Unit]
Description=Patched SDDM in the disposable fplogin guest
After=systemd-logind.service systemd-user-sessions.service dbus.service serial-getty@ttyS0.service
Requires=systemd-logind.service
Conflicts=getty@tty1.service
[Service]
ExecStartPre=/usr/local/sbin/fplogin-lab require-recovery
ExecStart=/usr/local/bin/sddm
Restart=no
StandardOutput=journal
StandardError=journal
Environment=QT_LOGGING_RULES=*.debug=true
Environment=LIBGL_ALWAYS_SOFTWARE=1
EOF
mkdir -p /etc/systemd/system/serial-getty@ttyS0.service.d
cat > /etc/systemd/system/serial-getty@ttyS0.service.d/recovery.conf <<'EOF'
[Service]
ExecStart=
ExecStart=-/usr/bin/agetty --autologin root --noclear --keep-baud 115200,38400,9600 - $TERM
EOF
systemctl enable serial-getty@ttyS0.service
systemctl add-wants multi-user.target systemd-logind.service
mkdir -p /home/fplab/.config/hypr
cat > /home/fplab/.config/hypr/hyprland.conf <<'EOF'
monitor = , preferred, auto, 1
bind = SUPER, M, exit,
EOF
chown -R fplab:fplab /home/fplab
# Avoid the build container's autodetect: guest storage/display/input drivers
# must be present even when the builder has none of this emulated hardware.
cat > /opt/fplogin-lab/mkinitcpio.conf <<'EOF'
MODULES=(virtio_pci virtio_blk virtio_gpu ext4 usbhid hid_generic i8042 atkbd)
BINARIES=()
FILES=()
HOOKS=(base udev modconf block filesystems keyboard)
COMPRESSION="zstd"
EOF
kernel_dirs=()
for base in /usr/lib/modules/*/pkgbase; do
    if [[ $(cat "$base") == linux ]]; then kernel_dirs+=("${base%/pkgbase}"); fi
done
test "${#kernel_dirs[@]}" = 1
kernel_dir=${kernel_dirs[0]}
cp "$kernel_dir/vmlinuz" /opt/fplogin-lab/vmlinuz
mkinitcpio -c /opt/fplogin-lab/mkinitcpio.conf -k "${kernel_dir##*/}" \
    -g /opt/fplogin-lab/initramfs.img
# Package archives and inherited build inputs are not required in a guest disk.
pacman -Scc --noconfirm
