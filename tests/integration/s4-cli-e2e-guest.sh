#!/usr/bin/bash
# End-to-end verification of the REAL packaged /usr/bin/fplogin CLI
# (install, status, uninstall, recover, components, --dry-run)
# inside a disposable, networkless, reader-free Arch x86_64 QEMU/KVM guest
# running systemd as PID 1, using /etc/fplogin/trust (offline system trust root)
# and human-named signed .pkg.tar.zst + .sig files.
set -Eeuo pipefail
export LC_ALL=C

grep -qw 'fplogin.clie2e=1' /proc/cmdline
systemd-detect-virt --vm
[[ $(cat /proc/1/comm) == systemd ]]
trap 'echo "CLI E2E GUEST FAIL line $LINENO"; rm -f /run/cli-e2e-pass; systemctl --no-block poweroff' ERR

echo "=== S4 Packaged CLI E2E Guest Environment ==="
uname -r
systemctl --version | head -1
ip -o link show
pacman -Q fplogin-git sddm systemd linux
id fplogin-adapter

# Ensure dbus and text-console recovery services are active.
systemctl start dbus.service
systemctl enable --now getty@tty2.service >/dev/null 2>&1 || true
systemctl start serial-getty@ttyS0.service >/dev/null 2>&1 || true

# Verify no network interface besides lo.
if ip -o link show | awk -F': ' '{print $2}' | grep -vq '^lo$'; then
    echo "ERROR: unexpected non-loopback network interface"
    exit 1
fi

# Pin unrelated local SDDM config and PAM login config.
printf '# CLI E2E unrelated local SDDM setting\n' > /etc/sddm.conf.d/10-local.conf
sha256sum /etc/sddm.conf.d/10-local.conf /etc/pam.d/login > /run/cli-local-pins
sha256sum /etc/pam.d/sddm /etc/pam.d/sddm-autologin /etc/pam.d/sddm-greeter \
    /usr/share/sddm/scripts/Xsetup /usr/share/sddm/scripts/Xstop > /run/cli-stock-pins

verify_console_login() {
    local label=$1
    systemctl is-active --quiet getty@tty2.service
    python3 - <<'PY'
import os, pty, select, time

pw = open("/run/cli-e2e-pass", "r").read().strip()

def attempt():
    pid, fd = pty.fork()
    if pid == 0:
        os.execv("/bin/login", ["/bin/login"])
        os._exit(127)
    buf = b""
    def read_until(markers, timeout=15.0):
        nonlocal buf
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for m in markers:
                if m in buf:
                    return m
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
        raise RuntimeError(f"timeout/eof waiting for {markers!r}")
    try:
        read_until([b"login:"])
        buf = b""
        os.write(fd, b"fplab\n")
        read_until([b"Password:"])
        buf = b""
        os.write(fd, (pw + "\n").encode())
        read_until([b"$ ", b"# "])
        buf = b""
        os.write(fd, b"id -un; id -u; printf '%s_%s\\n' LOGIN OK; exit\n")
        read_until([b"LOGIN_OK"])
        if b"fplab" not in buf or b"1000" not in buf:
            raise RuntimeError("unexpected id output from /bin/login")
    finally:
        os.close(fd)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass

for i in range(3):
    try:
        attempt()
        break
    except RuntimeError:
        if i == 2:
            raise
        time.sleep(1.0)
PY
    sha256sum -c --quiet /run/cli-local-pins
    echo "CONSOLE_PASSWORD_LOGIN_OK ($label)"
}

snapshot_state() {
    echo "--- packages ---"
    pacman -Q
    echo "--- services ---"
    for u in sddm.service greetd.service display-manager.service; do
        printf '%s enabled=%s active=%s\n' "$u" \
            "$(systemctl is-enabled "$u" 2>/dev/null || true)" \
            "$(systemctl is-active "$u" 2>/dev/null || true)"
    done
    echo "--- config ---"
    find /etc/pam.d /etc/sddm.conf.d -type f -exec sha256sum "{}" + 2>/dev/null | sort
    echo "--- manifest ---"
    if [[ -e /var/lib/fplogin/manifest.json ]]; then
        stat -c 'present %a %u:%g' /var/lib/fplogin/manifest.json
    else
        echo "absent"
    fi
}

extract_digest() {
    awk '/^  Plan SHA-256:/ {print $3; exit}'
}

run_fplab() {
    setpriv --reuid=1000 --regid=1000 --clear-groups "$@"
}

echo "=================================================================="
echo "CASE 1: Unprivileged CLI safeguards, components, and --dry-run"
echo "=================================================================="
snapshot_state > /run/snap-c1-before
run_fplab /usr/bin/fplogin components | grep -Fq "provider org.fplogin.platform.arch:"
run_fplab /usr/bin/fplogin components | grep -Fq "adapter org.fplogin.adapter.sddm:"
! run_fplab /usr/bin/fplogin install --artifacts-dir /opt/artifacts
! run_fplab /usr/bin/fplogin uninstall --yes
! run_fplab /usr/bin/fplogin recover
run_fplab /usr/bin/fplogin install --dry-run | grep -Fq "org.fplogin.adapter.sddm/sddm-local"
run_fplab /usr/bin/fplogin install --dry-run --target org.fplogin.adapter.sddm/sddm-local | grep -Fq "sddm-fplogin"
snapshot_state > /run/snap-c1-after
diff -u /run/snap-c1-before /run/snap-c1-after
echo "CASE 1 PASS"

echo "=================================================================="
echo "CASE 2: Stock SDDM replacement -> status -> reinstall -> repair -> uninstall"
echo "=================================================================="
systemctl enable sddm.service
snapshot_state > /run/snap-c2-before

# 2a. Refusal without approval must print Plan SHA-256 and leave zero diff.
rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts 2>&1) || rc=$?
printf '%s\n' "$out"
test "$rc" -eq 1
digest=$(printf '%s\n' "$out" | extract_digest)
test "${#digest}" -eq 64
snapshot_state > /run/snap-c2-refused
diff -u /run/snap-c2-before /run/snap-c2-refused

# 2b. Wrong digest must refuse with zero diff.
! /usr/bin/fplogin install --artifacts-dir /opt/artifacts --approve-plan "$(printf '0%.0s' {1..64})"
snapshot_state > /run/snap-c2-wrong
diff -u /run/snap-c2-before /run/snap-c2-wrong

# 2c. Approved install succeeds, preserves local/stock files, and passes status + console login.
/usr/bin/fplogin install --artifacts-dir /opt/artifacts --approve-plan "$digest"
pacman -Q sddm-fplogin | grep -Fq 'sddm-fplogin 0.21.0-3.1'
! pacman -Q | grep -Eq '^sddm '
sha256sum -c --quiet /run/cli-stock-pins
sha256sum -c --quiet /run/cli-local-pins
/usr/bin/fplogin status | grep -Fq 'Intact (all file checksums match)'
systemctl is-enabled sddm.service | grep -Fxq enabled
verify_console_login "case2-stock-installed"

# 2d. Reinstall (identical) succeeds and keeps recovery_baseline intact.
rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts 2>&1) || rc=$?
test "$rc" -eq 1
reinstall_digest=$(printf '%s\n' "$out" | extract_digest)
test "${#reinstall_digest}" -eq 64
/usr/bin/fplogin install --artifacts-dir /opt/artifacts --approve-plan "$reinstall_digest" | grep -Fq 'Mode:           reinstall'

# 2e. Delete theme drop-in -> repair restores it cleanly.
rm -f /etc/sddm.conf.d/90-fplogin.conf
/usr/bin/fplogin status | grep -Fq 'Mismatches detected'
rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts 2>&1) || rc=$?
test "$rc" -eq 1
repair_digest=$(printf '%s\n' "$out" | extract_digest)
/usr/bin/fplogin install --artifacts-dir /opt/artifacts --approve-plan "$repair_digest" | grep -Fq 'Mode:           repair'
/usr/bin/fplogin status | grep -Fq 'Intact (all file checksums match)'

# 2f. Transactional uninstall restores exact stock SDDM baseline.
/usr/bin/fplogin uninstall --yes --remove-shared-deps
snapshot_state > /run/snap-c2-after
diff -u /run/snap-c2-before /run/snap-c2-after
sha256sum -c --quiet /run/cli-stock-pins
verify_console_login "case2-stock-uninstalled"
echo "CASE 2 PASS"

echo "=================================================================="
echo "CASE 3: Fresh no-DM install with --activate -> uninstall"
echo "=================================================================="
systemctl disable sddm.service
pacman -Rdd --noconfirm sddm
systemctl daemon-reload
snapshot_state > /run/snap-c3-before

rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --activate 2>&1) || rc=$?
printf '%s\n' "$out"
test "$rc" -eq 1
nodm_digest=$(printf '%s\n' "$out" | extract_digest)
test "${#nodm_digest}" -eq 64

/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --activate --approve-plan "$nodm_digest"
systemctl is-enabled sddm.service | grep -Fxq enabled
systemctl is-active sddm.service | grep -Fxq active
/usr/bin/fplogin status | grep -Fq 'Intact (all file checksums match)'
verify_console_login "case3-nodm-active"

/usr/bin/fplogin uninstall --yes --remove-shared-deps
snapshot_state > /run/snap-c3-after
diff -u /run/snap-c3-before /run/snap-c3-after
verify_console_login "case3-nodm-uninstalled"
echo "CASE 3 PASS"

echo "=================================================================="
echo "CASE 4: Conflicting enabled/active DM (greetd) -> refuse -> approve -> uninstall"
echo "=================================================================="
pacman -U --noconfirm /opt/cli-e2e/greetd-*.pkg.tar.zst
systemctl daemon-reload
systemctl enable --now greetd.service
systemctl is-enabled greetd.service | grep -Fxq enabled
systemctl is-active greetd.service | grep -Fxq active
snapshot_state > /run/snap-c4-before

rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --activate 2>&1) || rc=$?
printf '%s\n' "$out"
test "$rc" -eq 1
grep -Fq 'greetd.service' <<<"$out"
greetd_digest=$(printf '%s\n' "$out" | extract_digest)
test "${#greetd_digest}" -eq 64

# Must refuse without --approve-replace-dm!
rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --activate --approve-plan "$greetd_digest" 2>&1) || rc=$?
printf '%s\n' "$out"
test "$rc" -eq 1
grep -Fq -- '--approve-replace-dm' <<<"$out"
snapshot_state > /run/snap-c4-refused
diff -u /run/snap-c4-before /run/snap-c4-refused

# Succeeds with BOTH --approve-plan AND --approve-replace-dm!
/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --activate --approve-plan "$greetd_digest" --approve-replace-dm
systemctl is-enabled sddm.service | grep -Fxq enabled
systemctl is-active sddm.service | grep -Fxq active
! systemctl is-enabled --quiet greetd.service
! systemctl is-active --quiet greetd.service
/usr/bin/fplogin status | grep -Fq 'Intact (all file checksums match)'
verify_console_login "case4-greetd-replaced"

# Uninstall restores greetd.service enabled + active!
/usr/bin/fplogin uninstall --yes --remove-shared-deps
snapshot_state > /run/snap-c4-after
diff -u /run/snap-c4-before /run/snap-c4-after
verify_console_login "case4-greetd-restored"

# Clean up greetd back to no-DM for Case 5.
systemctl disable --now greetd.service
pacman -R --noconfirm greetd greetd-agreety
systemctl daemon-reload
echo "CASE 4 PASS"

echo "=================================================================="
echo "CASE 5: Clean recover + SIGKILL interrupted live CLI install + recover"
echo "=================================================================="
/usr/bin/fplogin recover | grep -Fq 'Recovery completed cleanly.'
snapshot_state > /run/snap-c5-before

rc=0
out=$(/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm 2>&1) || rc=$?
test "$rc" -eq 1
sig_digest=$(printf '%s\n' "$out" | extract_digest)

# Start live CLI install in background and SIGKILL once a journal enters applying state.
/usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --approve-plan "$sig_digest" >/run/sigkill-cli.log 2>&1 &
cli_pid=$!
killed=0
for _ in $(seq 1 200); do
    if ! kill -0 "$cli_pid" 2>/dev/null; then
        break
    fi
    if grep -l '"state": "applying"' /var/lib/fplogin/transactions/*.json >/dev/null 2>&1; then
        kill -9 "$cli_pid" 2>/dev/null || true
        killed=1
        break
    fi
    sleep 0.05
done
wait "$cli_pid" 2>/dev/null || true
echo "SIGKILL sent during applying=$killed"
test "$killed" -eq 1

# A second live install must be refused while the journal is unresolved!
! /usr/bin/fplogin install --artifacts-dir /opt/artifacts-nodm --approve-plan "$sig_digest"

# fplogin recover must reconcile and restore exact pre-install baseline!
/usr/bin/fplogin recover | grep -Fq 'Recovery completed cleanly.'
snapshot_state > /run/snap-c5-after
diff -u /run/snap-c5-before /run/snap-c5-after
verify_console_login "case5-sigkill-recovered"
echo "CASE 5 PASS"

rm -f /run/cli-e2e-pass
echo "PACKAGED CLI E2E GUEST PASS"
systemctl --no-block poweroff
