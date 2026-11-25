#!/usr/bin/bash
# S4-F07 real-systemd disposable Arch x86_64 guest lifecycle verification.
# Runs ONLY inside a disposable, networkless, reader-free QEMU/KVM guest.
set -Eeuo pipefail
export LC_ALL=C

grep -qw 'fplogin.f07=1' /proc/cmdline
systemd-detect-virt --vm
[[ $(cat /proc/1/comm) == systemd ]]
trap 'echo "F07 GUEST FAIL line $LINENO"; rm -f /run/f07-lab-pass; systemctl --no-block poweroff' ERR

echo "=== S4-F07 Guest Environment ==="
uname -r
systemctl --version | head -1
ip -o link show
pacman -Q sddm systemd linux

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
mkdir -p /etc/sddm.conf.d /var/lib/fplogin
chmod 0700 /var/lib/fplogin
printf '# F07 unrelated local SDDM setting\n' > /etc/sddm.conf.d/10-local.conf
sha256sum /etc/sddm.conf.d/10-local.conf /etc/pam.d/login > /run/f07-local-pins
sha256sum /etc/pam.d/sddm /etc/pam.d/sddm-autologin /etc/pam.d/sddm-greeter \
    /usr/share/sddm/scripts/Xsetup /usr/share/sddm/scripts/Xstop > /run/f07-stock-pins

# Secret-free real text-console password login check via /bin/login on a PTY
# plus verification that text-console getty recovery is active.
verify_console_login() {
    local label=$1
    systemctl is-active --quiet getty@tty2.service
    python3 - <<'PY'
import os, pty, select, sys, time

pw = open("/run/f07-lab-pass", "r").read().strip()

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
        try:
            read_until([b"login:"])
        except RuntimeError as e:
            raise RuntimeError(f"{e}; pre-login buf={buf!r}")
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
    sha256sum -c --quiet /run/f07-local-pins
    echo "CONSOLE_PASSWORD_LOGIN_OK ($label)"
}

snap_system() {
    echo "--- packages ---"
    pacman -Q
    echo "--- explicit ---"
    pacman -Qqe
    echo "--- services ---"
    for u in sddm.service greetd.service display-manager.service getty@tty2.service; do
        printf '%s enabled=%s active=%s\n' "$u" \
            "$(systemctl is-enabled "$u" 2>/dev/null || true)" \
            "$(systemctl is-active "$u" 2>/dev/null || true)"
    done
    echo "--- configs ---"
    for f in /etc/sddm.conf /etc/pam.d/login /etc/pam.d/sddm /etc/pam.d/sddm-autologin /etc/pam.d/sddm-greeter /usr/share/sddm/scripts/Xsetup /usr/share/sddm/scripts/Xstop; do
        if [[ -f $f ]]; then
            sha256sum "$f"
        else
            echo "absent: $f"
        fi
    done
    if [[ -d /etc/sddm.conf.d ]]; then
        find /etc/sddm.conf.d -type f -print0 | sort -z | xargs -0r sha256sum
    fi
    echo "--- manifest ---"
    if [[ -f /var/lib/fplogin/manifest.json ]]; then
        stat -c '%a %U:%G' /var/lib/fplogin/manifest.json
        sha256sum /var/lib/fplogin/manifest.json
    else
        echo "manifest: absent"
    fi
}

log_journal_summary() {
    local label=$1
    local count=0
    if [[ -d /var/lib/fplogin/transactions ]]; then
        count=$(find /var/lib/fplogin/transactions -maxdepth 1 -name '*.json' | wc -l)
    fi
    local mstate="absent"
    [[ -f /var/lib/fplogin/manifest.json ]] && mstate="present($(stat -c %a /var/lib/fplogin/manifest.json))"
    echo "STATE [$label]: manifest=$mstate journals=$count sddm=$(systemctl is-enabled sddm.service 2>/dev/null || true)/$(systemctl is-active sddm.service 2>/dev/null || true) greetd=$(systemctl is-enabled greetd.service 2>/dev/null || true)/$(systemctl is-active greetd.service 2>/dev/null || true)"
}

run_case() {
    local name=$1
    F07_CASE="$name" /opt/f07/installer-test -test.run '^TestF07GuestLifecycle$' -test.v
}

verify_console_login "initial-baseline"

# =============================================================================
# SCENARIO 1: NO DISPLAY MANAGER
# =============================================================================
echo "=== Scenario 1: No Display Manager ==="
systemctl disable --now sddm.service >/dev/null 2>&1 || true
pacman -Rdd --noconfirm sddm >/dev/null
systemctl daemon-reload
snap_system > /run/f07-nodm-base
log_journal_summary "1-nodm-before"

# 1a: Fail package stage via pacman PreTransaction hook -> rollback preserves no-DM & text console
mkdir -p /etc/pacman.d/hooks
cat > /etc/pacman.d/hooks/99-f07-fail.hook <<'EOF'
[Trigger]
Operation = Install
Type = Package
Target = sddm-fplogin
[Action]
Description = F07 simulated package failure
When = PreTransaction
Exec = /usr/bin/false
AbortOnFail
EOF
run_case no-dm-pkg-fail
rm -f /etc/pacman.d/hooks/99-f07-fail.hook
snap_system > /run/f07-nodm-after-pkg-fail
diff -u /run/f07-nodm-base /run/f07-nodm-after-pkg-fail
verify_console_login "1a-no-dm-pkg-fail-rollback"
log_journal_summary "1a-nodm-pkg-fail"

# 1b: Fail verification after package + file -> rollback restores no-DM
run_case no-dm-verify-fail
snap_system > /run/f07-nodm-after-verify-fail
diff -u /run/f07-nodm-base /run/f07-nodm-after-verify-fail
verify_console_login "1b-no-dm-verify-fail-rollback"
log_journal_summary "1b-nodm-verify-fail"

# 1c: Fail service activation after enable-sddm -> rollback disables sddm, removes file & packages
run_case no-dm-svc-fail
snap_system > /run/f07-nodm-after-svc-fail
diff -u /run/f07-nodm-base /run/f07-nodm-after-svc-fail
verify_console_login "1c-no-dm-svc-fail-rollback"
log_journal_summary "1c-nodm-svc-fail"

# 1d: Fresh install succeeds -> configured login + text-console recovery -> uninstall restores no-DM
run_case no-dm-install
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
grep -Fx 'AutoFingerprintForLegacyThemes=true' /etc/sddm.conf.d/90-fplogin.conf
sha256sum -c --quiet /run/f07-stock-pins
verify_console_login "1d-no-dm-fresh-install"
log_journal_summary "1d-nodm-installed"

run_case no-dm-uninstall
snap_system > /run/f07-nodm-after-uninstall
diff -u /run/f07-nodm-base /run/f07-nodm-after-uninstall
verify_console_login "1d-no-dm-uninstall"
log_journal_summary "1d-nodm-uninstalled"

# 1e: Interrupted (SIGKILL) installation on no-DM -> console recovery restores no-DM
mkfifo /run/f07-nodm-in /run/f07-nodm-out
F07_CASE=interrupt-sigkill-nodm /opt/f07/installer-test -test.run '^TestF07GuestLifecycle$' < /run/f07-nodm-in > /run/f07-nodm-out 2>&1 &
pid=$!
exec 3> /run/f07-nodm-in
grep -m1 -Fx 'F07_READY' /run/f07-nodm-out
kill -9 "$pid"
wait "$pid" || true
exec 3>&-
rm -f /run/f07-nodm-in /run/f07-nodm-out
run_case interrupt-second-refused
run_case interrupt-recover
snap_system > /run/f07-nodm-after-recover
diff -u /run/f07-nodm-base /run/f07-nodm-after-recover
verify_console_login "1e-no-dm-sigkill-recover"
log_journal_summary "1e-nodm-recovered"

# =============================================================================
# SCENARIO 2: STOCK SDDM
# =============================================================================
echo "=== Scenario 2: Stock SDDM ==="
pacman -U --noconfirm /opt/f07/stock-sddm.pkg.tar.zst >/dev/null
systemctl daemon-reload
systemctl enable sddm.service >/dev/null 2>&1
sha256sum -c --quiet /run/f07-stock-pins
snap_system > /run/f07-stock-base
log_journal_summary "2-stock-before"

# 2a: Service failure during stock SDDM replacement -> rollback restores exact stock SDDM state
run_case stock-svc-fail
snap_system > /run/f07-stock-after-fail
diff -u /run/f07-stock-base /run/f07-stock-after-fail
sha256sum -c --quiet /run/f07-stock-pins
verify_console_login "2a-stock-svc-fail-rollback"
log_journal_summary "2a-stock-svc-fail"

# 2b: Install replacing stock SDDM -> compare stock config -> uninstall restores exact stock SDDM state
run_case stock-install
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
sha256sum -c --quiet /run/f07-stock-pins
sha256sum -c --quiet /run/f07-local-pins
verify_console_login "2b-stock-installed"
log_journal_summary "2b-stock-installed"

run_case stock-uninstall
snap_system > /run/f07-stock-after-uninstall
diff -u /run/f07-stock-base /run/f07-stock-after-uninstall
sha256sum -c --quiet /run/f07-stock-pins
verify_console_login "2b-stock-uninstalled"
log_journal_summary "2b-stock-uninstalled"

# =============================================================================
# SCENARIO 3: ANOTHER ENABLED DISPLAY MANAGER (greetd)
# =============================================================================
echo "=== Scenario 3: Another Enabled Display Manager (greetd) ==="
systemctl disable --now sddm.service >/dev/null 2>&1 || true
pacman -U --noconfirm /opt/f07/greetd*.pkg.tar.zst >/dev/null
systemctl daemon-reload
systemctl enable --now greetd.service >/dev/null 2>&1
sleep 1
systemctl is-enabled --quiet greetd.service
systemctl is-active --quiet greetd.service
snap_system > /run/f07-greetd-base
log_journal_summary "3-greetd-before"

# 3a: Refusal leaves greetd completely unchanged
run_case greetd-refuse
snap_system > /run/f07-greetd-after-refuse
diff -u /run/f07-greetd-base /run/f07-greetd-after-refuse
verify_console_login "3a-greetd-refuse"
log_journal_summary "3a-greetd-refused"

# 3b: Approved replacement fails at service stage -> rollback restores greetd enabled & active
run_case greetd-svc-fail
snap_system > /run/f07-greetd-after-fail
diff -u /run/f07-greetd-base /run/f07-greetd-after-fail
verify_console_login "3b-greetd-svc-fail-rollback"
log_journal_summary "3b-greetd-svc-fail"

# 3c: Approved replacement succeeds -> uninstall restores greetd enabled & active
run_case greetd-install
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
verify_console_login "3c-greetd-replaced-by-sddm"
log_journal_summary "3c-greetd-replaced"

run_case greetd-uninstall
snap_system > /run/f07-greetd-after-uninstall
diff -u /run/f07-greetd-base /run/f07-greetd-after-uninstall
verify_console_login "3c-greetd-restored"
log_journal_summary "3c-greetd-restored"

# Clean up greetd before Scenario 4
systemctl disable --now greetd.service >/dev/null 2>&1 || true
pacman -Rns --noconfirm greetd greetd-agreety >/dev/null 2>&1 || pacman -R --noconfirm greetd greetd-agreety >/dev/null
systemctl daemon-reload

# =============================================================================
# SCENARIO 4: PARTIAL PRIOR INSTALLATION
# =============================================================================
echo "=== Scenario 4: Partial Prior Installation ==="
# Pre-install qt5-translations + qt5-base and a stale 0640 90-fplogin.conf without manifest.json
pacman -U --noconfirm /opt/f07/qt5-translations.pkg.tar.zst /opt/f07/qt5-base.pkg.tar.zst >/dev/null
printf '[Theme]\nCurrent=stale\n' > /etc/sddm.conf.d/90-fplogin.conf
chmod 0640 /etc/sddm.conf.d/90-fplogin.conf
snap_system > /run/f07-partial-base
log_journal_summary "4-partial-before"

run_case partial-install
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
grep -Fx 'AutoFingerprintForLegacyThemes=true' /etc/sddm.conf.d/90-fplogin.conf
verify_console_login "4-partial-installed"

# Delete theme file and run repair -> restores file and preserves original recovery_baseline
rm -f /etc/sddm.conf.d/90-fplogin.conf
run_case partial-repair
grep -Fx 'AutoFingerprintForLegacyThemes=true' /etc/sddm.conf.d/90-fplogin.conf

# Uninstall restores exact partial baseline (keeps pre-existing qt5-base/translations and 0640 file!)
run_case partial-uninstall
snap_system > /run/f07-partial-after-uninstall
diff -u /run/f07-partial-base /run/f07-partial-after-uninstall
verify_console_login "4-partial-uninstalled"
log_journal_summary "4-partial-uninstalled"

# Clean up partial fixtures before Scenario 5
rm -f /etc/sddm.conf.d/90-fplogin.conf
pacman -R --noconfirm qt5-base qt5-translations >/dev/null

# =============================================================================
# SCENARIO 5: INTERRUPTED INSTALLATION (SIGKILL) + CONSOLE RECOVERY ON STOCK SDDM
# =============================================================================
echo "=== Scenario 5: Interrupted Installation (SIGKILL) on Stock SDDM ==="
systemctl enable sddm.service >/dev/null 2>&1
snap_system > /run/f07-interrupt-base
log_journal_summary "5-interrupt-before"

mkfifo /run/f07-stk-in /run/f07-stk-out
F07_CASE=interrupt-sigkill-stock /opt/f07/installer-test -test.run '^TestF07GuestLifecycle$' < /run/f07-stk-in > /run/f07-stk-out 2>&1 &
pid=$!
exec 3> /run/f07-stk-in
grep -m1 -Fx 'F07_READY' /run/f07-stk-out
kill -9 "$pid"
wait "$pid" || true
exec 3>&-
rm -f /run/f07-stk-in /run/f07-stk-out

# Verify unresolved state blocks a second install until recovered
run_case interrupt-second-refused
# Recover from text console -> restores exact stock SDDM baseline
run_case interrupt-recover
snap_system > /run/f07-interrupt-after-recover
diff -u /run/f07-interrupt-base /run/f07-interrupt-after-recover
sha256sum -c --quiet /run/f07-stock-pins
verify_console_login "5-interrupt-stock-recovered"
log_journal_summary "5-interrupt-recovered"

rm -f /run/f07-lab-pass
echo "F07 GUEST LIFECYCLE PASS"
systemctl --no-block poweroff
