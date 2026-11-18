#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C SYSTEMD_COLORS=0
umask 077
[[ $# == 2 && $EUID == 0 && $1 =~ ^[a-f0-9]{32}$ && $2 =~ ^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$ ]] || exit 2
base=$(dirname -- "$(realpath -- "$0")")
unit=s3-keyring-$2
d=/root/$unit
fplogin-lab require-recovery
[[ $(tty) == /dev/ttyS0 && $(</proc/sys/kernel/random/boot_id) == "$2" && $(</etc/machine-id) == "$1" ]]
[[ $(systemctl is-active sddm || :) == inactive && ! -e $d ]]
grep -qx 'User=fplab' /var/lib/sddm/state.conf
grep -qxE 'Session=(/usr/share/wayland-sessions/)?hyprland\.desktop' /var/lib/sddm/state.conf
grep -qx 'Current=where-is-my-sddm-fplogin-qt6' /etc/sddm.conf.d/zz-t4-theme2-qt6.conf
[[ -s /home/fplab/.local/share/keyrings/login.keyring ]]
fprintd-list fplab | grep -F right-index-finger
sessions() { loginctl list-sessions --no-legend --no-pager | awk '$3=="fplab" && $4=="seat0" {print $1}'; }
[[ -z $(sessions) ]]
session_confirmed=false
tracer=
monitor=
started=false
cleanup() {
    local status=$?
    if [[ -n $monitor ]]; then kill "$monitor" 2>/dev/null || :; wait "$monitor" 2>/dev/null || :; fi
    if [[ -n $tracer && $(readlink /proc/$tracer/exe 2>/dev/null || :) == /usr/bin/bpftrace ]]; then kill -TERM "$tracer" || :; fi
    if $session_confirmed; then
        if (( status != 0 )); then
            echo 'BLOCKED: captura no verificada. SDDM no se detuvo; observa Hyprland antes de cerrar la sesion.' >&2
        fi
    elif $started; then
        systemctl stop sddm || :
    fi
}
trap cleanup EXIT
systemd-run --quiet --unit="$unit" -p RuntimeMaxSec=180 /usr/bin/bash "$base/s3-keyring-capture.sh" "$1" "$d"
for _ in {1..100}; do
    [[ -f $d/trace.txt && $(grep -c '^heartbeat ' "$d/trace.txt" || :) -ge 2 ]] && break
    sleep .2
done
[[ $(grep -c '^heartbeat ' "$d/trace.txt" || :) -ge 2 && ! -s $d/trace.stderr ]]
main=$(systemctl show -p MainPID --value "$unit")
read -r tracer rest <<< "$(</proc/$main/task/$main/children)"
[[ $tracer =~ ^[0-9]+$ && -z ${rest:-} && $(readlink /proc/$tracer/exe) == /usr/bin/bpftrace ]]
timeout 35 busctl --system --limit-messages=1 --match='type=method_call,interface=net.reactivated.Fprint.Device,member=VerifyStart' monitor > "$d/verify-start.txt" 2> "$d/monitor.stderr" &
monitor=$!
for _ in {1..30}; do grep -Fq 'Monitoring bus message stream.' "$d/monitor.stderr" && break; sleep .1; done
grep -Fq 'Monitoring bus message stream.' "$d/monitor.stderr"
started=true
systemctl start --no-block sddm
wait "$monitor"
monitor=
grep -Fq 'Interface=net.reactivated.Fprint.Device  Member=VerifyStart' "$d/verify-start.txt"
sender=$(grep -oE 'Sender=:[0-9]+\.[0-9]+' "$d/verify-start.txt")
busctl --system --timeout=2 status "${sender#Sender=}" | grep -E '^[[:blank:]]*(PID|Comm|Unit)=' > "$d/verify-sender.txt"
grep -Eq '^[[:blank:]]*Comm=sddm-helper$' "$d/verify-sender.txt"
echo 'APOYA AHORA el indice derecho UNA vez. No ingreses contrasena.'
for _ in {1..240}; do
    id=$(sessions)
    [[ $id =~ ^[0-9]+$ && $(loginctl show-session "$id" -p Active --value) == yes ]] && break
    sleep .25
done
[[ $id =~ ^[0-9]+$ ]]
python3 "$base/s3-keyring.py" snapshot "$id" fplab > "$d/session.json"
# A trace failure is not a reason to tear down a confirmed desktop session.
session_confirmed=true
n=$(grep -c '^heartbeat ' "$d/trace.txt")
for _ in {1..25}; do [[ $(grep -c '^heartbeat ' "$d/trace.txt") -gt $n ]] && break; sleep .2; done
[[ $(grep -c '^heartbeat ' "$d/trace.txt") -gt $n && $(readlink /proc/$tracer/exe) == /usr/bin/bpftrace ]]
kill -TERM "$tracer"
tracer=
for _ in {1..30}; do [[ -f $d/boot.after ]] && break; sleep .2; done
python3 "$base/s3-keyring.py" verify "$d" fplab
echo 'CAPTURA COMPLETA. Observa Hyprland antes de salir.'
