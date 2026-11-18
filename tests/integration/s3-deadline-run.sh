#!/usr/bin/env bash
# Only inside the guarded guest, as root, after recovery-check and fresh reader handoff.
set -euo pipefail
export LC_ALL=C SYSTEMD_COLORS=0
umask 077
here=$(cd -- "$(dirname -- "$0")" && pwd)
fplogin-lab require-recovery >/dev/null
[[ $(uname -m) == x86_64 && $(systemctl is-active sddm || :) == inactive ]]
cd /
sha256sum -c <<'SUMS'
41cd8264241b5d510f9c96446ab7b32e3c0ee7e4a35ecd1f8c90bf43e307798a  usr/bin/sddm
5afdbe5ac384abdec69f82b7ace78f4f9c3439a88848b3cef7609da6fc838126  usr/lib/sddm/sddm-helper
bb8c568cb72f87608ec71fa19de4787807a7131e3dda23c7fef2aca6744c013e  usr/lib/security/pam_fprintd.so
SUMS
grep -Exq 'auth[[:space:]]+required[[:space:]]+pam_fprintd.so max-tries=3 timeout=35' /etc/pam.d/sddm-fingerprint
grep -Eq '^User=fplab[[:blank:]]*$' /var/lib/sddm/state.conf
grep -Eq '^Session=(/usr/share/wayland-sessions/)?hyprland.desktop[[:blank:]]*$' /var/lib/sddm/state.conf
grep -Fxq Current=where-is-my-sddm-fplogin-qt6 /etc/sddm.conf.d/zz-t4-theme2-qt6.conf
fprintd-list fplab | grep -F 'right-index-finger'
d=$(mktemp -d /root/s3-deadline.XXXXXXXX); echo "Evidence: $d"
faillock --user fplab > "$d/faillock-before"
cursor=$(journalctl -b -n1 --show-cursor -o cat | awk '/^-- cursor:/ {print $3}'); [[ -n $cursor ]]
unit=s3-deadline-${d##*.}; started=false
cleanup() {
    if $started; then systemctl stop sddm || :; fi
    systemctl stop "$unit" || :
}
trap cleanup EXIT
systemd-run --quiet --unit="$unit" -p UMask=0077 -p KillSignal=SIGINT -p RuntimeMaxSec=110 -p TimeoutStopSec=8 -p StandardOutput="file:$d/events" -p StandardError="file:$d/stderr" /usr/bin/bpftrace -q -B line "$here/s3-deadline.bt"
for i in {1..120}; do [[ -f $d/events ]] && grep -q '^tick ' "$d/events" && break; sleep .1; done
grep -q '^tick ' "$d/events"; test ! -s "$d/stderr"
started=true
systemctl start --no-block sddm
for i in {1..200}; do grep -q '^enter ' "$d/events" && break; sleep .15; done
helper=$(awk '$1=="enter" {print $3}' "$d/events"); [[ $helper =~ ^[0-9]+$ ]]
daemon=$(systemctl show -p MainPID --value sddm); [[ $daemon =~ ^[1-9][0-9]*$ ]]
python3 - "$helper" "$daemon" "$d/target.json" <<'PY'
import json, re, sys, uuid
from pathlib import Path
h, daemon, dest=sys.argv[1:]; p=Path('/proc')/h
if p.joinpath('exe').resolve(strict=True) != Path('/usr/lib/sddm/sddm-helper'):
    sys.exit('unexpected helper')
# Read only selected non-secret CLI identifiers; never print cmdline or PAM input.
a=p.joinpath('cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
def field(k):
    if a.count(k)!=1: sys.exit('missing or ambiguous helper identity')
    return a[a.index(k)+1]
r=str(uuid.UUID(field('--request-id'))); method=field('--method'); ident=field('--id')
if method!='1' or not re.fullmatch('[0-9]+',ident): sys.exit('not a fingerprint attempt')
Path(dest).write_text(json.dumps(dict(boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),daemon=int(daemon),helper=int(h),request=r,method=method,auth_id=ident,start_ticks=p.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]))+'\n')
PY
for i in {1..300}; do grep -q '^exit ' "$d/events" && break; sleep .2; done
grep -q '^exit ' "$d/events"; sleep 3; systemctl is-active --quiet "$unit"
# Stop tracer first so greeter teardown cannot add a second attempt to the evidence.
systemctl stop "$unit"; grep -q '^end ' "$d/events"
users=$(loginctl list-sessions --no-legend); if awk '$3=="fplab" && $4=="seat0" {found=1} END {exit !found}' <<< "$users"; then exit 1; fi
logs=$(journalctl -b --after-cursor="$cursor" -u sddm -o cat)
if grep -Eq 'Session started true|session opened for user fplab' <<< "$logs"; then exit 1; fi
grep -Fq 'Loading theme configuration from "/usr/share/sddm/themes/where-is-my-sddm-fplogin-qt6/theme.conf"' <<< "$logs"
cmp "$d/faillock-before" <(faillock --user fplab)
touch "$d/negative-ok"
python3 "$here/s3-deadline.py" "$d"
