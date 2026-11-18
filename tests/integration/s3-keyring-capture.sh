#!/usr/bin/env bash
# Launch only from the authorized disposable guest's serial recovery shell.
set -euo pipefail
umask 077
export PATH=/usr/bin:/bin LC_ALL=C
unset BPFTRACE_QUIET BPFTRACE_LOG_SIZE BPFTRACE_PERF_RB_PAGES
[[ $# == 2 && $EUID == 0 && $1 =~ ^[a-f0-9]{32}$ && $2 =~ ^/root/s3-keyring-[a-zA-Z0-9_-]+$ ]] || exit 2
[[ $(< /etc/machine-id) == "$1" && -f /etc/fplogin-lab/host-machine-id ]] || exit 2
host=$(< /etc/fplogin-lab/host-machine-id)
[[ $host =~ ^[a-f0-9]{32}$ && $host != "$1" ]] || exit 2
here=$(dirname -- "$(realpath -- "$0")")
for path in /usr/lib/libpam.so.0 /usr/lib/security/{pam_gnome_keyring,pam_kwallet5}.so /usr/lib/sddm/sddm-helper; do
    [[ -f $path ]] || exit 2
done
mkdir -- "$2"
cd -- "$2"
sha256sum -- "$here/s3-keyring.bt" /usr/lib/libpam.so.0 \
    /usr/lib/security/{pam_gnome_keyring,pam_kwallet5}.so /usr/lib/sddm/sddm-helper > inputs.sha256
bpftrace --version > tracer-version.txt
boot=/proc/sys/kernel/random/boot_id
cp -- "$boot" boot.before
# Keep the wrapper alive to record the tracer exit status and boot.
bpftrace -q -B line "$here/s3-keyring.bt" > trace.txt 2> trace.stderr &
tracer=$!
printf 'Tracer PID %d. Stop via SIGTERM from the second guest shell.\n' "$tracer"
status=0
wait "$tracer" || status=$?
printf '%d\n' "$status" > trace.status
cp -- "$boot" boot.after
exit "$status"
