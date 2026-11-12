#!/bin/sh
# Sprint 3 (preparatory, unaccepted) PAM stack scenarios for the packaged
# sddm-fingerprint service. Runs ONLY inside a disposable no-network lab
# container as root; it edits that container's /etc only. Never on the host.
# Usage: docker run ... -v <repo>:/repo:ro <lab-image> /repo/tests/integration/sprint3-pam-stack-check.sh
set -u
test -f /.dockerenv && test "$(id -u)" = 0 || { echo "refusing: not a disposable container as root"; exit 2; }
cc -o /tmp/pamc /repo/tests/integration/sprint3_pam_client.c -lpam || exit 2
grep -q '^/bin/bash$' /etc/shells || echo /bin/bash >> /etc/shells
useradd -m -s /bin/bash fpuser 2>/dev/null; useradd -m -s /bin/bash fpdenied 2>/dev/null
useradd -m -s /bin/bash fpexpired 2>/dev/null; useradd -m -s /usr/local/bin/notashell fpbadshell 2>/dev/null
useradd -m -s /bin/bash fplocked 2>/dev/null
chage -E 1 fpexpired
printf -- '-:fpdenied:ALL\n' >> /etc/security/access.conf
printf 'auth required pam_faillock.so authfail deny=3\n' > /etc/pam.d/fpl-seed-failures
for i in 1 2 3; do /tmp/pamc auth fpl-seed-failures fplocked >/dev/null; done
run() { # label service mode user
  printf '%-40s %-22s ' "$1" "$2"; /tmp/pamc "$3" "$2" "$4"
}
cp /repo/platforms/arch/pam/sddm-fingerprint /etc/pam.d/fpl-new
printf 'auth required pam_fprintd.so timeout=30\naccount include sddm\nsession include sddm\n' > /etc/pam.d/fpl-lab
for svc in fpl-new fpl-lab; do
  echo "== service $svc"
  run "valid user reaches pam_fprintd"   $svc auth fpuser
  run "valid shell, no lock: account"     $svc account fpuser
  run "pam_access denial: account"        $svc account fpdenied
  run "expired account: account"          $svc account fpexpired
  run "invalid shell: auth"               $svc auth fpbadshell
  run "faillock-locked: auth"             $svc auth fplocked
  touch /etc/nologin
  run "/etc/nologin present: auth"        $svc auth fpuser
  rm -f /etc/nologin
  run "valid user: setcred+session"       $svc session fpuser
  run "password change"                   $svc chauthtok fpuser
done
