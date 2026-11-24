#!/bin/bash
# Exercise the Arch provider and recoverable installer inside a disposable,
# networkless Arch container. Never modifies the host; no private key is mounted.
set -euo pipefail
cd "$(dirname "$0")/../.."
lab=$PWD/.work/labs/sprint4/f05-baseline
stage=$(mktemp -d "$lab/prepare.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
guest=/var/lib/fplogin/archives
refs='[]'
for file in "$lab"/inputs/*.zst "$PWD"/.work/labs/sprint3/e6-abi/stock/*.zst; do
    sum=$(sha256sum "$file" | cut -d' ' -f1)
    name=${file##*/}; printf '%s' "${name%-*-*-*}" > "$stage/$sum.name"
    cp "$file" "$stage/$sum"; cp "$file.sig" "$stage/$sum.sig"
    refs=$(jq -c --arg hash "$sum" --arg path "$guest/$sum" --argjson size "$(stat -c %s "$file")" '.+[{artifact_id:$hash,canonical_path:$path,media_type:"application/octet-stream",size:$size,sha256:$hash}]' <<<"$refs")
done
req=$(jq -c --arg dir "$guest" --argjson refs "$refs" '.operation="PrepareArtifactInstall" | .context.deadline=(now+120|todateiso8601) | .payload={plan_digest:("a"*64),selected_capabilities:[],operation_ids:["install"],artifact_references:$refs,staging_handoff:{workspace:$dir,source_cache:$dir}}' contracts/platform/v1/examples/request.valid.json)
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

# Common container setup: install packaged provider at root-owned trusted path,
# create local setting to prove preservation, and define snapshot().
common_setup='
set -euo pipefail
export LC_ALL=C
install -d -m 0755 /usr/lib/fplogin /usr/lib/fplogin/platforms /usr/lib/fplogin/platforms/bin /usr/lib/fplogin/platforms/assets /etc/sddm.conf.d
install -m 0644 /provider-descriptor.json /usr/lib/fplogin/platforms/platform.json
install -m 0755 /provider /usr/lib/fplogin/platforms/bin/fplogin-platform-arch
mkdir -p /var/lib/fplogin && chmod 0700 /var/lib/fplogin
printf "# F05 unrelated local setting\n" > /etc/sddm.conf.d/10-local.conf
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

echo "=== Case 1: Direct provider PrepareArtifactInstall & dependency drift ==="
response=$(run_container /provider <<<"$req")
jq -e '.ok and (.result.references|length==7)' <<<"$response" || { echo "$response" >&2; exit 1; }
response=$(run_container /bin/bash -ec 'pacman -Rdd --dbonly --noconfirm fprintd >&2; exec /provider' <<<"$req")
jq -e '.ok==false and (.error.message|contains("offline package resolution"))' <<<"$response" || { echo "$response" >&2; exit 1; }

echo "=== Case 2: Preparation refuses modified /etc/pam.d/sddm before mutation ==="
run_container /bin/bash -ec "$common_setup"'
echo "# local change" >> /etc/pam.d/sddm
snapshot > /run/before
F05_CASE=prepare-refuse EXPECTED_ERROR="stock backup contents differ: /etc/pam.d/sddm" /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
snapshot > /run/after
diff -u /run/before /run/after
'

echo "=== Case 3: Real package failure (hook aborts sddm-fplogin after Qt5 install) rolls back packages ==="
run_container /bin/bash -ec "$common_setup"'
snapshot > /run/before
mkdir -p /etc/pacman.d/hooks
cat > /etc/pacman.d/hooks/01-f05-refuse.hook <<EOF
[Trigger]
Operation = Install
Type = Package
Target = sddm-fplogin
[Action]
Description = F05 controlled package refusal
When = PreTransaction
Exec = /usr/bin/false
AbortOnFail
EOF
F05_CASE=pkg-fail /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
rm -f /etc/pacman.d/hooks/01-f05-refuse.hook
snapshot > /run/after
diff -u /run/before /run/after
'

echo "=== Case 4: Verification failure prevents activation and rolls back file + stock SDDM + Qt5 ==="
run_container /bin/bash -ec "$common_setup"'
snapshot > /run/before
F05_CASE=verify-fail /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
snapshot > /run/after
diff -u /run/before /run/after
'

echo "=== Case 5: SIGKILL after real package + file mutation, then fresh-process RecoverTransaction ==="
run_container /bin/bash -ec "$common_setup"'
snapshot > /run/before
mkfifo /run/child-in /run/child-out
F05_CASE=sigkill-child /installer-test -test.run "^TestF05LabInstallerTransaction$" < /run/child-in > /run/child-out 2>&1 &
pid=$!
exec 3> /run/child-in
grep -m1 -Fx "F05_READY" /run/child-out
kill -9 "$pid"
wait "$pid" || true
exec 3>&-
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
[[ -f /etc/sddm.conf.d/90-fplogin.conf ]]
F05_CASE=sigkill-recover /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
snapshot > /run/after
diff -u /run/before /run/after
'

echo "=== Case 6: Real service failure after systemctl enable rolls back service + file + stock SDDM + Qt5 ==="
run_container /bin/bash -ec "$common_setup"'
snapshot > /run/before
F05_CASE=svc-fail /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
snapshot > /run/after
diff -u /run/before /run/after
'

echo "=== Case 7: Full recoverable package + file + service install succeeds and preserves local files ==="
run_container /bin/bash -ec "$common_setup"'
F05_CASE=success /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
[[ $(pacman -Q sddm-fplogin) == "sddm-fplogin 0.21.0-3.1" ]]
! pacman -Qq | grep -Fx sddm
sha256sum -c /run/local-pins
[[ $(systemctl is-enabled sddm.service) == "enabled" ]]
'

echo "=== Case 8: Tampered signature rejected before mutation ==="
printf 'bad' > "$stage/$sum.sig"
run_container /bin/bash -ec "$common_setup"'
snapshot > /run/before
F05_CASE=prepare-refuse EXPECTED_ERROR="signature rejected for sddm 0.21.0-7" /installer-test -test.run "^TestF05LabInstallerTransaction$" -test.v
snapshot > /run/after
diff -u /run/before /run/after
'
run_container /provider <<<"$req" | jq -e '.ok==false and (.error.message|contains("signature rejected"))'
echo "ALL F05 CONTAINER CASES PASSED"
