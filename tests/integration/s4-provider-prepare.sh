#!/bin/bash
# Exercise the provider, not pacman on the host. No private key is mounted.
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
printf '[options]\nLocalFileSigLevel = Required TrustedOnly\n' > "$stage/pacman.conf"
CGO_ENABLED=0 go test -tags f05lab -c -o "$lab/installer-test" ./internal/core/install
invoke(){ docker run --rm --network none -i --tmpfs /var/lib/fplogin:uid=1000,gid=1000,mode=0700 -v "$stage:/cache:ro" -v "$lab/installer-test:/installer-test:ro" -v "$PWD/contracts/platform/v1/examples/request.valid.json:/request.json:ro" -v "$stage:$guest:ro" -v "$stage/pacman.conf:/etc/fplogin/f05-lab/pacman.conf:ro" -v "$PWD/.work/labs/sprint4/f05-signer/pacman:/etc/fplogin/f05-lab/public:ro" -v "$lab/platform-arch:/provider:ro" -v "$PWD/.work/labs/sprint4/f05-signer/approved.gpg:/etc/fplogin/f05-lab/candidate.gpg:ro" sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c "$@" <<<"$req"; }
installer(){ invoke /bin/bash -ec 'if [[ $2 == modified-pam ]]; then echo "# local change" >> /etc/pam.d/sddm; fi; chmod o+rx /etc/pacman.d/gnupg; chmod o+r /etc/pacman.d/gnupg/pubring.gpg; export TMPDIR=/var/lib/fplogin EXPECTED_ERROR="$1"; exec setpriv --reuid=1000 --regid=1000 --clear-groups /installer-test -test.run "^TestF05LabInstallerPreparation$" -test.v' -- "$1" "${2:-}"; }
installer 'recoverable package apply unavailable'
installer 'stock backup contents differ: /etc/pam.d/sddm' modified-pam
response=$(invoke /provider); jq -e '.ok and (.result.references|length==7)' <<<"$response" || { echo "$response" >&2; exit 1; }
# Remove an installed dependency only in the disposable container database.
response=$(invoke /bin/bash -ec 'pacman -Rdd --dbonly --noconfirm fprintd >&2; exec /provider')
jq -e '.ok==false and (.error.message|contains("offline package resolution"))' <<<"$response" || { echo "$response" >&2; exit 1; }
printf 'bad' > "$stage/$sum.sig"
installer 'signature rejected for sddm 0.21.0-7'
invoke /provider | jq -e '.ok==false and (.error.message|contains("signature rejected"))'
