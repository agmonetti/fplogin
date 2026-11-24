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
    cp "$file" "$stage/$sum"; cp "$file.sig" "$stage/$sum.sig"
    refs=$(jq -c --arg hash "$sum" --arg path "$guest/$sum" --argjson size "$(stat -c %s "$file")" '.+[{artifact_id:$hash,canonical_path:$path,media_type:"application/octet-stream",size:$size,sha256:$hash}]' <<<"$refs")
done
req=$(jq -c --arg dir "$guest" --argjson refs "$refs" '.operation="PrepareArtifactInstall" | .context.deadline=(now+120|todateiso8601) | .payload={plan_digest:("a"*64),selected_capabilities:[],operation_ids:["install"],artifact_references:$refs,staging_handoff:{workspace:$dir,source_cache:$dir}}' contracts/platform/v1/examples/request.valid.json)
CGO_ENABLED=0 go build -o "$lab/platform-arch" ./cmd/fplogin-platform-arch
printf '[options]\nLocalFileSigLevel = Required TrustedOnly\n' > "$stage/pacman.conf"
invoke(){ docker run --rm --network none -i -v "$stage:$guest:ro" -v "$stage/pacman.conf:/etc/fplogin/f05-lab/pacman.conf:ro" -v "$PWD/.work/labs/sprint4/f05-signer/pacman:/etc/fplogin/f05-lab/public:ro" -v "$lab/platform-arch:/provider:ro" -v "$PWD/.work/labs/sprint4/f05-signer/approved.gpg:/etc/fplogin/f05-lab/candidate.gpg:ro" sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c /provider <<<"$req"; }
response=$(invoke); jq -e '.ok and (.result.references|length==7)' <<<"$response" || { echo "$response" >&2; exit 1; }
printf 'bad' > "$stage/$sum.sig"
invoke | jq -e '.ok==false and (.error.message|contains("signature rejected"))'
