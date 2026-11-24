#!/bin/bash
# Run from repository root against the disposable F05 baseline, never host PAM.
set -euo pipefail
lab=$PWD/.work/labs/sprint4/f05-baseline
CGO_ENABLED=0 go build -o "$lab/platform-arch" ./cmd/fplogin-platform-arch
req=$(jq -c '.operation="VerifyOperation" | .context.deadline=(now+120|todateiso8601) | .payload={operation_id:"stock",plan_digest:("a"*64),phase:"pre_apply",expected_postcondition:{stock_backup_files_match_archive:"927cc24362cdc83b8c48532252ae4d41ade99dc5e65cb0fdeb9b6d69f7601a7a"}}' contracts/platform/v1/examples/request.valid.json)
result=$(docker run --rm --network none -e "REQ=$req" -v "$lab/platform-arch:/provider:ro" sha256:4da16761307d6db0754c243bc15b5f4dab17c9556f18bd93d952fe22eb7a606c /bin/bash -ec '
 /provider <<<"$REQ"
 /provider <<<"${REQ/pre_apply/post_rollback}"
 /provider <<<"${REQ/stock_backup_files_match_archive/unimplemented}"
 echo "# local change" >> /etc/pam.d/sddm
 /provider <<<"$REQ"
')
jq -es 'length==4 and all(.[:2][]; .ok and .result.checks[0].status=="passed") and .[2].error.code=="unsupported_operation" and .[3].ok==false and (.[3].error.message|contains("stock backup contents differ: /etc/pam.d/sddm"))' <<<"$result"
