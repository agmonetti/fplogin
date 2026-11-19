#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
image=$(docker image inspect --format '{{.Id}}' archlinux:base-devel)
build=$(mktemp -d "$PWD/.work/build/s4-adapter-privilege.XXXXXX")
chmod 0755 "$build"
CGO_ENABLED=0 go test -c -o "$build/adapter.test" ./internal/adapterclient
CGO_ENABLED=0 go build -o "$build/adapter-real" ./cmd/fplogin-adapter-sddm
cp adapters/sddm/adapter.json "$build/sddm.json"
# Run this probe in the actual credential context immediately before Describe.
cat > "$build/adapter-probe" <<'PROBE'
#!/usr/bin/bash
set -eu
[[ $PWD == / && $# == 0 && ${FPL_UNSAFE_ENV-unset} == unset && $LC_ALL == C ]]
for file in /var/lib/fplogin/{manifest.json,transactions/tx.json,backups/tx/file.bak}; do
    [[ ! -r $file && ! -w $file ]]
done
/usr/bin/awk '
/^Uid:/ { if (NF != 5 || $2 != 65534 || $3 != 65534 || $4 != 65534 || $5 != 65534) exit 1; uid++ }
/^Gid:/ { if (NF != 5 || $2 != 65534 || $3 != 65534 || $4 != 65534 || $5 != 65534) exit 1; gid++ }
/^Groups:/ { if (NF != 1) exit 1; groups++ }
/^Cap(Inh|Prm|Eff|Bnd|Amb):/ { if ($2 !~ /^0+$/) exit 1; caps++ }
/^NoNewPrivs:/ { if ($2 != 1) exit 1; nnp++ }
END { if (uid != 1 || gid != 1 || groups != 1 || caps != 5 || nnp != 1) exit 1 }
' "/proc/$$/status"
exec /fixture/adapter-real
PROBE
docker run --rm --pull=never --network=none --read-only --cap-drop=ALL \
    --cap-add=SETPCAP --cap-add=SETUID --cap-add=SETGID \
    --mount "type=bind,src=$build,dst=/fixture,readonly" \
    --tmpfs /usr/lib/fplogin:rw,exec,mode=0755 \
    --tmpfs /var/lib/fplogin:rw,noexec,mode=0700 \
    --env FPL_ISOLATED_ADAPTER_TEST=1 "$image" /usr/bin/bash -euc '
    install -d /usr/lib/fplogin/adapters/bin /usr/lib/fplogin/adapters/assets
    install -m 0644 /fixture/sddm.json /usr/lib/fplogin/adapters/sddm.json
    install -m 0755 /fixture/adapter-probe /usr/lib/fplogin/adapters/bin/fplogin-adapter-sddm
    install -d -m 0700 /var/lib/fplogin/transactions /var/lib/fplogin/backups /var/lib/fplogin/backups/tx
    install -m 0600 /dev/null /var/lib/fplogin/manifest.json
    install -m 0600 /dev/null /var/lib/fplogin/transactions/tx.json
    install -m 0600 /dev/null /var/lib/fplogin/backups/tx/file.bak
    /fixture/adapter.test -test.v -test.run "^TestElevatedAdapterHandshake$"
'
