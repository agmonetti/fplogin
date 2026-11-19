#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
package=$(realpath "${1:?pass the Arch tools package}")
image=$(docker image inspect --format '{{.Id}}' archlinux:base-devel)
build=$(mktemp -d "$PWD/.work/build/s4-adapter-privilege.XXXXXX")
chmod 0755 "$build"
CGO_ENABLED=0 go test -c -o "$build/adapter.test" ./internal/adapterclient
CGO_ENABLED=0 go test -c -o "$build/install.test" ./internal/core/install
# Run this probe in the actual credential context immediately before Describe.
cat > "$build/adapter-probe" <<'PROBE'
#!/usr/bin/bash
set -eu
[[ $PWD == / && $# == 0 && ${FPL_UNSAFE_ENV-unset} == unset && $LC_ALL == C ]]
for file in /var/lib/fplogin/{manifest.json,transactions/tx.json,backups/tx/file.bak}; do
    [[ ! -r $file && ! -w $file ]]
done
read -r uid gid < /run/fplogin-test-ids
/usr/bin/awk -v u="$uid" -v g="$gid" '
/^Uid:/ { if (NF != 5 || $2 != u || $3 != u || $4 != u || $5 != u) exit 1; uid++ }
/^Gid:/ { if (NF != 5 || $2 != g || $3 != g || $4 != g || $5 != g) exit 1; gid++ }
/^Groups:/ { if (NF != 1) exit 1; groups++ }
/^Cap(Inh|Prm|Eff|Bnd|Amb):/ { if ($2 !~ /^0+$/) exit 1; caps++ }
/^NoNewPrivs:/ { if ($2 != 1) exit 1; nnp++ }
END { if (uid != 1 || gid != 1 || groups != 1 || caps != 5 || nnp != 1) exit 1 }
' "/proc/$$/status"
exec /usr/lib/fplogin/adapters/bin/adapter-real
PROBE
docker run --rm --pull=never --network=none --cap-drop=ALL \
    --cap-add=SETPCAP --cap-add=SETUID --cap-add=SETGID --cap-add=CHOWN \
    --mount "type=bind,src=$build,dst=/fixture,readonly" \
    --mount "type=bind,src=$package,dst=/tools.pkg.tar.zst,readonly" \
    --env FPL_ISOLATED_ADAPTER_TEST=1 "$image" /usr/bin/bash -euc '
    bsdtar -xf /tools.pkg.tar.zst -C / usr
    for command in install uninstall; do
        if fplogin "$command"; then exit 1; fi
    done
    FPL_EXPECT_NO_IDENTITY=1 /fixture/adapter.test -test.v -test.run "^TestElevatedAdapterHandshake$"
    /usr/bin/systemd-sysusers fplogin.conf
    printf "%s %s\n" "$(id -u fplogin-adapter)" "$(id -g fplogin-adapter)" > /run/fplogin-test-ids
    mv /usr/lib/fplogin/adapters/bin/{fplogin-adapter-sddm,adapter-real}
    install -m 0755 /fixture/adapter-probe /usr/lib/fplogin/adapters/bin/fplogin-adapter-sddm
    install -d -m 0700 /var/lib/fplogin /var/lib/fplogin/transactions /var/lib/fplogin/backups /var/lib/fplogin/backups/tx
    install -m 0600 /dev/null /var/lib/fplogin/manifest.json
    install -m 0600 /dev/null /var/lib/fplogin/transactions/tx.json
    install -m 0600 /dev/null /var/lib/fplogin/backups/tx/file.bak
    /fixture/adapter.test -test.v -test.run "^TestElevatedAdapterHandshake$"
    printf "fpl-conflict:x:%s:0::/:/usr/bin/nologin\n" "$(id -u fplogin-adapter)" >> /etc/passwd
    FPL_EXPECT_NO_IDENTITY=1 /fixture/adapter.test -test.v -test.run "^TestElevatedAdapterHandshake$"
    rm /var/lib/fplogin/manifest.json /var/lib/fplogin/transactions/tx.json
    install -d -m 0755 /etc/sddm.conf.d
    /fixture/install.test -test.v -test.run "^TestSystemFileTransaction$"
'
