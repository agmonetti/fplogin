#!/usr/bin/env bash
# Run with a local Arch image (or its ID) and the main makepkg archive.
set -euo pipefail
package=$(realpath "${1:?usage: $0 PACKAGE [ARCH_IMAGE]}")
image=${2:-archlinux:base-devel}
entries=$(bsdtar -tf "$package")
if grep -Eq '^usr/share/sddm/|^etc/pam.d/' <<< "$entries"; then
    echo 'The tools package must not ship SDDM integration files' >&2
    exit 1
fi

docker run --rm --pull never --network none --cap-drop ALL --cap-add SETUID --cap-add SETGID \
    --security-opt no-new-privileges --mount "type=bind,src=${package},dst=/tools.pkg.tar.zst,readonly" \
    --entrypoint /usr/bin/bash "$image" -ec '
    bsdtar -xf /tools.pkg.tar.zst -C / usr/bin/fplogin usr/lib/fplogin
    for d in platforms adapters; do
        test "$(stat -c %u:%g:%a /usr/lib/fplogin/$d/assets)" = 0:0:755
    done
    run_user() { setpriv --reuid=65534 --regid=65534 --clear-groups "$@"; }
    found=$(run_user /usr/bin/fplogin components)
    printf "%s\n" "$found"
    grep -Fxq "provider org.fplogin.platform.arch: /usr/lib/fplogin/platforms/bin/fplogin-platform-arch (assets: /usr/lib/fplogin/platforms/assets)" <<< "$found"
    grep -Fxq "adapter org.fplogin.adapter.sddm: /usr/lib/fplogin/adapters/bin/fplogin-adapter-sddm (assets: /usr/lib/fplogin/adapters/assets)" <<< "$found"
    if /usr/bin/fplogin components; then exit 1; fi
    expect_disabled() {
        local rc=0
        run_user /usr/bin/fplogin "$@" || rc=$?
        test "$rc" -eq 1
    }
    expect_disabled install
    expect_disabled install --dry-run
    expect_disabled uninstall
'
