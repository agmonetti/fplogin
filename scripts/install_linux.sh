#!/usr/bin/env bash
# Distro-agnostic Linux (systemd) installer for fplogin CLI, generic Linux
# platform provider, and SDDM adapter. Does not depend on pacman/apt/dnf.
#
# Usage:
#   sudo ./scripts/install_linux.sh [--prefix /usr] [--destdir DIR]
set -euo pipefail

prefix="/usr"
destdir=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)  prefix="$2"; shift 2 ;;
        --destdir) destdir="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,7p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="$root_dir/bin"

if [[ ! -x "$bin_dir/fplogin" || ! -x "$bin_dir/fplogin-platform-linux" || ! -x "$bin_dir/fplogin-adapter-sddm" ]]; then
    if command -v go >/dev/null 2>&1; then
        echo "Building fplogin binaries from source..."
        (
            cd "$root_dir"
            mkdir -p bin
            go build -trimpath -o bin/fplogin ./cmd/fplogin
            go build -trimpath -o bin/fplogin-platform-linux ./cmd/fplogin-platform-linux
            go build -trimpath -o bin/fplogin-adapter-sddm ./cmd/fplogin-adapter-sddm
        )
    else
        echo "ERROR: prebuilt binaries not found in $bin_dir and 'go' is not installed." >&2
        exit 1
    fi
fi

install -Dm755 "$bin_dir/fplogin"                "${destdir}${prefix}/bin/fplogin"
install -Dm755 "$bin_dir/fplogin-platform-linux" "${destdir}${prefix}/lib/fplogin/platforms/bin/fplogin-platform-linux"
install -Dm755 "$bin_dir/fplogin-adapter-sddm"   "${destdir}${prefix}/lib/fplogin/adapters/bin/fplogin-adapter-sddm"
install -Dm644 "$root_dir/platforms/linux/platform.json" "${destdir}${prefix}/lib/fplogin/platforms/linux.json"
install -Dm644 "$root_dir/adapters/sddm/adapter.json"    "${destdir}${prefix}/lib/fplogin/adapters/sddm.json"

install -dm755 "${destdir}${prefix}/lib/fplogin/platforms/assets" "${destdir}${prefix}/lib/fplogin/adapters/assets"
install -dm700 "${destdir}/var/lib/fplogin"
install -dm755 "${destdir}/etc/sddm.conf.d"

echo "Installed fplogin (generic Linux systemd provider + SDDM adapter) under ${destdir}${prefix}."
echo "Next steps:"
echo "  fplogin components"
echo "  fplogin analyze"
echo "  fplogin install --dry-run"
echo "  sudo fplogin install [--activate]"
