#!/usr/bin/env bash
# Build local/private reproducible release artifacts, SHA256SUMS, and optional
# detached GPG signatures under .work/release/<version>/ without mutating the
# host or pushing anything remotely.
#
# Usage:
#   scripts/build_release.sh [--version v1.0.0] [--sddm-pkg <path>] [--fplogin-pkg <path>] [--gpg-key <fpr-or-id>]
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

version="v1.0.0"
sddm_pkg=""
fplogin_pkg=""
gpg_key=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)     version="$2"; shift 2 ;;
        --sddm-pkg)    sddm_pkg="$2"; shift 2 ;;
        --fplogin-pkg) fplogin_pkg="$2"; shift 2 ;;
        --gpg-key)     gpg_key="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,9p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

out_dir="$repo/.work/release/${version}"
mkdir -p "$out_dir"
rm -f "$out_dir/SHA256SUMS" "$out_dir/SHA256SUMS.asc"

head_commit="$(git rev-parse HEAD)"
sde="$(git show -s --format=%ct HEAD)"
tar_name="fplogin-${version#v}.tar.gz"

echo "Creating reproducible source tarball $tar_name (commit ${head_commit:0:12}, SOURCE_DATE_EPOCH=$sde)..."
git archive --format=tar --prefix="fplogin-${version#v}/" "$head_commit" \
    | GZIP=-n gzip -9 > "$out_dir/$tar_name"
touch -d "@$sde" "$out_dir/$tar_name"

# Build distro-agnostic Linux binary tarballs (x86_64 + aarch64) for any systemd distro
build_linux_bundle() {
    local goarch="$1" arch_label="$2"
    local linux_tar="fplogin-linux-${arch_label}.tar.gz"
    local linux_stage
    linux_stage="$(mktemp -d)"
    mkdir -p "$linux_stage/bin" "$linux_stage/platforms/linux" "$linux_stage/platforms/arch" "$linux_stage/adapters/sddm" "$linux_stage/scripts"
    GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -o "$linux_stage/bin/fplogin" ./cmd/fplogin
    GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -o "$linux_stage/bin/fplogin-platform-linux" ./cmd/fplogin-platform-linux
    GOOS=linux GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -o "$linux_stage/bin/fplogin-adapter-sddm" ./cmd/fplogin-adapter-sddm
    cp -f platforms/linux/platform.json "$linux_stage/platforms/linux/platform.json"
    cp -f platforms/arch/fplogin.sysusers "$linux_stage/platforms/arch/fplogin.sysusers"
    cp -f adapters/sddm/adapter.json "$linux_stage/adapters/sddm/adapter.json"
    cp -f scripts/install_linux.sh "$linux_stage/scripts/install_linux.sh"
    chmod 755 "$linux_stage/scripts/install_linux.sh"
    cp -f LICENSE README.md "$linux_stage/"
    tar --sort=name --mtime="@$sde" --owner=0 --group=0 --numeric-owner -C "$linux_stage" -cf - . \
        | GZIP=-n gzip -9 > "$out_dir/$linux_tar"
    touch -d "@$sde" "$out_dir/$linux_tar"
    rm -rf "$linux_stage"
    echo "Created generic Linux bundle: $linux_tar"
}
build_linux_bundle amd64 x86_64
build_linux_bundle arm64 aarch64

if [[ -z "$fplogin_pkg" ]]; then
    fplogin_pkg="$(ls -1t target/arch-package.*/fplogin-git-*-x86_64.pkg.tar.zst 2>/dev/null | grep -v -- '-debug-' | head -n1 || true)"
fi
if [[ -n "$fplogin_pkg" && -f "$fplogin_pkg" ]]; then
    cp -f "$fplogin_pkg" "$out_dir/$(basename "$fplogin_pkg")"
    echo "Included fplogin package: $(basename "$fplogin_pkg")"
else
    echo "WARN: no fplogin-git package found (pass --fplogin-pkg or run 'make package' first)" >&2
fi

if [[ -z "$sddm_pkg" ]]; then
    sddm_pkg="$(ls -1t .work/labs/sprint7/sddm-build/out-A/sddm-fplogin-*-x86_64.pkg.tar.zst 2>/dev/null | grep -v -- '-debug-' | head -n1 || true)"
fi
if [[ -n "$sddm_pkg" && -f "$sddm_pkg" ]]; then
    cp -f "$sddm_pkg" "$out_dir/$(basename "$sddm_pkg")"
    echo "Included sddm-fplogin package: $(basename "$sddm_pkg")"
else
    echo "WARN: no sddm-fplogin package found yet (pass --sddm-pkg when dual Qt6+Qt5 build completes)" >&2
fi

(
    cd "$out_dir"
    artifacts=()
    for f in *.tar.gz *.pkg.tar.zst; do
        [[ -f "$f" ]] && artifacts+=("$f")
    done
    if [[ ${#artifacts[@]} -eq 0 ]]; then
        echo "ERROR: no release artifacts staged in $out_dir" >&2
        exit 1
    fi
    sha256sum "${artifacts[@]}" > SHA256SUMS
    sha256sum -c SHA256SUMS

    if [[ -n "$gpg_key" ]]; then
        for f in "${artifacts[@]}" SHA256SUMS; do
            gpg --batch --yes --armor --detach-sign --local-user "$gpg_key" -o "${f}.asc" "$f"
            gpg --verify "${f}.asc" "$f"
        done
        echo "Signed and verified all artifacts with GPG key $gpg_key"
    else
        echo "Note: --gpg-key not specified; SHA256SUMS generated and verified. Pass --gpg-key <key-id> to create detached .asc signatures."
    fi
)

echo "Local release artifacts ready in: $out_dir"
