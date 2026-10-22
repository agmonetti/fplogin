#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== fplogin Packaging & Release Automation Verification ==="
echo "Repository Root: ${REPO_ROOT}"

# 1. Validate PKGBUILD syntax
echo "[1/4] Checking PKGBUILD syntax..."
bash -n "${REPO_ROOT}/platforms/arch/PKGBUILD"
echo "  -> PKGBUILD syntax is valid."

# 2. Build local binaries if needed
echo "[2/4] Ensuring binaries are built..."
make -C "${REPO_ROOT}" build

# 3. Simulate Package Installation into Staging Root
STAGING_DIR="${REPO_ROOT}/target/pkg_staging"
echo "[3/4] Simulating packaging into ${STAGING_DIR}..."
rm -rf "${STAGING_DIR}"
mkdir -p "${STAGING_DIR}/usr/bin"
mkdir -p "${STAGING_DIR}/usr/lib/fplogin/platforms"
mkdir -p "${STAGING_DIR}/usr/lib/fplogin/adapters"
mkdir -p "${STAGING_DIR}/usr/share/doc/fplogin"

# Install simulated artifacts
install -m755 "${REPO_ROOT}/bin/fplogin" "${STAGING_DIR}/usr/bin/fplogin"
install -m755 "${REPO_ROOT}/bin/fplogin-platform-arch" "${STAGING_DIR}/usr/lib/fplogin/platforms/arch"
install -m755 "${REPO_ROOT}/bin/fplogin-adapter-sddm" "${STAGING_DIR}/usr/lib/fplogin/adapters/sddm"
install -m644 "${REPO_ROOT}/platforms/arch/platform.json" "${STAGING_DIR}/usr/lib/fplogin/platforms/arch.json"
install -m644 "${REPO_ROOT}/adapters/sddm/adapter.json" "${STAGING_DIR}/usr/lib/fplogin/adapters/sddm.json"
install -m644 "${REPO_ROOT}/docs/EMERGENCY_RECOVERY.md" "${STAGING_DIR}/usr/share/doc/fplogin/EMERGENCY_RECOVERY.md"
install -m644 "${REPO_ROOT}/docs/SUPPORTED_VERSIONS.md" "${STAGING_DIR}/usr/share/doc/fplogin/SUPPORTED_VERSIONS.md"

# 4. Verify package integrity
echo "[4/4] Verifying staged package layout and executable permissions..."
test -x "${STAGING_DIR}/usr/bin/fplogin"
test -x "${STAGING_DIR}/usr/lib/fplogin/platforms/arch"
test -x "${STAGING_DIR}/usr/lib/fplogin/adapters/sddm"
test -f "${STAGING_DIR}/usr/lib/fplogin/platforms/arch.json"
test -f "${STAGING_DIR}/usr/lib/fplogin/adapters/sddm.json"
test -f "${STAGING_DIR}/usr/share/doc/fplogin/EMERGENCY_RECOVERY.md"

echo "=== Packaging Verification Passed Successfully ==="
ls -lR "${STAGING_DIR}"
