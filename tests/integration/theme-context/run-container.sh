#!/usr/bin/env bash
# Isolated context-only regression; never installs a theme or contacts a real daemon/reader.
set -euo pipefail
root=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
label=${1:?Usage: run-container.sh UNIQUE_LABEL}
[[ $label =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Invalid run label' >&2; exit 2; }
cd "$root"
evidence="$root/.work/evidence/sprint3-qt5/theme-contract-20261117/runs/$label"
build="$root/.work/build/sprint3-qt5/theme-contract-20261117"
theme="$root/.work/labs/sprint3/theme-contract-runs/$label"
image=sha256:0ccf97570aa91d4d68ea7f2800d33b23df983290ea5ad86c9f5ba6c1c1ab254b
source="$root/.work/sddm/sprint3-qt5"
constants="$root/.work/build/sprint3-qt5/qt5/src/common"
components="$root/.work/labs/sprint3/e6-qt5-openssl3/inspection/candidate/usr/lib/qt/qml/SddmComponents"
[[ -f $constants/Constants.h && -f $components/qmldir ]] || { echo 'Pinned build constants/components unavailable' >&2; exit 3; }
[[ ! -e $evidence && ! -e $theme ]] || { echo 'Run label already used; refusing overwrite' >&2; exit 4; }
mkdir -p "$(dirname -- "$evidence")" "$(dirname -- "$theme")" "$build"
mkdir "$evidence"
python3 tests/integration/theme-context/prepare.py "$theme" > "$evidence/prepare.log" 2>&1
printf '%s\n' "$image" > "$evidence/image.id"
git -C "$source" rev-parse HEAD > "$evidence/sddm-source.txt"
git -C "$source" diff --exit-code > "$evidence/sddm-source.diff"
sha256sum adapters/sddm/integrations/where-is-my-sddm-qt5/* tests/integration/theme-context/*.{py,cpp,sh,txt} > "$evidence/inputs.sha256"
docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" \
    --env QT_QPA_PLATFORM=xcb --env QT_QUICK_BACKEND=software --env QT_QUICK_CONTROLS_STYLE=Basic \
    --env DISPLAY=:99 --env XDG_RUNTIME_DIR=/tmp/runtime \
    --env THEME_CONTEXT_ORIGINAL=/original --env THEME_CONTEXT_ADAPTED=/adapted --env THEME_CONTEXT_EVIDENCE=/evidence \
    --mount "type=bind,src=$root/tests/integration/theme-context,dst=/tests,readonly" \
    --mount "type=bind,src=$source,dst=/src,readonly" \
    --mount "type=bind,src=$constants,dst=/constants,readonly" \
    --mount "type=bind,src=$components,dst=/usr/lib/qt/qml/SddmComponents,readonly" \
    --mount "type=bind,src=$root/tests/fixtures/themes/where-is-my-sddm-qt5,dst=/original,readonly" \
    --mount "type=bind,src=$theme,dst=/adapted,readonly" \
    --mount "type=bind,src=$build,dst=/build" \
    --mount "type=bind,src=$evidence,dst=/evidence" \
    --entrypoint /bin/bash "$image" -c '
set -euo pipefail
run() {
    label=$1; shift
    printf "%s\n" "$*" > "/evidence/$label.command"
    if "$@" > "/evidence/$label.log" 2>&1; then rc=0; else rc=$?; fi
    printf "%s\n" "$rc" > "/evidence/$label.exit"
    if (( rc != 0 )); then tail -80 "/evidence/$label.log"; exit "$rc"; fi
}
run configure cmake -S /tests -B /build -DSDDM_SOURCE_ROOT=/src -DSDDM_CONSTANTS_DIR=/constants
run build cmake --build /build --parallel 4
mkdir -m 700 /tmp/runtime
Xvfb :99 -screen 0 1024x768x24 -nolisten tcp -noreset > /evidence/xvfb.log 2>&1 & xvfb=$!
trap "kill $xvfb 2>/dev/null || true" EXIT
for i in $(seq 1 50); do
    if test -S /tmp/.X11-unix/X99; then break; fi
    sleep 0.1
done
run ctest ctest --test-dir /build --output-on-failure --no-tests=error
cp /build/Testing/Temporary/LastTest.log /evidence/test-detail.log
'
printf 'Evidence: %s\n' "$evidence"
