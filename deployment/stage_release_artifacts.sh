#!/bin/bash
set -euo pipefail

# Map CI artifact downloads to final release assets (same output as extract.exs).
ARTIFACTS_ROOT="${1:-./artifacts}"
OUT_DIR="${2:-./release-staging/out}"

DIST_ZIPS=(
  diode_windows_amd64.zip
  diode_darwin_arm64.zip
  diode_darwin_amd64.zip
)

require_dir() {
  if [ ! -d "$1" ]; then
    echo "missing artifact directory: $1" >&2
    exit 1
  fi
}

zip_dist_artifact() {
  local name="$1"
  local src="${ARTIFACTS_ROOT}/${name}"
  local dst="${OUT_DIR}/${name}"

  require_dir "$src"
  if [ -z "$(find "$src" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "empty artifact directory: $src" >&2
    exit 1
  fi

  rm -f "$dst"
  (cd "$src" && zip -1 -j "$dst" ./*)
}

copy_pkg_artifact() {
  local artifact_name="$1"
  local out_name="$2"
  local src="${ARTIFACTS_ROOT}/${artifact_name}"
  local pkg

  require_dir "$src"
  pkg="$(find "$src" -maxdepth 1 -name '*.pkg' | head -n 1)"
  if [ -z "$pkg" ]; then
    echo "missing pkg in artifact directory: $src" >&2
    exit 1
  fi

  cp "$pkg" "${OUT_DIR}/${out_name}"
}

unzip_linux_artifact() {
  local artifact_name="$1"
  local out_name="$2"
  local zip_file="${ARTIFACTS_ROOT}/${artifact_name}/${artifact_name}"

  require_dir "${ARTIFACTS_ROOT}/${artifact_name}"
  if [ ! -f "$zip_file" ]; then
    echo "missing zip file: $zip_file" >&2
    exit 1
  fi

  unzip -p "$zip_file" > "${OUT_DIR}/${out_name}"
}

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

for name in "${DIST_ZIPS[@]}"; do
  zip_dist_artifact "$name"
done

copy_pkg_artifact macOS-ARM64 diode_darwin_arm64.pkg
copy_pkg_artifact macOS-X64 diode_darwin_amd64.pkg

unzip_linux_artifact diode_linux_arm.zip diode_linux_arm.zip
unzip_linux_artifact diode_linux_arm64.zip diode_linux_arm64.zip
unzip_linux_artifact diode_linux_amd64_bullseye.zip diode_linux_amd64.zip

echo "release artifacts in ${OUT_DIR}"
