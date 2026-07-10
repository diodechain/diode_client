#!/bin/bash
set -euo pipefail

ARTIFACTS_ROOT="${1:-./artifacts}"
STAGING_DIR="${2:-./release-staging}"

DIST_ZIPS=(
  diode_windows_amd64.zip
  diode_darwin_arm64.zip
  diode_darwin_amd64.zip
)

LINUX_ZIPS=(
  diode_linux_arm.zip
  diode_linux_arm64.zip
  diode_linux_amd64_bullseye.zip
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
  local dst="${STAGING_DIR}/${name}"

  require_dir "$src"
  if [ ! "$(find "$src" -mindepth 1 -maxdepth 1 | wc -l)" -gt 0 ]; then
    echo "empty artifact directory: $src" >&2
    exit 1
  fi

  rm -f "$dst"
  (cd "$src" && zip -1 -j "$dst" ./*)
}

zip_pkg_artifact() {
  local artifact_name="$1"
  local zip_name="$2"
  local src="${ARTIFACTS_ROOT}/${artifact_name}"
  local dst="${STAGING_DIR}/${zip_name}"
  local pkg

  require_dir "$src"
  pkg="$(find "$src" -maxdepth 1 -name '*.pkg' | head -n 1)"
  if [ -z "$pkg" ]; then
    echo "missing pkg in artifact directory: $src" >&2
    exit 1
  fi

  rm -f "$dst"
  zip -1 -j "$dst" "$pkg"
}

copy_zip_artifact() {
  local name="$1"
  local src_dir="${ARTIFACTS_ROOT}/${name}"
  local src_file="${src_dir}/${name}"
  local dst="${STAGING_DIR}/${name}"

  require_dir "$src_dir"
  if [ ! -f "$src_file" ]; then
    echo "missing zip file: $src_file" >&2
    exit 1
  fi

  cp "$src_file" "$dst"
}

mkdir -p "$STAGING_DIR"
STAGING_DIR="$(cd "$STAGING_DIR" && pwd)"

for name in "${DIST_ZIPS[@]}"; do
  zip_dist_artifact "$name"
done

zip_pkg_artifact macOS-ARM64 macOS-ARM64.zip
zip_pkg_artifact macOS-X64 macOS-X64.zip

for name in "${LINUX_ZIPS[@]}"; do
  copy_zip_artifact "$name"
done

echo "staged release artifacts in ${STAGING_DIR}"
