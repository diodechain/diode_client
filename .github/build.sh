#!/bin/bash
set -e
export DOCKER_DEFAULT_PLATFORM=linux/amd64

# Surface docker failures as Actions annotations. Job logs require admin.
emit_failure() {
  local log="$1"
  local line
  tail -n 40 "$log" | while IFS= read -r line; do
    line=${line//$'\r'/}
    line=${line//%/%25}
    printf '::error::%s\n' "$line"
  done
}

docker_build() {
  local tag="$1"
  local file="$2"
  local log
  log=$(mktemp)
  if ! docker build -t "$tag" -f "$file" .. >"$log" 2>&1; then
    cat "$log"
    emit_failure "$log"
    rm -f "$log"
    exit 1
  fi
  cat "$log"
  rm -f "$log"
}

docker_build pi-arm32 pi-arm32.dockerfile
docker run --rm --entrypoint cat pi-arm32 /build/diode_client/diode_linux_amd64.zip > diode_linux_arm.zip

docker_build pi-arm64 pi-arm64.dockerfile
docker run --rm --entrypoint cat pi-arm64 /build/diode_client/diode_linux_amd64.zip > diode_linux_arm64.zip

docker_build bullseye-amd64 bullseye-amd64.dockerfile
docker run --rm --entrypoint cat bullseye-amd64 /build/diode_client/diode_linux_amd64.zip > diode_linux_amd64_bullseye.zip