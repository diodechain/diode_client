#!/bin/bash
set -euo pipefail

TAG="${1:-${GITHUB_REF_NAME:-}}"
if [ -z "$TAG" ]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

PREV="$(git describe --tags --abbrev=0 "${TAG}^" 2>/dev/null || true)"
if [ -n "$PREV" ]; then
  git log "${PREV}..${TAG}" --pretty=format:'%h %s'
else
  git log "$TAG" --pretty=format:'%h %s'
fi
