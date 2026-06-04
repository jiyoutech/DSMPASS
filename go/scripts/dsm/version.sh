#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)

if [ -n "${DSMPASS_VERSION:-}" ]; then
  printf '%s\n' "$DSMPASS_VERSION"
  exit 0
fi

base_version() {
  package_json="$ROOT_DIR/frontend/package.json"
  if [ -f "$package_json" ]; then
    sed -n 's/^[[:space:]]*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$package_json" | sed -n '1p'
    return
  fi
  printf '0.0.0\n'
}

git_dirty() {
  if ! git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 1
  fi
  [ -n "$(git -C "$ROOT_DIR" status --porcelain -- "$ROOT_DIR" 2>/dev/null)" ]
}

if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  tag=$(git -C "$ROOT_DIR" describe --tags --exact-match 2>/dev/null || true)
  if [ -n "$tag" ] && ! git_dirty; then
    printf '%s\n' "${tag#v}"
    exit 0
  fi
  sha=$(git -C "$ROOT_DIR" rev-parse --short=12 HEAD 2>/dev/null || true)
else
  sha=""
fi

if [ -z "$sha" ]; then
  sha="unknown"
fi

version="$(base_version)-dev.$sha"
if git_dirty; then
  version="$version.dirty"
fi
printf '%s\n' "$version"
