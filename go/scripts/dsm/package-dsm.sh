#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
GO_DIR="$ROOT_DIR/go"
FRONTEND_DIR="$ROOT_DIR/frontend"
VERSION=$("$GO_DIR/scripts/dsm/version.sh")
ALLOW_MULTIPLE_IDENTITY_SOURCES=${DSMPASS_ALLOW_MULTIPLE_IDENTITY_SOURCES:-1}
case "$ALLOW_MULTIPLE_IDENTITY_SOURCES" in
  1|true|TRUE)
    ALLOW_MULTIPLE_IDENTITY_SOURCES=true
    ;;
  0|false|FALSE)
    ALLOW_MULTIPLE_IDENTITY_SOURCES=false
    ;;
  *)
    echo "DSMPASS_ALLOW_MULTIPLE_IDENTITY_SOURCES must be 1, 0, true, or false" >&2
    exit 1
    ;;
esac
LDFLAGS="-s -w -X github.com/dsmpass/dsmpass/go/internal/buildinfo.Version=$VERSION -X github.com/dsmpass/dsmpass/go/internal/buildinfo.FrontendVersion=$VERSION -X github.com/dsmpass/dsmpass/go/internal/buildinfo.AllowMultipleIdentitySources=$ALLOW_MULTIPLE_IDENTITY_SOURCES"
export GOCACHE="${GOCACHE:-$GO_DIR/.gocache}"
export GOMODCACHE="${GOMODCACHE:-$GO_DIR/.gomodcache}"

cd "$FRONTEND_DIR"
npm run build

cd "$GO_DIR"
rm -rf dist/dsm/package-linux-amd64 dist/dsm/package-linux-arm64
mkdir -p dist/dsm/package-linux-amd64/bin dist/dsm/package-linux-amd64/frontend
mkdir -p dist/dsm/package-linux-arm64/bin dist/dsm/package-linux-arm64/frontend

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath "-ldflags=$LDFLAGS" -o dist/dsm/package-linux-amd64/bin/dsmpass-backend ./cmd/backend
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath "-ldflags=$LDFLAGS" -o dist/dsm/package-linux-amd64/bin/dsmpass-helper ./cmd/helper
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath "-ldflags=$LDFLAGS" -o dist/dsm/package-linux-arm64/bin/dsmpass-backend ./cmd/backend
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath "-ldflags=$LDFLAGS" -o dist/dsm/package-linux-arm64/bin/dsmpass-helper ./cmd/helper

rm -rf dist/dsm/package-linux-amd64/frontend/dist dist/dsm/package-linux-arm64/frontend/dist
cp -R "$FRONTEND_DIR/dist" dist/dsm/package-linux-amd64/frontend/dist
cp -R "$FRONTEND_DIR/dist" dist/dsm/package-linux-arm64/frontend/dist
cp scripts/dsm/start-dsmpass.sh dist/dsm/package-linux-amd64/start-dsmpass.sh
cp scripts/dsm/start-dsmpass.sh dist/dsm/package-linux-arm64/start-dsmpass.sh
cp scripts/dsm/helper-control.sh dist/dsm/package-linux-amd64/helper-control.sh
cp scripts/dsm/helper-control.sh dist/dsm/package-linux-arm64/helper-control.sh
cp scripts/dsm/setup-helper-sudo.sh dist/dsm/package-linux-amd64/setup-helper-sudo.sh
cp scripts/dsm/setup-helper-sudo.sh dist/dsm/package-linux-arm64/setup-helper-sudo.sh
printf '%s\n' "$VERSION" > dist/dsm/package-linux-amd64/VERSION
printf '%s\n' "$VERSION" > dist/dsm/package-linux-arm64/VERSION

chmod +x dist/dsm/package-linux-amd64/start-dsmpass.sh dist/dsm/package-linux-amd64/helper-control.sh dist/dsm/package-linux-amd64/setup-helper-sudo.sh dist/dsm/package-linux-amd64/bin/dsmpass-backend dist/dsm/package-linux-amd64/bin/dsmpass-helper
chmod +x dist/dsm/package-linux-arm64/start-dsmpass.sh dist/dsm/package-linux-arm64/helper-control.sh dist/dsm/package-linux-arm64/setup-helper-sudo.sh dist/dsm/package-linux-arm64/bin/dsmpass-backend dist/dsm/package-linux-arm64/bin/dsmpass-helper

tar -czf dist/dsm/dsmpass-linux-amd64.tar.gz -C dist/dsm/package-linux-amd64 .
tar -czf dist/dsm/dsmpass-linux-arm64.tar.gz -C dist/dsm/package-linux-arm64 .

echo "version: $VERSION"
echo "allow multiple identity sources: $ALLOW_MULTIPLE_IDENTITY_SOURCES"
echo "amd64: $GO_DIR/dist/dsm/dsmpass-linux-amd64.tar.gz"
echo "arm64: $GO_DIR/dist/dsm/dsmpass-linux-arm64.tar.gz"
