#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
go test ./...
go test -race ./...
go vet ./...
node internal/ui/frontend_test.cjs
sh scripts/build-windows.sh
if [ "$(uname -s)" = Darwin ]; then
    sh scripts/build-local.sh
fi
