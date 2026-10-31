#!/bin/sh
# Prepare the native Mac review release. This does not install or launch it.
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
exec sh scripts/package-macos-desktop.sh
