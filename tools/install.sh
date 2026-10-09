#!/bin/sh
# Builds the pinned development tools into ./bin.
#
# Each tool lives in its own module under tools/<name>/ so that its dependency
# graph is exactly the one its maintainers tested (a shared module forces one
# version of every transitive dependency on all tools and breaks some of them),
# and every download is verified against go.sum and the Go checksum database.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
GOBIN="$root/bin"
export GOBIN
GOFLAGS=-mod=readonly
export GOFLAGS

for dir in "$root"/tools/*/; do
	[ -f "${dir}go.mod" ] || continue
	echo "building $(basename "$dir")" >&2
	go -C "$dir" install tool
done
