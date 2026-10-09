#!/bin/sh
# Reproducible build of the ittcsecscan CLI.
#
# Usage: release/build.sh VERSION OUTDIR [GOOS/GOARCH ...]
#
# Every input that influences the output is fixed or explicit:
#   toolchain      go.mod toolchain line; GOTOOLCHAIN=local refuses any other
#   environment    CGO_ENABLED=0, GOAMD64=v1, GOARM64=v8.0, no GOEXPERIMENT
#   paths          -trimpath; build ID emptied
#   VCS stamping   -buildvcs=false; identity injected explicitly below
#   build time     SOURCE_DATE_EPOCH (required), never the wall clock
#   commit/tree    from git, or COMMIT / TREE_STATE when git is unavailable
#
# Two builds of the same source must be byte-identical. CI proves it by
# building in two different directories and comparing SHA256SUMS.
#
# Besides the binaries, OUTDIR gets ittcsecscan_VERSION_buildinfo.txt (the
# inputs above, so release/sign.sh can rebuild the same thing) and SHA256SUMS.
# Signing is a separate, offline step (ADR-0009, release/sign.sh).
set -eu
LC_ALL=C
export LC_ALL

usage() {
	echo "usage: $0 VERSION OUTDIR [GOOS/GOARCH ...]" >&2
	exit 2
}

[ $# -ge 2 ] || usage
version=$1
outdir=$2
shift 2

case "$version" in
'' | *[!0-9A-Za-z.+-]*)
	echo "invalid VERSION: must match [0-9A-Za-z.+-]+" >&2
	exit 2
	;;
esac

: "${SOURCE_DATE_EPOCH:?must be set, e.g. SOURCE_DATE_EPOCH=\$(git log -1 --format=%ct)}"
case "$SOURCE_DATE_EPOCH" in
'' | *[!0-9]*)
	echo "SOURCE_DATE_EPOCH must be a positive integer" >&2
	exit 2
	;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

in_git=false
if git rev-parse --git-dir >/dev/null 2>&1; then
	in_git=true
fi

if [ -z "${COMMIT:-}" ]; then
	if $in_git; then COMMIT=$(git rev-parse HEAD); else COMMIT=unknown; fi
fi
case "$COMMIT" in
'' | *[!0-9A-Za-z]*)
	echo "COMMIT must be alphanumeric" >&2
	exit 2
	;;
esac

if [ -z "${TREE_STATE:-}" ]; then
	if $in_git; then
		if [ -n "$(git status --porcelain)" ]; then TREE_STATE=modified; else TREE_STATE=clean; fi
	else
		TREE_STATE=unknown
	fi
fi
case "$TREE_STATE" in
clean | modified | unknown) ;;
*)
	echo "TREE_STATE must be clean, modified, or unknown" >&2
	exit 2
	;;
esac
if [ "$TREE_STATE" = modified ] && [ "${ALLOW_DIRTY:-0}" != 1 ]; then
	echo "refusing to build from a modified tree (ALLOW_DIRTY=1 for local testing only)" >&2
	exit 1
fi

if [ $# -eq 0 ]; then
	set -- linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
fi

pkg=github.com/ittcsec/ittcsecscan/internal/version
ldflags="-s -w -buildid= -X $pkg.version=$version -X $pkg.commit=$COMMIT -X $pkg.sourceDateEpoch=$SOURCE_DATE_EPOCH -X $pkg.treeState=$TREE_STATE"

mkdir -p "$outdir"
for target in "$@"; do
	goos=${target%/*}
	goarch=${target#*/}
	ext=
	[ "$goos" = windows ] && ext=.exe
	name="ittcsecscan_${version}_${goos}_${goarch}${ext}"
	echo "building $name" >&2
	# Build from the vendored dependencies (ADR-0017): the release compiles only
	# in-tree code, with no module download.
	env CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOAMD64=v1 GOARM64=v8.0 \
		GOEXPERIMENT= GOFLAGS=-mod=vendor GOTOOLCHAIN=local \
		go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$outdir/$name" ./cmd/ittcsecscan
done

# Build info. It is covered by SHA256SUMS and therefore by the release
# signature, and release/sign.sh reads it to rebuild the same commit.
{
	echo "version=$version"
	echo "commit=$COMMIT"
	echo "source_date_epoch=$SOURCE_DATE_EPOCH"
	echo "tree_state=$TREE_STATE"
	echo "go=$(env GOTOOLCHAIN=local go env GOVERSION)"
	echo "targets=$*"
} >"$outdir/ittcsecscan_${version}_buildinfo.txt"

sh "$root/release/checksums.sh" "$outdir"
