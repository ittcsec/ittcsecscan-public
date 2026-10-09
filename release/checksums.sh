#!/bin/sh
# Write DIR/SHA256SUMS over every ittcsecscan_* asset in DIR, in the one
# format the release scripts accept: "<hash>  <name>", byte order.
#
# Usage: release/checksums.sh DIR
set -eu
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

[ $# -eq 1 ] || {
	echo "usage: $0 DIR" >&2
	exit 2
}
write_sums "$1"
cat "$1/SHA256SUMS"
