#!/bin/sh
# Verify a signed ittcsecscan release (ADR-0009).
#
# Usage: release/verify.sh [--partial] [--allowed-signers FILE] DIR
#
# DIR holds SHA256SUMS, SHA256SUMS.sig, and the downloaded assets. It passes
# only if:
#   1. SHA256SUMS.sig is a good OpenSSH signature over SHA256SUMS, in the
#      namespace ittcsecscan-release, by a key listed for the principal
#      ittcsecscan-release in the allowed-signers file. The default is
#      release/keys/allowed_signers next to this script. Take it from the
#      repository's main branch, never from the release being checked.
#   2. SHA256SUMS is well formed, and every ittcsecscan_* file in DIR is
#      listed in it.
#   3. Every listed asset is present and matches its hash. With --partial,
#      assets you did not download are skipped, but at least one must be
#      present.
#
# Needs OpenSSH 8.1 or later (ssh-keygen -Y verify). On Windows, use Git Bash.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

usage() {
	echo "usage: $0 [--partial] [--allowed-signers FILE] DIR" >&2
	exit 2
}

signers=$here/keys/allowed_signers
mode=strict
while [ $# -gt 0 ]; do
	case $1 in
	--partial)
		mode=partial
		shift
		;;
	--allowed-signers)
		[ $# -ge 2 ] || usage
		signers=$2
		shift 2
		;;
	--)
		shift
		break
		;;
	-*) usage ;;
	*) break ;;
	esac
done
[ $# -eq 1 ] || usage
dir=$1

command -v ssh-keygen >/dev/null 2>&1 || fail "ssh-keygen (OpenSSH 8.1 or later) is not on PATH"
release_keys "$signers" >/dev/null
[ -f "$dir/SHA256SUMS" ] || fail "no SHA256SUMS in $dir"
[ -f "$dir/SHA256SUMS.sig" ] || fail "no SHA256SUMS.sig in $dir: the release is not signed"

if ! out=$(ssh-keygen -Y verify -f "$signers" -I "$RELEASE_PRINCIPAL" -n "$RELEASE_NAMESPACE" \
	-s "$dir/SHA256SUMS.sig" <"$dir/SHA256SUMS" 2>&1); then
	printf '%s\n' "$out" | tr -cd '[:print:]\n' >&2
	fail "bad signature on SHA256SUMS"
fi
printf '%s\n' "$out"

check_sums "$dir" "$mode"
echo "verify: OK: good release signature, and the assets match SHA256SUMS"
