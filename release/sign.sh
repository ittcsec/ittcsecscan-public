#!/bin/sh
# Offline release signing (ADR-0009). The maintainer runs this on their own
# machine; the release key never goes near CI or GitHub.
#
# Usage: release/sign.sh [--allowed-signers FILE] DIR KEY
#
#   DIR  the assets the release workflow built, downloaded unchanged:
#          gh release download vX.Y.Z --repo ittcsec/ittcsecscan-public --dir DIR
#        or, for a dry run, from a workflow run:
#          gh run download RUN_ID --repo ittcsec/ittcsecscan-public -n release-assets --dir DIR
#   KEY  the private release key. KEY.pub must sit next to it.
#
# SHA256SUMS is signed only if every check passes:
#   1. KEY.pub is a release key in release/keys/allowed_signers.
#   2. DIR is a complete release, and every asset matches SHA256SUMS.
#   3. The build info names a commit in this clone (and, for a real release,
#      the commit its tag points to), built from a clean tree with the Go
#      version installed here.
#   4. Every binary and the build info, rebuilt here from that commit in a
#      fresh worktree with an empty build cache, is byte-identical to the
#      downloaded ones. A signature therefore means "independently
#      reproduced", and a compromised CI runner cannot obtain one. The SBOMs and
#      the SLSA provenance are signed as CI produced them; they are not rebuilt
#      (they describe the build rather than being an output of it), but the
#      offline signature over SHA256SUMS still covers their content.
# Then ssh-keygen asks for the key's passphrase and writes DIR/SHA256SUMS.sig,
# and release/verify.sh checks the result. Nothing is uploaded.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
. "$here/lib.sh"

usage() {
	echo "usage: $0 [--allowed-signers FILE] DIR KEY" >&2
	exit 2
}

signers=$here/keys/allowed_signers
while [ $# -gt 0 ]; do
	case $1 in
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
[ $# -eq 2 ] || usage
dir=$1
key=$2

for tool in git go ssh-keygen; do
	command -v "$tool" >/dev/null 2>&1 || fail "$tool is not on PATH"
done

# 1. The key: checked first, so a wrong key fails before any work.
[ -f "$key" ] || fail "private key not found: $key"
[ -f "$key.pub" ] || fail "public key not found: $key.pub"
pub=$(cut -d' ' -f1,2 "$key.pub")
keys=$(release_keys "$signers")
printf '%s\n' "$keys" | grep -qxF -- "$pub" || fail "$key.pub is not a release key in $signers"
[ ! -e "$dir/SHA256SUMS.sig" ] || fail "$dir/SHA256SUMS.sig already exists"

# 2. The downloaded assets.
echo "== checking the downloaded assets against SHA256SUMS" >&2
check_sums "$dir" strict >&2

# 3. The build info.
set -- "$dir"/ittcsecscan_*_buildinfo.txt
[ $# -eq 1 ] && [ -f "$1" ] || fail "expected exactly one ittcsecscan_*_buildinfo.txt in $dir"
info=$1
field() {
	[ "$(grep -Ec "^$1=" "$info")" = 1 ] || fail "build info: expected exactly one $1= line"
	grep -E "^$1=" "$info" | cut -d= -f2-
}
version=$(field version)
commit=$(field commit)
epoch=$(field source_date_epoch)
tree=$(field tree_state)
gover=$(field go)
targets=$(field targets)

printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?' || fail "build info: bad version"
[ "$info" = "$dir/ittcsecscan_${version}_buildinfo.txt" ] || fail "build info: file name does not match version $version"
printf '%s\n' "$commit" | grep -Eqx '[0-9a-f]{40}' || fail "build info: bad commit"
printf '%s\n' "$epoch" | grep -Eqx '[0-9]+' || fail "build info: bad source_date_epoch"
printf '%s\n' "$targets" | grep -Eqx '[a-z0-9]+/[a-z0-9]+( [a-z0-9]+/[a-z0-9]+)*' || fail "build info: bad targets"
[ "$tree" = clean ] || fail "build info: CI built from a $tree tree; refusing to sign"
localgo=$(env GOTOOLCHAIN=local go env GOVERSION)
[ "$gover" = "$localgo" ] || fail "CI built with $gover but this machine has $localgo"
git -C "$root" cat-file -e "$commit^{commit}" 2>/dev/null ||
	fail "commit $commit is not in this clone; run: git fetch origin $commit"
[ "$(git -C "$root" log -1 --format=%ct "$commit")" = "$epoch" ] ||
	fail "build info: source_date_epoch is not the commit time of $commit"
case $version in
0.0.0-dryrun) ;; # pull-request dry runs have no tag
*)
	tagged=$(git -C "$root" rev-parse -q --verify "refs/tags/v$version^{commit}") ||
		fail "tag v$version is not in this clone; run: git fetch origin tag v$version"
	[ "$tagged" = "$commit" ] || fail "tag v$version points to $tagged, but CI built $commit"
	;;
esac

# 4. Rebuild and compare. The work directory sits inside the repository (the
# maintainer's owner-only folder), not in a shared temporary directory.
echo "== rebuilding $version from $commit in a fresh worktree with an empty build cache" >&2
work=$(mktemp -d "$root/.release-work.XXXXXX")
cleanup() {
	git -C "$root" worktree remove --force "$work/src" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
git -C "$root" worktree add --quiet --detach "$work/src" "$commit"
# $targets is validated above and split on purpose.
# shellcheck disable=SC2086
(cd "$work/src" && SOURCE_DATE_EPOCH=$epoch GOCACHE=$work/gocache ./release/build.sh "$version" "$work/out" $targets) >&2

grep -Ev '(\.cdx\.json|_provenance\.json)$' "$dir/SHA256SUMS" >"$work/ci.sums"
if ! cmp -s "$work/ci.sums" "$work/out/SHA256SUMS"; then
	echo "downloaded (<) versus rebuilt here (>):" >&2
	diff "$work/ci.sums" "$work/out/SHA256SUMS" >&2 || true
	fail "the rebuild does not match the downloaded assets; do not sign"
fi
echo "== reproduced: all $(wc -l <"$work/ci.sums" | tr -d ' ') files (binaries and build info) are byte-identical" >&2

# 5. Sign, then verify exactly as a user would.
echo "== signing $dir/SHA256SUMS: ssh-keygen asks for the release key's passphrase" >&2
ssh-keygen -q -Y sign -f "$key" -n "$RELEASE_NAMESPACE" "$dir/SHA256SUMS"
sh "$here/verify.sh" --allowed-signers "$signers" "$dir"
echo "== signed: $dir/SHA256SUMS.sig (next step: release/README.md)" >&2
