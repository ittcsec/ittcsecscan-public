#!/bin/sh
# Tests for the release signing scripts, with throwaway keys (ADR-0009), and a
# check of the committed trust root, release/keys/allowed_signers.
#
# Usage: release/signing_test.sh
#
# CI runs it in the release-prep job. Needs OpenSSH 8.1 or later, git, and go.
# The full signing path, including the rebuild, runs in the release
# workflow's pull-request dry run.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
. "$here/lib.sh"

t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
count=0
failures=0

# case NAME ok|fail:MESSAGE COMMAND...: COMMAND must succeed, or must fail with
# MESSAGE in its output.
case_() {
	_name=$1
	_want=$2
	shift 2
	count=$((count + 1))
	if "$@" >"$t/out" 2>&1; then _got=ok; else _got=fail; fi
	case $_want in
	ok) [ "$_got" = ok ] ;;
	fail:*) [ "$_got" = fail ] && grep -qF -- "${_want#fail:}" "$t/out" ;;
	esac && {
		echo "ok   $_name"
		return 0
	}
	failures=$((failures + 1))
	echo "FAIL $_name: wanted $_want, got $_got"
	sed 's/^/     | /' "$t/out"
}

verify() { sh "$here/verify.sh" --allowed-signers "$t/signers" "$@"; }
sign() { sh "$here/sign.sh" --allowed-signers "$t/signers" "$@"; }

ssh-keygen -q -t ed25519 -N '' -C throwaway-release -f "$t/release"
ssh-keygen -q -t ed25519 -N '' -C throwaway-other -f "$t/other"
printf '%s namespaces="%s" %s\n' "$RELEASE_PRINCIPAL" "$RELEASE_NAMESPACE" \
	"$(cut -d' ' -f1,2 "$t/release.pub")" >"$t/signers"
gover=$(env GOTOOLCHAIN=local go env GOVERSION)

# resign NAME [KEY [NAMESPACE]]: replace NAME's signature.
resign() {
	rm -f "$t/$1/SHA256SUMS.sig"
	ssh-keygen -q -Y sign -f "$t/${2:-release}" -n "${3:-$RELEASE_NAMESPACE}" "$t/$1/SHA256SUMS"
}

# fixture NAME [COMMIT [TREE_STATE]]: a complete release signed by the
# throwaway release key.
fixture() {
	_d=$t/$1
	mkdir "$_d"
	printf 'linux binary\n' >"$_d/ittcsecscan_0.0.0-test_linux_amd64"
	printf 'linux sbom\n' >"$_d/ittcsecscan_0.0.0-test_linux_amd64.cdx.json"
	printf 'windows binary\n' >"$_d/ittcsecscan_0.0.0-test_windows_amd64.exe"
	printf 'version=0.0.0-test\ncommit=%s\nsource_date_epoch=1\ntree_state=%s\ngo=%s\ntargets=linux/amd64 windows/amd64\n' \
		"${2:-0000000000000000000000000000000000000000}" "${3:-clean}" "$gover" \
		>"$_d/ittcsecscan_0.0.0-test_buildinfo.txt"
	write_sums "$_d"
	resign "$1"
}

win=ittcsecscan_0.0.0-test_windows_amd64.exe
lin=ittcsecscan_0.0.0-test_linux_amd64

echo "== verify.sh"
fixture good
case_ "good release verifies" ok verify "$t/good"

fixture missing
rm "$t/missing/$win"
case_ "missing asset fails" "fail:listed asset is missing: $win" verify "$t/missing"
case_ "missing asset passes with --partial" ok verify --partial "$t/missing"

fixture none
rm "$t/none"/ittcsecscan_*
case_ "--partial still needs one asset" "fail:none of the listed assets" verify --partial "$t/none"

fixture tampered
printf 'x' >>"$t/tampered/$lin"
case_ "tampered binary fails" "fail:checksum mismatch: $lin" verify "$t/tampered"

fixture resummed
printf 'x' >>"$t/resummed/$lin"
write_sums "$t/resummed"
case_ "SHA256SUMS changed after signing fails" "fail:bad signature" verify "$t/resummed"

fixture extra
printf 'evil\n' >"$t/extra/ittcsecscan_0.0.0-test_evil"
case_ "unlisted asset fails" "fail:asset not listed" verify "$t/extra"
case_ "unlisted asset fails with --partial" "fail:asset not listed" verify --partial "$t/extra"

fixture stray
printf 'notes\n' >"$t/stray/notes.txt"
case_ "unexpected file fails" "fail:unexpected file" verify "$t/stray"
case_ "unexpected file allowed with --partial" ok verify --partial "$t/stray"

fixture unsigned
rm "$t/unsigned/SHA256SUMS.sig"
case_ "unsigned release fails" "fail:the release is not signed" verify "$t/unsigned"

fixture otherkey
resign otherkey other
case_ "signature by another key fails" "fail:bad signature" verify "$t/otherkey"

fixture wrongns
resign wrongns release file
case_ "signature for another namespace fails" "fail:bad signature" verify "$t/wrongns"

fixture garbage
printf 'not a signature\n' >"$t/garbage/SHA256SUMS.sig"
case_ "garbage signature fails" "fail:bad signature" verify "$t/garbage"

fixture traversal
printf '%064d  ../escape\n' 0 >>"$t/traversal/SHA256SUMS"
resign traversal
case_ "signed path traversal fails" "fail:is malformed" verify "$t/traversal"

fixture crlf
awk '{ printf "%s\r\n", $0 }' "$t/crlf/SHA256SUMS" >"$t/crlf.tmp"
mv "$t/crlf.tmp" "$t/crlf/SHA256SUMS"
resign crlf
case_ "signed CRLF SHA256SUMS fails" "fail:contains carriage returns" verify "$t/crlf"

fixture dup
head -n 1 "$t/dup/SHA256SUMS" >>"$t/dup/SHA256SUMS"
resign dup
case_ "signed duplicate entry fails" "fail:lists an asset twice" verify "$t/dup"

fixture empty
: >"$t/empty/SHA256SUMS"
resign empty
case_ "signed empty SHA256SUMS fails" "fail:missing or empty" verify "$t/empty"

fixture nonl
printf '%s' "$(cat "$t/nonl/SHA256SUMS")" >"$t/nonl.tmp"
mv "$t/nonl.tmp" "$t/nonl/SHA256SUMS"
resign nonl
printf 'x' >>"$t/nonl/$win"
case_ "last line without newline is still checked" "fail:checksum mismatch: $win" verify "$t/nonl"

fixture notfile
rm "$t/notfile/$win"
mkdir "$t/notfile/$win"
case_ "listed asset that is a directory fails" "fail:not a regular file" verify "$t/notfile"

echo "== trust root"
printf 'someone-else namespaces="%s" %s\n' "$RELEASE_NAMESPACE" "$(cut -d' ' -f1,2 "$t/release.pub")" >"$t/signers-principal"
case_ "key for another principal is rejected" "fail:every entry must read" \
	sh "$here/verify.sh" --allowed-signers "$t/signers-principal" "$t/good"
printf '%s %s\n' "$RELEASE_PRINCIPAL" "$(cut -d' ' -f1,2 "$t/release.pub")" >"$t/signers-nons"
case_ "key without the namespace restriction is rejected" "fail:every entry must read" \
	sh "$here/verify.sh" --allowed-signers "$t/signers-nons" "$t/good"
printf '# no keys\n' >"$t/signers-empty"
case_ "allowed-signers without keys is rejected" "fail:every entry must read" \
	sh "$here/verify.sh" --allowed-signers "$t/signers-empty" "$t/good"

# The committed file: well formed, and every key parses.
trust_root_ok() (
	release_keys "$here/keys/allowed_signers" >"$t/keys"
	while read -r _type _key; do
		printf '%s %s\n' "$_type" "$_key" >"$t/one.pub"
		ssh-keygen -l -f "$t/one.pub"
	done <"$t/keys"
)
case_ "committed release/keys/allowed_signers is valid" ok trust_root_ok

echo "== sign.sh refusals (before any rebuild or passphrase prompt)"
fixture s-key
rm "$t/s-key/SHA256SUMS.sig"
case_ "sign: key not in the trust root" "fail:is not a release key" sign "$t/s-key" "$t/other"
case_ "sign: already signed" "fail:already exists" sign "$t/good" "$t/release"

fixture s-tampered
rm "$t/s-tampered/SHA256SUMS.sig"
printf 'x' >>"$t/s-tampered/$lin"
case_ "sign: tampered asset" "fail:checksum mismatch" sign "$t/s-tampered" "$t/release"

fixture s-dirty 0000000000000000000000000000000000000000 modified
rm "$t/s-dirty/SHA256SUMS.sig"
case_ "sign: modified tree" "fail:refusing to sign" sign "$t/s-dirty" "$t/release"

fixture s-commit
rm "$t/s-commit/SHA256SUMS.sig"
case_ "sign: commit not in the clone" "fail:is not in this clone" sign "$t/s-commit" "$t/release"

fixture s-noinfo
rm "$t/s-noinfo/SHA256SUMS.sig" "$t/s-noinfo/ittcsecscan_0.0.0-test_buildinfo.txt"
write_sums "$t/s-noinfo"
case_ "sign: no build info" "fail:exactly one ittcsecscan_*_buildinfo.txt" sign "$t/s-noinfo" "$t/release"

echo "$count cases, $failures failed"
[ "$failures" -eq 0 ]
