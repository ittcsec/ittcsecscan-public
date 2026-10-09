# Shared by the release scripts. Sourced, never run. POSIX sh.
#
# Release signature (ADR-0009): an OpenSSH signature (ssh-keygen -Y sign) over
# SHA256SUMS, in the namespace below, by a key listed for the principal below
# in release/keys/allowed_signers. The namespace keeps a release signature
# from being valid for anything else (git commits, other files) and the other
# way round.

RELEASE_PRINCIPAL=ittcsecscan-release
RELEASE_NAMESPACE=ittcsecscan-release

# One SHA256SUMS line: 64 lowercase hex digits, two spaces, an asset name.
# Asset names start with ittcsecscan_ and contain no path separators, so even a
# signed SHA256SUMS cannot point outside the release directory.
SUMS_LINE='^[0-9a-f]{64}  ittcsecscan_[0-9A-Za-z._+-]+$'

LC_ALL=C
export LC_ALL

fail() {
	echo "${0##*/}: FAIL: $*" >&2
	exit 1
}

# sha256_of FILE: the lowercase hex SHA-256 of FILE, or failure.
sha256_of() {
	_h=$(if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1"
	else
		shasum -a 256 "$1"
	fi | cut -d' ' -f1)
	printf '%s\n' "$_h" | grep -Eqx '[0-9a-f]{64}' || fail "cannot hash $1"
	printf '%s\n' "$_h"
}

# write_sums DIR: DIR/SHA256SUMS over every ittcsecscan_* file in DIR, in byte
# order, as "<hash>  <name>" on every platform (sha256sum on Windows would
# write "<hash> *<name>").
write_sums() {
	(
		cd "$1"
		for _f in ittcsecscan_*; do
			[ -f "$_f" ] || fail "no assets in $1"
			_h=$(sha256_of "$_f")
			printf '%s  %s\n' "$_h" "$_f"
		done >SHA256SUMS
	)
}

# check_sums DIR strict|partial: DIR/SHA256SUMS is well formed, every
# ittcsecscan_* file in DIR is listed, and every listed file that is present
# matches its hash.
#   strict   every listed file must be present, and DIR holds nothing but the
#            assets, SHA256SUMS, and SHA256SUMS.sig
#   partial  listed files that were not downloaded are skipped, but at least
#            one must be present
check_sums() {
	_dir=$1
	_mode=$2
	_sums=$_dir/SHA256SUMS
	[ -f "$_sums" ] && [ -s "$_sums" ] || fail "SHA256SUMS is missing or empty in $_dir"
	# Parsed defensively even when signed: names become file paths below.
	# Carriage returns are checked separately because grep on Windows drops
	# them before matching.
	if ! tr -d '\r' <"$_sums" | cmp -s - "$_sums"; then
		fail "SHA256SUMS is malformed: it contains carriage returns"
	fi
	if grep -Evq "$SUMS_LINE" "$_sums"; then
		fail "SHA256SUMS line $(grep -Evn "$SUMS_LINE" "$_sums" | head -n 1 | cut -d: -f1) is malformed"
	fi
	if cut -c 67- "$_sums" | sort | uniq -d | grep -q .; then
		fail "SHA256SUMS lists an asset twice"
	fi

	_present=0
	# "|| [ -n ... ]" also reads a last line that has no newline.
	while IFS= read -r _line || [ -n "$_line" ]; do
		_want=${_line%%  *}
		_name=${_line#*  }
		if [ ! -e "$_dir/$_name" ] && [ ! -L "$_dir/$_name" ]; then
			[ "$_mode" = partial ] || fail "listed asset is missing: $_name"
			echo "skipped (not downloaded): $_name"
			continue
		fi
		[ -f "$_dir/$_name" ] && [ ! -L "$_dir/$_name" ] || fail "not a regular file: $_name"
		_got=$(sha256_of "$_dir/$_name")
		[ "$_got" = "$_want" ] || fail "checksum mismatch: $_name"
		echo "ok: $_name"
		_present=$((_present + 1))
	done <"$_sums"
	[ "$_present" -gt 0 ] || fail "none of the listed assets is present in $_dir"

	for _f in "$_dir"/*; do
		[ -e "$_f" ] || [ -L "$_f" ] || continue
		_n=${_f##*/}
		case $_n in
		ittcsecscan_*)
			cut -c 67- "$_sums" | grep -qxF -- "$_n" ||
				fail "asset not listed in SHA256SUMS: $(printf '%s' "$_n" | tr -c '[:alnum:]._+-' '?')"
			;;
		SHA256SUMS | SHA256SUMS.sig) ;;
		*)
			[ "$_mode" = partial ] ||
				fail "unexpected file in the release directory: $(printf '%s' "$_n" | tr -c '[:alnum:]._+-' '?')"
			;;
		esac
	done
}

# release_keys FILE: prints "<type> <base64>" for every key in an
# allowed-signers file, and fails unless every entry is for the release
# principal, restricted to the release namespace, and an Ed25519 key (a
# FIDO security-key Ed25519 key is accepted too).
release_keys() {
	[ -f "$1" ] || fail "allowed-signers file not found: $1"
	grep -Ev '^[[:space:]]*(#|$)' "$1" | awk -v p="$RELEASE_PRINCIPAL" -v ns="$RELEASE_NAMESPACE" '
		{
			ok = NF >= 4 && $1 == p && $2 ~ ("^namespaces=\"" ns "\"(,|$)") &&
				($3 == "ssh-ed25519" || $3 == "sk-ssh-ed25519@openssh.com")
			if (!ok) { bad = 1; exit }
			print $3 " " $4
			n++
		}
		END { exit (bad || n == 0) }' ||
		fail "$1: every entry must read: $RELEASE_PRINCIPAL namespaces=\"$RELEASE_NAMESPACE\" ssh-ed25519 <key>"
}
