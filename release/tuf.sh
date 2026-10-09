#!/bin/sh
# Release-time TUF metadata generation (UP-1, ADR-0030). The maintainer runs this offline
# on their own machine: it signs the metadata with the maintainer's offline root, targets,
# snapshot, and timestamp keys through ssh-keygen, which prompts for each passphrase. The
# keys never enter CI. This is pure shell, the same pattern as sign.sh, because the product
# forbids process execution from Go (depguard safety-invariants, ADR-0005), so signing lives
# here, not in a Go tool.
#
# The exact metadata format, the signing rule (sign the stored bytes), and the pin-the-full
# -signed-file ordering are specified and round-trip verified against the update client in
# internal/update (generate.go, generate_test.go). This script mirrors that algorithm.
#
# Usage:
#   release/tuf.sh VERSION ASSETS_DIR OUT_DIR ROOT_KEY TARGETS_KEY SNAPSHOT_KEY TIMESTAMP_KEY \
#     [ROOT_VER TARGETS_VER SNAPSHOT_VER TIMESTAMP_VER]
set -eu

[ $# -ge 7 ] || {
	echo "usage: $0 VERSION ASSETS_DIR OUT_DIR ROOT_KEY TARGETS_KEY SNAPSHOT_KEY TIMESTAMP_KEY [ROOT_VER TARGETS_VER SNAPSHOT_VER TIMESTAMP_VER]" >&2
	exit 2
}
version="$1" assets="$2" out="$3"
root_key="$4" targets_key="$5" snapshot_key="$6" timestamp_key="$7"
root_ver="${8:-1}" targets_ver="${9:-1}" snapshot_ver="${10:-1}" timestamp_ver="${11:-1}"

namespace="ittcsecscan-update"
spec="ittcsecscan-tuf/1"
channel="stable"
mkdir -p "$out"

# expires ROLE_SECONDS -> RFC3339 UTC expiry from now.
expires() { date -u -d "+$1 seconds" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+"$1"S +%Y-%m-%dT%H:%M:%SZ; }
now_root=$(expires 31536000)   # 365d
now_targets=$(expires 2592000) # 30d
now_snapshot=$(expires 604800) # 7d
now_timestamp=$(expires 86400) # 24h

# keyid KEYFILE -> lowercase hex sha256 of the raw 32-byte ed25519 public key (the last 32
# bytes of the SSH public-key blob), matching internal/update.keyID.
keyid() { ssh-keygen -y -f "$1" | awk '{print $2}' | base64 -d | tail -c 32 | sha256sum | cut -d' ' -f1; }

# publine KEYFILE -> the "ssh-ed25519 <base64>" authorized line (comment stripped).
publine() { ssh-keygen -y -f "$1" | awk '{print $1" "$2}'; }

# jstr STRING -> a JSON string literal for an armored signature: escape backslashes and
# quotes (an sshsig armored blob has neither, but be safe) and turn newlines into \n.
jstr() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g'; }

# assemble ROLE KEYFILE BODY_FILE -> OUT/ROLE.json = {"signed":<body>,"signatures":[{...}]}.
# Signs the exact body bytes, then embeds those same bytes verbatim, so the stored "signed"
# is what was signed.
assemble() {
	_role="$1" _key="$2" _body="$3"
	rm -f "$_body.sig"
	ssh-keygen -Y sign -n "$namespace" -f "$_key" "$_body" >/dev/null
	_kid=$(keyid "$_key")
	_sig=$(jstr "$(cat "$_body.sig")")
	printf '{"signed":%s,"signatures":[{"keyid":"%s","sig":"%s"}]}' "$(cat "$_body")" "$_kid" "$_sig" >"$out/$_role.json"
	rm -f "$_body.sig"
}

# ---- targets: one entry per release binary ----
targets_entries=""
for f in "$assets"/ittcsecscan_"${version}"_*; do
	case "$f" in *.cdx.json | *_buildinfo.txt | *.json | *_provenance.json) continue ;; esac
	[ -f "$f" ] || continue
	name=$(basename "$f")
	len=$(wc -c <"$f" | tr -d ' ')
	sha=$(sha256sum "$f" | cut -d' ' -f1)
	entry=$(printf '"%s":{"length":%s,"sha256":"%s","custom":{"component":"ittcsecscan","version":"%s","channel":"%s"}}' "$name" "$len" "$sha" "$version" "$channel")
	targets_entries="${targets_entries:+$targets_entries,}$entry"
done
[ -n "$targets_entries" ] || { echo "no release binaries in $assets" >&2; exit 1; }
printf '{"spec":"%s","type":"targets","version":%s,"expires":"%s","targets":{%s}}' "$spec" "$targets_ver" "$now_targets" "$targets_entries" >"$out/targets.body"
assemble targets "$targets_key" "$out/targets.body"

# ---- snapshot: pins the signed targets.json ----
tlen=$(wc -c <"$out/targets.json" | tr -d ' ')
tsha=$(sha256sum "$out/targets.json" | cut -d' ' -f1)
printf '{"spec":"%s","type":"snapshot","version":%s,"expires":"%s","meta":{"targets.json":{"version":%s,"length":%s,"sha256":"%s"}}}' "$spec" "$snapshot_ver" "$now_snapshot" "$targets_ver" "$tlen" "$tsha" >"$out/snapshot.body"
assemble snapshot "$snapshot_key" "$out/snapshot.body"

# ---- timestamp: pins the signed snapshot.json ----
slen=$(wc -c <"$out/snapshot.json" | tr -d ' ')
ssha=$(sha256sum "$out/snapshot.json" | cut -d' ' -f1)
printf '{"spec":"%s","type":"timestamp","version":%s,"expires":"%s","meta":{"snapshot.json":{"version":%s,"length":%s,"sha256":"%s"}}}' "$spec" "$timestamp_ver" "$now_timestamp" "$snapshot_ver" "$slen" "$ssha" >"$out/timestamp.body"
assemble timestamp "$timestamp_key" "$out/timestamp.body"

# ---- root: lists every role's key and threshold 1 ----
rid=$(keyid "$root_key"); rpub=$(publine "$root_key")
tid=$(keyid "$targets_key"); tpub=$(publine "$targets_key")
sid=$(keyid "$snapshot_key"); spub=$(publine "$snapshot_key")
mid=$(keyid "$timestamp_key"); mpub=$(publine "$timestamp_key")
keys=$(printf '"%s":{"type":"ssh-ed25519","public":"%s"},"%s":{"type":"ssh-ed25519","public":"%s"},"%s":{"type":"ssh-ed25519","public":"%s"},"%s":{"type":"ssh-ed25519","public":"%s"}' "$rid" "$rpub" "$tid" "$tpub" "$sid" "$spub" "$mid" "$mpub")
roles=$(printf '"root":{"keyids":["%s"],"threshold":1},"targets":{"keyids":["%s"],"threshold":1},"snapshot":{"keyids":["%s"],"threshold":1},"timestamp":{"keyids":["%s"],"threshold":1}' "$rid" "$tid" "$sid" "$mid")
printf '{"spec":"%s","type":"root","version":%s,"expires":"%s","keys":{%s},"roles":{%s}}' "$spec" "$root_ver" "$now_root" "$keys" "$roles" >"$out/root.body"
assemble root "$root_key" "$out/root.body"

rm -f "$out"/*.body
echo "wrote $out/{root,targets,snapshot,timestamp}.json"
echo "upload them to the release: gh release upload v${version} $out/root.json $out/targets.json $out/snapshot.json $out/timestamp.json --repo ittcsec/ittcsecscan-public"
