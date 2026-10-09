#!/bin/sh
# SLSA v1 build provenance for the release binaries (ADR-0009).
#
# Usage: release/provenance.sh VERSION DIR
#
# Writes DIR/ittcsecscan_<VERSION>_provenance.json, an in-toto Statement whose
# subject is every release binary in DIR with its SHA-256 digest, and whose
# predicate (SLSA provenance v1) records the builder workflow, the source repo and
# commit, the version, and the workflow run id. The file is named ittcsecscan_* so
# release/checksums.sh includes it in SHA256SUMS; the maintainer's offline signature
# over SHA256SUMS (release/sign.sh) is therefore the provenance's authenticity, with
# no CI-held key and no online attestation service. It is generated after the
# reproducible double-build, so its run-specific fields never affect that comparison.
#
# Environment (supplied by the release workflow; sensible defaults otherwise):
#   PROV_COMMIT   the built commit SHA
#   PROV_REF      the git ref (tag or branch)
#   PROV_RUN_ID   the CI run id
#   PROV_REPO     owner/repo
#   PROV_BUILDER  the builder id (workflow) URI
set -eu

[ $# -eq 2 ] || {
	echo "usage: $0 VERSION DIR" >&2
	exit 2
}
version="$1"
dir="$2"
commit="${PROV_COMMIT:-unknown}"
ref="${PROV_REF:-unknown}"
run_id="${PROV_RUN_ID:-unknown}"
repo="${PROV_REPO:-ittcsec/ittcsecscan-public}"
builder="${PROV_BUILDER:-https://github.com/$repo/.github/workflows/release.yml}"
out="$dir/ittcsecscan_${version}_provenance.json"

# Build the subject array over the six release binaries, in a fixed target order.
subjects=""
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	goos="${target%/*}"
	goarch="${target#*/}"
	name="ittcsecscan_${version}_${goos}_${goarch}"
	[ "$goos" = windows ] && name="${name}.exe"
	file="$dir/$name"
	[ -f "$file" ] || {
		echo "provenance: missing binary $file" >&2
		exit 1
	}
	digest=$(sha256sum "$file" | cut -d' ' -f1)
	entry="{\"name\":\"$name\",\"digest\":{\"sha256\":\"$digest\"}}"
	if [ -z "$subjects" ]; then
		subjects="$entry"
	else
		subjects="$subjects,$entry"
	fi
done

cat >"$out" <<EOF
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [$subjects],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://github.com/$repo/release",
      "externalParameters": {"version": "$version", "ref": "$ref"},
      "resolvedDependencies": [{"uri": "git+https://github.com/$repo@$ref", "digest": {"gitCommit": "$commit"}}]
    },
    "runDetails": {
      "builder": {"id": "$builder"},
      "metadata": {"invocationId": "$run_id"}
    }
  }
}
EOF

echo "provenance: wrote $out"
