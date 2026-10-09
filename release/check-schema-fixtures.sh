#!/bin/sh
# Release blocker (ADR-0012 §4): a release that ships a tenant schema needs
# that schema's frozen fixture checked in, and the tests that consume released
# fixtures (ADR-0011 rollback tests 1 and 3). A release ships a tenant schema
# when cmd/ittcsecscan links internal/store.
#
# Usage: release/check-schema-fixtures.sh [--assume-store-linked]
#   --assume-store-linked  check as if the CLI linked the store (self-test)
set -eu
cd "$(dirname "$0")/.."

linked=
if [ "${1:-}" = --assume-store-linked ]; then
  linked=yes
elif go list -deps ./cmd/ittcsecscan | grep -qx 'github.com/ittcsec/ittcsecscan/internal/store'; then
  linked=yes
fi
if [ -z "$linked" ]; then
  echo "schema fixtures: cmd/ittcsecscan does not link internal/store, so this release ships no tenant schema"
  exit 0
fi

latest="$(ls internal/store/migrations | grep -E '^[0-9]{4}_[a-z0-9_]+\.sql$' | sort | tail -n 1 | cut -c1-4)"
fixture="internal/store/testdata/releases/schema-v$latest/store.db"
status=0
if [ ! -f "$fixture" ]; then
  echo "release blocker: this release ships tenant schema version $latest, but its frozen fixture $fixture is not checked in (ADR-0012 §4)" >&2
  status=1
fi
for entry in TestReleasedSchemaFixturesMigrate:1 TestPreviousReleaseReadsCurrentFiles:3; do
  test="${entry%:*}"
  if ! grep -q "^func $test(" internal/store/*_test.go; then
    echo "release blocker: $test, ADR-0011 rollback test ${entry#*:}, does not exist yet (ADR-0012 §4)" >&2
    status=1
  fi
done
if [ "$status" -eq 0 ]; then
  echo "schema fixtures: schema version $latest has its frozen fixture, and the released-fixture tests exist"
fi
exit "$status"
