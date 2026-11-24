#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $*"; }

mkdir -p "strfry-db-test"
rm -f "strfry-db-test/data.mdb"

# write tests

info "running write tests..."

node "./test/tests/writeTest.js" \
  && pass "./test/tests/writeTest.js" \
  || fail "./test/tests/writeTest.js failed"

info "running private storage tests..."

node "./test/tests/privateStorageTest.js" \
  && pass "./test/tests/privateStorageTest.js" \
  || fail "./test/tests/privateStorageTest.js failed"

info "running relay management tests..."

node "./test/tests/adminTest.js" \
  && pass "./test/tests/adminTest.js" \
  || fail "./test/tests/adminTest.js failed"

info "running webhook tests..."

node "./test/tests/webhookTest.js" \
  && pass "./test/tests/webhookTest.js" \
  || fail "./test/tests/webhookTest.js failed"

info "Seeding events..."

perl "./test/utils/generate-seed-data.pl" -o - | ./strfry --config ./test/cfgs/test.conf import --no-verify

info "running filterFuzzTest..."

perl "./test/tests/filterFuzzTest.pl" scan \
&& pass "./test/tests/filterFuzzTest.pl scan" \
|| fail "./test/tests/filterFuzzTest.pl scan failed"

perl "./test/tests/filterFuzzTest.pl" scan-limit \
&& pass "./test/tests/filterFuzzTest.pl scan-limit" \
|| fail "./test/tests/filterFuzzTest.pl scan-limit failed"

perl "./test/tests/filterFuzzTest.pl" monitor \
&& pass "./test/tests/filterFuzzTest.pl monitor" \
|| fail "./test/tests/filterFuzzTest.pl monitor failed"

pass "All tests passed."
