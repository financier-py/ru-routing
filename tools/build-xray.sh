#!/bin/sh
# Build Xray with the domain matcher that iOS and Android get, so that
# tools/memory.py measures what phones actually run.
#
#   tools/build-xray.sh v26.10.31    # the core in Happ for iOS, November 2026
set -eu
version=${1:?usage: build-xray.sh <tag>}
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
git clone -q --depth 1 -b "$version" https://github.com/XTLS/Xray-core "$src"
file=$src/common/geodata/domain_matcher.go
grep -q 'case "ios", "android":' "$file" || { echo "matcher switch not found in $version" >&2; exit 1; }
sed -i 's/case "ios", "android":/case "ios", "android", "linux":/' "$file"
(cd "$src" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OLDPWD/xray-mobile" ./main)
echo "built ./xray-mobile ($version, mobile matcher)"
