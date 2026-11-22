#!/bin/sh
# Make sure the example configs load in real cores against a fresh build.
#   tools/check-examples.sh dist/full path/to/xray path/to/mihomo
set -eu
dist=${1:?dist variant}; xray=${2:?xray}; mihomo=${3:?mihomo}
for mode in smart classic; do
  XRAY_LOCATION_ASSET=$dist "$xray" run -test -c examples/xray/$mode.json
  home=$(mktemp -d)
  mkdir -p "$home/rules"
  cp -r "$dist/mihomo/geosite" "$dist/mihomo/geoip" "$home/rules/"
  "$mihomo" -t -d "$home" -f examples/mihomo/$mode.yaml
  rm -rf "$home"
done
