#!/bin/sh
# Pack a build into release assets: one .dat pair and one archive per format and variant.
#   tools/package.sh dist out
set -eu
dist=${1:?dist}; out=${2:?out}
mkdir -p "$out"
for variant in $(ls "$dist"); do
  cp "$dist/$variant/geosite.dat" "$out/geosite-$variant.dat"
  cp "$dist/$variant/geoip.dat" "$out/geoip-$variant.dat"
  tar -C "$dist/$variant" -czf "$out/mihomo-$variant.tar.gz" mihomo
  tar -C "$dist/$variant" -czf "$out/text-$variant.tar.gz" text
done
(cd "$out" && sha256sum -- *.dat *.tar.gz > SHA256SUMS)
