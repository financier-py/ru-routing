#!/bin/sh
# Put a build on its own branch, one commit with no history, so every file has a
# stable URL (raw.githubusercontent.com, jsDelivr). max stays in releases only:
# its files are too big for a branch.
#   tools/publish-branch.sh dist release
set -eu
dist=${1:?dist}; branch=${2:?branch}
tree=$(mktemp -d)
for variant in lite standard full; do
  cp -r "$dist/$variant" "$tree/$variant"
done
cd "$tree"
git init -q -b "$branch"
git add -A
git -c user.name="github-actions[bot]" -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
  commit -q -m "Lists of $(date -u +%Y-%m-%d)"
git push -q --force "https://x-access-token:$GH_TOKEN@github.com/$GITHUB_REPOSITORY.git" "$branch"
