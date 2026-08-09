#!/bin/sh

set -eu

if [ "${1:-}" != "patch" ] || [ "$#" -ne 1 ]; then
  echo "usage: $0 patch" >&2
  exit 2
fi

package_version() {
  awk '
    $0 == "[package]" { in_package = 1; next }
    /^\[/ { in_package = 0 }
    in_package && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "$1"
}

wgprobe_version=$(package_version crates/wgprobe/Cargo.toml)
nordprobe_version=$(package_version crates/nordprobe/Cargo.toml)
python_version=$(package_version crates/wgprobe-python/Cargo.toml)

if [ "$wgprobe_version" != "$nordprobe_version" ] || [ "$wgprobe_version" != "$python_version" ]; then
  echo "package versions do not match" >&2
  exit 1
fi

if ! printf '%s\n' "$wgprobe_version" |
  awk -F. 'NF == 3 && $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ { valid = 1 } END { exit !valid }'; then
  echo "invalid package version: $wgprobe_version" >&2
  exit 1
fi

major=${wgprobe_version%%.*}
remainder=${wgprobe_version#*.}
minor=${remainder%%.*}
patch=${remainder#*.}
next_version="$major.$minor.$((patch + 1))"

for manifest in \
  crates/wgprobe/Cargo.toml \
  crates/nordprobe/Cargo.toml \
  crates/wgprobe-python/Cargo.toml; do
  sed -i.bak \
    "s/^version = \"$wgprobe_version\"$/version = \"$next_version\"/" \
    "$manifest"
  rm "$manifest.bak"
done

for manifest in \
  crates/nordprobe/Cargo.toml \
  crates/wgprobe-python/Cargo.toml; do
  sed -i.bak \
    "s/version = \"$wgprobe_version\", path = \"..\/wgprobe\"/version = \"$next_version\", path = \"..\/wgprobe\"/" \
    "$manifest"
  rm "$manifest.bak"
done

cargo check --workspace --quiet
cargo check --workspace --locked --quiet

printf '%s\n' "$next_version"
