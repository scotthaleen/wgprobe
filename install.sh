#!/bin/sh
set -eu

repository="scotthaleen/wgprobe"
selection="all"
version=""
install_dir=${WGPROBE_INSTALL_DIR:-"$HOME/.local/bin"}

usage() {
  cat <<'EOF'
Install wgprobe release binaries on Linux.

Usage: install.sh [--bin wgprobe|nordprobe|all] [--version VERSION] [--to DIRECTORY]

Defaults:
  --bin all
  --version latest
  --to $WGPROBE_INSTALL_DIR or $HOME/.local/bin
EOF
}

fail() {
  printf 'install.sh: %s\n' "$*" >&2
  exit 1
}

valid_version() {
  value=$1
  old_ifs=$IFS
  IFS=.
  set -- $value
  IFS=$old_ifs
  [ "$#" -eq 3 ] || return 1
  for component in "$@"; do
    case "$component" in ''|*[!0-9]*) return 1 ;; esac
  done
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bin)
      [ "$#" -ge 2 ] || fail "--bin requires a value"
      selection=$2
      shift 2
      ;;
    --version)
      [ "$#" -ge 2 ] || fail "--version requires a value"
      version=$2
      shift 2
      ;;
    --to)
      [ "$#" -ge 2 ] || fail "--to requires a value"
      install_dir=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *) fail "unknown option: $1" ;;
  esac
done

case "$selection" in
  wgprobe|nordprobe|all) ;;
  *) fail "--bin must be wgprobe, nordprobe, or all" ;;
esac

if [ -n "$version" ]; then
  release_tag=$version
  case "$release_tag" in v*) ;; *) release_tag="v$release_tag" ;; esac
  version=${release_tag#v}
  valid_version "$version" || fail "invalid release version: $release_tag"
fi

[ "$(uname -s)" = "Linux" ] || fail "the installer currently supports Linux only"
case "$(uname -m)" in
  x86_64|amd64) platform="linux-x86_64" ;;
  aarch64|arm64) platform="linux-aarch64" ;;
  *) fail "unsupported Linux architecture: $(uname -m)" ;;
esac

for command in curl tar sha256sum install awk; do
  command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
done

if [ -z "$version" ]; then
  latest_url=$(curl --proto '=https' --tlsv1.2 -LfsS -o /dev/null \
    -w '%{url_effective}' "https://github.com/$repository/releases/latest")
  release_tag=${latest_url##*/}
  version=${release_tag#v}
  valid_version "$version" || fail "invalid release version: $release_tag"
fi

temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
base_url="https://github.com/$repository/releases/download/$release_tag"
checksums="$temporary/SHA256SUMS"
curl --proto '=https' --tlsv1.2 -LfsS "$base_url/SHA256SUMS" -o "$checksums"

case "$selection" in
  all) binaries="wgprobe nordprobe" ;;
  *) binaries=$selection ;;
esac

for binary in $binaries; do
  package="$binary-$version-$platform"
  asset="$package.tar.gz"
  archive="$temporary/$asset"
  curl --proto '=https' --tlsv1.2 -LfsS "$base_url/$asset" -o "$archive"
  expected=$(awk -v asset="$asset" '$2 == asset { print $1 }' "$checksums")
  [ -n "$expected" ] || fail "checksum not found for $asset"
  actual=$(sha256sum "$archive" | awk '{ print $1 }')
  [ "$actual" = "$expected" ] || fail "checksum mismatch for $asset"
  tar -xzf "$archive" -C "$temporary"
done

mkdir -p "$install_dir"
for binary in $binaries; do
  package="$binary-$version-$platform"
  install -m 0755 "$temporary/$package/$binary" "$install_dir/$binary"
  printf 'installed %s %s to %s\n' "$binary" "$version" "$install_dir/$binary"
done

case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) printf 'add %s to PATH to run the installed binaries\n' "$install_dir" >&2 ;;
esac
