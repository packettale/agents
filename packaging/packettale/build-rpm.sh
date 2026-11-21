#!/usr/bin/env bash
# Usage: build-rpm.sh PAYLOAD_ROOT OUTPUT_RPM VERSION
set -euo pipefail
payload=$(realpath "$1")
output=$(realpath -m "$2")
version=$3
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bash "$repo/packaging/packettale/stage-linux.sh" "$payload" "$work/stage"
rpmbuild -bb --define "_tmppath $work" --define "_topdir $work/rpm" --define "payload_root $work/stage" --define "pkg_version $version" --define '_build_id_links none' --define '_buildhost packettale' --define '__strip /bin/true' --define '__brp_strip /bin/true' --define '__brp_strip_comment_note /bin/true' "$repo/packaging/packettale/packettale.spec"
mkdir -p "$(dirname "$output")"
cp "$work/rpm/RPMS/x86_64/packettale-$version-1.x86_64.rpm" "$output"
