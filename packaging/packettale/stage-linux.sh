#!/usr/bin/env bash
set -euo pipefail
payload=$(realpath "$1")
work=$(realpath -m "$2")
repo=$(cd "$(dirname "$0")/../.." && pwd)
install -d "$work/usr/lib/packettale" "$work/usr/lib/systemd/system" "$work/usr/sbin" "$work/var/lib/packettale/intel" "$work/usr/share/doc/packettale"
for f in packettale-core; do
 install -m 644 "$payload/linux_amd64/$f" "$work/usr/lib/packettale/$f"
done
chmod 755 "$work/usr/lib/packettale/packettale-core"
cp -a "$payload/intel/." "$work/var/lib/packettale/intel/"
install -m 644 "$repo/packaging/linux/packettale.service" "$work/usr/lib/systemd/system/packettale.service"
install -m 644 "$repo/LICENSE" "$work/usr/share/doc/packettale/copyright"

install -m 755 "$repo/packaging/packettale/uninstall-linux.sh" "$work/usr/sbin/packettale-uninstall"
