#!/usr/bin/env bash
# Usage: build-linux.sh PAYLOAD_ROOT OUTPUT_DEB VERSION
# PAYLOAD_ROOT contains linux_amd64/ from a verified release and intel/.
set -euo pipefail
payload=$(realpath "$1")
output=$(realpath -m "$2")
version=$3
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || exit 2
repo=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
bash "$repo/packaging/packettale/stage-linux.sh" "$payload" "$work"
install -d "$work/DEBIAN"
cat > "$work/DEBIAN/control" <<EOF
Package: packettale
Version: $version
Architecture: amd64
Homepage: https://packettale.com
Maintainer: PacketTale contributors
Priority: optional
Section: net
Installed-Size: $(du -sk "$work/usr" "$work/var" | awk '{sum+=$1} END{print sum}')
Depends: iptables
Description: Centrally managed application firewall
 PacketTale background endpoint with centrally managed traffic monitoring and DNS filtering.
EOF
cat > "$work/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = configure ]; then
 if [ ! -f /var/lib/packettale/management.json ]; then
  echo 'Provision enrollment with the installation script from the portal before installing.' >&2
  exit 1
 fi
 chmod 600 /var/lib/packettale/management.json
 systemctl daemon-reload
 systemctl enable packettale.service
 systemctl restart packettale.service
fi
EOF
cat > "$work/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
case "$1" in
 remove|deconfigure)
  if [ -d /run/systemd/system ]; then
   systemctl stop packettale.service
   systemctl disable packettale.service
  fi
 ;;
esac
EOF
cat > "$work/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
systemctl daemon-reload || true
# Standard dpkg removal retains data; explicit purge removes it.
if [ "$1" = purge ]; then
 rm -rf --one-file-system -- /var/lib/packettale /usr/lib/packettale
fi
EOF
chmod 755 "$work/DEBIAN/postinst" "$work/DEBIAN/prerm" "$work/DEBIAN/postrm"
mkdir -p "$(dirname "$output")"
dpkg-deb --root-owner-group --build "$work" "$output"
