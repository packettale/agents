#!/usr/bin/env bash
# Isolated package-removal checks; does not mount or remove host endpoint data.
set -euo pipefail
[[ ${PACKETTALE_PACKAGE_TESTS:-0} = 1 ]] || { echo 'Set PACKETTALE_PACKAGE_TESTS=1 to run isolated Docker package checks.' >&2; exit 2; }
repo=$(cd "$(dirname "$0")/../../.." && pwd)
docker run --rm --network none --mount "type=bind,src=$repo,dst=/source,readonly" debian:trixie-slim sh -eu -c '
 install -d /var/lib/packettale/databases /usr/lib/packettale /outside /test-bin
 printf retained > /var/lib/packettale/management-state.json
 printf evidence > /var/lib/packettale/databases/history.db
 printf index > /usr/lib/packettale/index.json
 printf sentinel > /outside/retain
 ln -s /outside /var/lib/packettale/external
 # Package-manager behavior is stubbed here; native DEB/RPM trials are separate.
 printf "#!/bin/sh\nexit 0\n" > /test-bin/dpkg
 chmod 755 /test-bin/dpkg
 PATH=/test-bin:$PATH sh /source/packaging/packettale/uninstall-linux.sh
 test -f /var/lib/packettale/databases/history.db
 test -f /usr/lib/packettale/index.json
 printf "#!/bin/sh\nexit 7\n" > /test-bin/dpkg
 if PATH=/test-bin:$PATH sh /source/packaging/packettale/uninstall-linux.sh --purge; then
  echo "Failed package removal was ignored" >&2; exit 1
 fi
 test -f /var/lib/packettale/databases/history.db
 printf "#!/bin/sh\nexit 0\n" > /test-bin/dpkg
 PATH=/test-bin:$PATH sh /source/packaging/packettale/uninstall-linux.sh --purge
 test ! -e /var/lib/packettale
 test ! -e /usr/lib/packettale
 test "$(cat /outside/retain)" = sentinel
'
echo 'Linux explicit purge removes only endpoint data and retains an external symlink target.'

docker run --rm --network none --mount "type=bind,src=$repo,dst=/source,readonly" fedora:44 sh -eu -c '
 mkdir -p /var/lib/packettale /usr/lib/packettale /outside /test-bin
 printf evidence > /var/lib/packettale/history.db
 printf index > /usr/lib/packettale/index.json
 printf sentinel > /outside/retain
 ln -s /outside /var/lib/packettale/external
 printf "#!/bin/sh\nif [ \"\$1\" = -e ] && [ -e /test-bin/fail ]; then exit 7; fi\nexit 0\n" > /test-bin/rpm
 chmod 755 /test-bin/rpm
 PATH=/test-bin:$PATH sh /source/packaging/packettale/uninstall-linux.sh
 test -f /var/lib/packettale/history.db
 touch /test-bin/fail
 if PATH=/test-bin:$PATH sh /source/packaging/packettale/uninstall-linux.sh --purge; then exit 1; fi
 test -f /var/lib/packettale/history.db
 rm /test-bin/fail
 PATH=/test-bin:$PATH sh /source/packaging/packettale/uninstall-linux.sh --purge
 test ! -e /var/lib/packettale
 test ! -e /usr/lib/packettale
 test "$(cat /outside/retain)" = sentinel
'
echo 'RPM removal path preserves data by default and refuses purge after removal failure.'

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/payload/linux_amd64" "$work/payload/intel" "$work/control"
for filename in packettale-core; do printf test > "$work/payload/linux_amd64/$filename"; done
bash "$repo/packaging/packettale/build-linux.sh" "$work/payload" "$work/test.deb" 0.0.1 >/dev/null
dpkg-deb --control "$work/test.deb" "$work/control"
docker run --rm --network none --mount "type=bind,src=$work/control,dst=/control,readonly" debian:trixie-slim sh -eu -c '
 mkdir -p /var/lib/packettale/databases /usr/lib/packettale
 printf evidence > /var/lib/packettale/databases/history.db
 printf index > /usr/lib/packettale/index.json
 sh /control/postrm remove
 test -f /var/lib/packettale/databases/history.db
 sh /control/postrm purge
 test ! -e /var/lib/packettale
 test ! -e /usr/lib/packettale
'
echo 'Generated DEB hooks retain data on remove and delete it on explicit purge.'
