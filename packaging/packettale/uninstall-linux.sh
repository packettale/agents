#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# OS-administrator removal. Ordinary package removal retains local endpoint data.
set -eu
purge=false
case "${1:-}" in
 --purge) purge=true ;;
 --help) printf '%s\n' 'Usage: packettale-uninstall [--purge]' 'Without --purge, enrollment and local history are retained.'; exit 0 ;;
 '') ;;
 *) echo 'Usage: packettale-uninstall [--purge]' >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo 'Unexpected uninstall arguments.' >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo 'Run this command as root.' >&2; exit 1; }

# The complete function is parsed before its package-owned script is unlinked.
remove_endpoint() {
 . /etc/os-release
 case "$ID" in
  debian|ubuntu)
   if [ "$purge" = true ]; then dpkg --purge packettale; else dpkg --remove packettale; fi
  ;;
  fedora)
   if rpm -q packettale >/dev/null 2>&1; then rpm -e packettale; fi
  ;;
  *) echo 'Use the native package manager on this unsupported distribution.' >&2; exit 1 ;;
 esac
 if [ "$purge" = true ]; then
  # GNU rm removes symlinks themselves and does not traverse other filesystems.
  # Fixed package paths only: no environment override or caller-supplied path.
  rm -rf --one-file-system -- /var/lib/packettale /usr/lib/packettale
 fi
}
remove_endpoint
