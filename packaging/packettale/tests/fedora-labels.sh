#!/usr/bin/env bash
# Validate installed executables after an RPM installation or signed update.
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
[[ -f /etc/fedora-release && $(getenforce) = Enforcing ]] || { echo 'Enforcing Fedora is required.' >&2; exit 2; }
for path in /usr/lib/packettale/packettale-core; do
  [[ -x $path ]] || { echo "Missing installed executable: $path" >&2; exit 2; }
  matchpathcon -V "$path"
done
echo 'Core executable label match the installed SELinux policy.'
