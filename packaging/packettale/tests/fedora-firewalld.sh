#!/usr/bin/env bash
# Opt-in integration test for an enrolled disposable Fedora VM.
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
if [[ ${1:-} != --allow-service-restarts || $# != 1 ]]; then
  echo 'Usage: sudo fedora-firewalld.sh --allow-service-restarts' >&2
  exit 2
fi
[[ $(id -u) = 0 && -f /etc/fedora-release ]] || { echo 'An isolated Fedora test VM and root are required.' >&2; exit 2; }
[[ $(getenforce) = Enforcing ]] || { echo 'SELinux must already be enforcing.' >&2; exit 2; }
for command in systemctl firewall-cmd iptables sha256sum; do
  command -v "$command" >/dev/null || { echo "Missing prerequisite: $command" >&2; exit 2; }
done
state=/var/lib/packettale/management-state.json
config=/var/lib/packettale/management.json
[[ -f $state && -f $config && -x /usr/lib/packettale/packettale-core ]] || { echo 'An enrolled standard installation is required.' >&2; exit 2; }
[[ $(systemctl show packettale -p ExecStart --value) == *'/usr/lib/packettale/packettale-core '* ]] || { echo 'Unexpected core service executable.' >&2; exit 2; }
before=$(sha256sum "$state" "$config")
assert_services() {
  systemctl is-active --quiet packettale || { echo 'The core service stopped.' >&2; exit 1; }
  systemctl is-active --quiet firewalld || { echo 'Starting the core stopped firewalld.' >&2; exit 1; }
}
assert_hooks() {
  local attempt
  for attempt in {1..30}; do
    if iptables -t mangle -C OUTPUT -j PACKETTALE-INGEST-OUTPUT 2>/dev/null &&
       iptables -t mangle -C INPUT -j PACKETTALE-INGEST-INPUT 2>/dev/null; then
      return
    fi
    sleep .5
  done
  echo 'IPv4 interception hooks are missing.' >&2
  exit 1
}
systemctl start firewalld
systemctl restart packettale
assert_services
assert_hooks
firewall-cmd --reload >/dev/null
assert_services
assert_hooks
[[ $(getenforce) = Enforcing ]] || { echo 'SELinux mode changed.' >&2; exit 1; }
[[ $(sha256sum "$state" "$config") = "$before" ]] || { echo 'Enrollment or management configuration changed.' >&2; exit 1; }
echo 'Both services and IPv4 interception hooks remain active after firewalld reload; enrollment and configuration hashes are unchanged.'
