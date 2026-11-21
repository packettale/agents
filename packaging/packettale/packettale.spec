Name: packettale
URL: https://packettale.com
Version: %{pkg_version}
Release: 1
Summary: Centrally managed application firewall
License: GPL-3.0-only
BuildArch: x86_64
AutoReqProv: no
Requires: systemd, policycoreutils-python-utils, iptables-nft
Requires(post): systemd, policycoreutils
Requires(preun): systemd
Requires(postun): systemd
%description
PacketTale endpoint with local traffic monitoring and DNS filtering.
%install
mkdir -p "%{buildroot}"
cp -a "%{payload_root}/." "%{buildroot}/"
%pre
if [ "$1" -eq 1 ] && [ ! -f /var/lib/packettale/management.json ]; then
 echo 'Provision enrollment using the installation script from the portal.' >&2
 exit 1
fi
%post
chmod 600 /var/lib/packettale/management.json
if command -v selinuxenabled >/dev/null && selinuxenabled; then
 semanage fcontext -a -t bin_t '/usr/lib/packettale/packettale-core' 2>/dev/null || semanage fcontext -m -t bin_t '/usr/lib/packettale/packettale-core'
 restorecon /usr/lib/packettale/packettale-core
fi
if [ -d /run/systemd/system ]; then
 systemctl daemon-reload
 systemctl enable packettale.service
 systemctl restart packettale.service
fi
%preun
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
 systemctl stop packettale.service || exit 1
 systemctl disable packettale.service || exit 1
fi
%postun
if [ -d /run/systemd/system ]; then systemctl daemon-reload || :; fi
%files
/usr/sbin/packettale-uninstall
/usr/lib/packettale
/usr/lib/systemd/system/packettale.service
%license /usr/share/doc/packettale/copyright
%dir /var/lib/packettale
/var/lib/packettale/intel
