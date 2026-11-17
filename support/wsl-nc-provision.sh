#!/bin/sh
set -eu

marker=/etc/v5vpn-nc/managed-ubuntu-24.04-v1
check_tools() {
    test -x /usr/lib/ipsec/charon || return 1
    for plugin in kernel-netlink socket-default vici aes gmp hmac sha1; do
        test -f "/usr/lib/ipsec/plugins/libstrongswan-$plugin.so" || return 1
    done
    for tool in swanctl ip iptables socat flock python3; do
        command -v "$tool" >/dev/null || return 1
    done
}

if [ "${1:-}" = --check ]; then
    test -f "$marker" && check_tools || exit 10
    exit 0
fi
test "$#" -eq 0

# Share the runtime lock so repairing tools cannot disrupt a running tunnel.
exec 9>/run/v5vpn-nc.lock
flock -n 9 || exit 11
if test -f "$marker" && check_tools; then
    exit 0
fi
export DEBIAN_FRONTEND=noninteractive

policy=/usr/sbin/policy-rc.d
policy_marker='# V5VPN-NC provisioning only'
if [ ! -e "$policy" ] && [ ! -L "$policy" ]; then
    # Package setup must leave the session's charon daemon to the client.
    ( set -C; printf '#!/bin/sh\n%s\nexit 101\n' "$policy_marker" > "$policy" )
fi
if [ -f "$policy" ] && [ ! -L "$policy" ] && grep -Fxq "$policy_marker" "$policy"; then
    trap 'if [ -f "$policy" ] && [ ! -L "$policy" ] && grep -Fxq "$policy_marker" "$policy"; then rm -f -- "$policy"; fi' EXIT
    chmod 0755 "$policy"
fi

dpkg --configure -a
apt-get -o APT::Update::Error-Mode=any update
apt-get install -y --no-install-recommends \
    strongswan-charon strongswan-swanctl libstrongswan-standard-plugins \
    iproute2 iptables socat util-linux python3

if [ -d /run/systemd/system ]; then
    for unit in strongswan.service strongswan-starter.service; do
        if systemctl cat "$unit" >/dev/null 2>&1; then
            systemctl disable --now "$unit"
        fi
    done
fi

check_tools
install -d -m 0755 /etc/v5vpn-nc
touch "$marker"
