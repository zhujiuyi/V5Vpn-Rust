#!/bin/sh
# Run inside the dedicated Linux distribution. stdin becomes VICI after the
# route and native relay configuration records.
set -eu
set -f
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
umask 077

marker=/etc/v5vpn-nc/managed-ubuntu-24.04-v1
test -f "$marker" || { printf '%s\n' V5VPN_UNMANAGED; exit 1; }
IFS=' ' read -r peer port vip host secured || exit 1
case "$peer:$port:$vip:$host" in *[!0-9.:]*) exit 1 ;; esac
IFS=' ' read -r native bridge_port bridge_nonce native_targets || exit 1
[ "$native" = native ] || exit 1
case "$bridge_port" in
    0) [ "$bridge_nonce" = - ] && [ -z "$native_targets" ] || exit 1 ;;
    ''|*[!0-9]*) exit 1 ;;
    *) [ -n "$native_targets" ] || exit 1 ;;
esac
set -- $secured
[ "$#" -gt 0 ] || exit 1
for route do
    case "$route" in *[!0-9./]*|'') exit 1 ;; esac
done

exec 9>/run/v5vpn-nc.lock
flock -n 9 || { printf '%s\n' V5VPN_BUSY; exit 1; }
test ! -e /run/charon.pid || { printf '%s\n' V5VPN_CHARON_EXISTS; exit 1; }
dir=$(mktemp -d /run/v5vpn-nc.XXXXXX)
charon=
transport=
native_relay=
native_watchdog=
native_relay_port=
native_rule_tag=${dir##*/}
vip_added=no
changed_forward=no
nat_added=
policy_added=
forward_added=
mss_out_added=
mss_in_added=
old_forward=$(cat /proc/sys/net/ipv4/ip_forward)

tcp_mss() {
    operation=$1
    source_network=$2
    destination_network=$3
    # WSL NAT and ESP add overhead. Limit the MSS advertised in both TCP
    # handshake directions when the protected path does not deliver PMTU.
    iptables -w 3 -t mangle "$operation" FORWARD -s "$source_network" \
        -d "$destination_network" -p tcp --tcp-flags SYN,RST SYN \
        -m tcpmss --mss 1281:65535 -m comment --comment v5vpn-nc-mss \
        -j TCPMSS --set-mss 1280
}

native_guard() {
    iptables -w 3 "$1" FORWARD -d "$2/32" \
        -m comment --comment "$native_rule_tag" -j DROP
}

native_redirect() {
    iptables -w 3 -t nat "$1" PREROUTING -s "$host/32" -d "$2/32" \
        -p tcp -m comment --comment "$native_rule_tag" \
        -j REDIRECT --to-ports "$native_relay_port"
}

remove_native_rule() {
    if "$1" -C "$2" 2>/dev/null; then
        "$1" -D "$2"
    else
        [ "$?" -eq 1 ]
    fi
}

native_failed() {
    printf '%s\n' V5VPN_NATIVE_FAILED
    exit 1
}

cleanup() {
    result=$?
    trap - EXIT
    trap '' HUP INT TERM
    set +e
    if [ -n "$native_watchdog" ]; then kill "$native_watchdog" 2>/dev/null; wait "$native_watchdog" 2>/dev/null; fi
    if [ -n "$transport" ]; then kill "$transport" 2>/dev/null; wait "$transport" 2>/dev/null; fi
    if [ -n "$charon" ]; then kill "$charon" 2>/dev/null; wait "$charon" 2>/dev/null; fi
    if [ "$changed_forward" = yes ]; then
        printf '%s\n' "$old_forward" >/proc/sys/net/ipv4/ip_forward || result=1
    fi
    if [ -n "$native_relay_port" ]; then
        for target in $native_targets; do
            remove_native_rule native_redirect "$target" || result=1
            remove_native_rule native_guard "$target" || result=1
        done
    fi
    if [ -n "$native_relay" ]; then kill "$native_relay" 2>/dev/null; wait "$native_relay" 2>/dev/null; fi
    for route in $nat_added; do
        iptables -w 3 -t nat -D POSTROUTING -s "$host/32" -d "$route" \
            -m comment --comment v5vpn-nc-session -j SNAT --to-source "$vip" || result=1
    done
    for route in $forward_added; do
        iptables -w 3 -D FORWARD -d "$route" ! -s "$host/32" \
            -m comment --comment v5vpn-nc-source -j DROP || result=1
    done
    for route in $mss_out_added; do
        tcp_mss -D "$host/32" "$route" || result=1
    done
    for route in $mss_in_added; do
        tcp_mss -D "$route" "$host/32" || result=1
    done
    for index in $policy_added; do
        ip xfrm policy delete dir out index "$index" || result=1
    done
    if [ "$vip_added" = yes ]; then ip -4 address del "$vip/32" dev lo || result=1; fi
    rm -f -- "$dir/strongswan.conf" "$dir/charon.vici" \
        "$dir/native_relay.py" "$dir/native_relay.port" || result=1
    rmdir -- "$dir" || result=1
    exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# Do not share a forwarding or IPsec environment with another Linux VPN.
old_state=$(ip xfrm state list nokeys) || { printf '%s\n' V5VPN_XFRM_FAILED; exit 1; }
old_policy=$(ip xfrm policy list) || { printf '%s\n' V5VPN_XFRM_FAILED; exit 1; }
if [ "$old_forward" != 0 ] || [ -n "$old_state" ] || [ -n "$old_policy" ]; then
    printf '%s\n' V5VPN_NETWORK_BUSY
    exit 1
fi

if [ "$bridge_port" != 0 ]; then
    test -x /usr/bin/python3 || native_failed
    cat >"$dir/native_relay.py" <<'V5VPN_NATIVE_PY' || native_failed
__V5VPN_NATIVE_HELPER__
V5VPN_NATIVE_PY
    printf '%s %s %s %s\n' "$host" "$bridge_port" "$bridge_nonce" "$native_targets" |
        /usr/bin/python3 "$dir/native_relay.py" >"$dir/native_relay.port" 9>&- &
    native_relay=$!
    unset bridge_nonce
    for attempt in $(seq 1 100); do
        if [ -s "$dir/native_relay.port" ] &&
            IFS= read -r native_relay_port <"$dir/native_relay.port"; then
            break
        fi
        kill -0 "$native_relay" 2>/dev/null || native_failed
        sleep 0.05
    done
    test -n "$native_relay_port" || native_failed
    for target in $native_targets; do
        # These targets are outside the authorized XFRM policy. If REDIRECT
        # does not apply, forwarding them must never use the default route.
        native_guard -I "$target" || native_failed
        native_redirect -I "$target" || native_failed
    done
fi

ip -4 address add "$vip/32" dev lo
vip_added=yes
index=3400000001
for route do
    # An ESP policy installed by charon takes precedence over this fallback.
    ip xfrm policy add dir out src "$vip/32" dst "$route" action block priority 4000000000 index "$index"
    policy_added="$policy_added $index"
    index=$((index + 8))
    iptables -w 3 -t nat -I POSTROUTING 1 -s "$host/32" -d "$route" \
        -m comment --comment v5vpn-nc-session -j SNAT --to-source "$vip"
    nat_added="$nat_added $route"
    # The forwarding path must not transmit an unmatched Windows source with
    # the guest's default route when the SNAT rule applies only to the host.
    iptables -w 3 -I FORWARD 1 -d "$route" ! -s "$host/32" \
        -m comment --comment v5vpn-nc-source -j DROP
    forward_added="$forward_added $route"
    tcp_mss -I "$host/32" "$route"
    mss_out_added="$mss_out_added $route"
    tcp_mss -I "$route" "$host/32"
    mss_in_added="$mss_in_added $route"
done

cat >"$dir/strongswan.conf" <<EOF
charon {
    port = $port
    port_nat_t = 4500
    install_routes = no
    install_virtual_ip = no
    load_modular = yes
    plugins {
        include /etc/strongswan.d/charon/*.conf
        stroke {
            load = no
        }
        vici {
            socket = unix://$dir/charon.vici
        }
    }
    filelog {
        stderr {
            default = -1
        }
    }
}
EOF
STRONGSWAN_CONF="$dir/strongswan.conf" /usr/lib/ipsec/charon </dev/null >/dev/null 2>&1 9>&- &
charon=$!
for attempt in $(seq 1 100); do
    if [ -S "$dir/charon.vici" ]; then break; fi
    kill -0 "$charon" 2>/dev/null || { printf '%s\n' V5VPN_CHARON_FAILED; exit 1; }
    sleep 0.05
done
test -S "$dir/charon.vici" || { printf '%s\n' V5VPN_CHARON_FAILED; exit 1; }

printf '1\n' >/proc/sys/net/ipv4/ip_forward
changed_forward=yes
if [ -n "$native_relay" ]; then
    kill -0 "$native_relay" 2>/dev/null || native_failed
fi
printf '%s\n' V5VPN_NC_READY
if [ -z "$native_relay" ]; then
    socat - "UNIX-CONNECT:$dir/charon.vici"
    exit 0
fi
(
    while kill -0 "$native_relay" 2>/dev/null; do sleep 1; done
    kill -TERM "$$"
) </dev/null >/dev/null 2>&1 9>&- &
native_watchdog=$!
exec 8<&0
socat - "UNIX-CONNECT:$dir/charon.vici" <&8 8<&- 9>&- &
transport=$!
exec 8<&-
wait "$transport"
