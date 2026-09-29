#!/bin/sh
set -eu

scenario="${1:-}"
case "$scenario" in
  secure-baseline) ike='aes256gcm16-prfsha384-ecp384'; esp='aes256gcm16-ecp384' ;;
  aes128-gcm) ike='aes128gcm16-prfsha384-ecp384'; esp='aes128gcm16-ecp384' ;;
  aes256-cbc) ike='aes256-sha256-prfsha256-ecp384'; esp='aes256-sha256-ecp384' ;;
  no-pfs) ike='aes256gcm16-prfsha384-ecp384'; esp='aes256gcm16' ;;
  *) echo 'unsupported scenario' >&2; exit 2 ;;
esac

test -d /tmp/ipsec-sentinel-bundle/ipsec_sentinel
for secret in psk control-token endpoint.crt endpoint.key; do
  test -f "/tmp/ipsec-sentinel-secrets/$secret"
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  strongswan-swanctl charon-systemd strongswan-libcharon \
  libstrongswan-standard-plugins \
  iproute2 iptables tcpdump python3 ca-certificates

install -d -m 0755 /opt/ipsec-sentinel
cp -a /tmp/ipsec-sentinel-bundle/ipsec_sentinel /opt/ipsec-sentinel/
install -d -m 0700 /etc/ipsec-sentinel
install -m 0600 /tmp/ipsec-sentinel-secrets/psk /etc/ipsec-sentinel/psk
install -m 0600 /tmp/ipsec-sentinel-secrets/control-token /etc/ipsec-sentinel/control-token
install -m 0644 /tmp/ipsec-sentinel-secrets/endpoint.crt /etc/ipsec-sentinel/endpoint.crt
install -m 0600 /tmp/ipsec-sentinel-secrets/endpoint.key /etc/ipsec-sentinel/endpoint.key
printf '%s\n' "$scenario" > /etc/ipsec-sentinel/scenario
chmod 0600 /etc/ipsec-sentinel/scenario

install -d -m 0755 /etc/swanctl/conf.d
psk=$(cat /etc/ipsec-sentinel/psk)
cat > /etc/swanctl/conf.d/ipsec-sentinel.conf <<EOF
connections {
  $scenario {
    version = 2
    local_addrs = %any
    remote_addrs = %any
    proposals = $ike
    mobike = no
    encap = yes
    local { auth = psk
      id = gateway-b
    }
    remote { auth = psk
      id = gateway-a
    }
    children { protected-nets {
      local_ts = 10.20.0.0/24
      remote_ts = 10.10.0.0/24
      mode = tunnel
      esp_proposals = $esp
      start_action = none
    } }
  }
}
secrets { ike-cloud {
  id-a = gateway-a
  id-b = gateway-b
  secret = "$psk"
} }
EOF
chmod 0600 /etc/swanctl/conf.d/ipsec-sentinel.conf

cat > /usr/local/sbin/ipsec-sentinel-topology <<'EOF'
#!/bin/sh
set -eu
ip netns del ips-server 2>/dev/null || true
ip link del ips-server-host 2>/dev/null || true
ip netns add ips-server
ip link add ips-server-host type veth peer name ips-server-ns
ip link set ips-server-ns netns ips-server
ip addr add 10.20.0.1/24 dev ips-server-host
ip link set ips-server-host up
ip -n ips-server link set lo up
ip -n ips-server link set ips-server-ns name eth0
ip -n ips-server addr add 10.20.0.2/24 dev eth0
ip -n ips-server link set eth0 up
ip -n ips-server route add 10.10.0.0/24 via 10.20.0.1
sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw net.ipv4.conf.ips-server-host.rp_filter=0
EOF
chmod 0755 /usr/local/sbin/ipsec-sentinel-topology

cat > /etc/systemd/system/ipsec-sentinel-topology.service <<'EOF'
[Unit]
Description=IPsec Sentinel protected server namespace
Before=strongswan.service ipsec-sentinel-endpoint.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/ipsec-sentinel-topology
ExecStop=-/sbin/ip netns del ips-server
ExecStop=-/sbin/ip link del ips-server-host

[Install]
WantedBy=multi-user.target
EOF

install -m 0644 /tmp/ipsec-sentinel-bundle/deploy/gcp/ipsec-sentinel-endpoint.service /etc/systemd/system/
install -m 0644 /tmp/ipsec-sentinel-bundle/deploy/gcp/ipsec-sentinel-watchdog.service /etc/systemd/system/
install -m 0644 /tmp/ipsec-sentinel-bundle/deploy/gcp/ipsec-sentinel-watchdog.timer /etc/systemd/system/

install -m 0755 /tmp/ipsec-sentinel-bundle/deploy/gcp/ipsec-sentinel-ready \
  /usr/local/sbin/ipsec-sentinel-ready

cat > /etc/systemd/system/ipsec-sentinel-ready.service <<'EOF'
[Unit]
Description=IPsec Sentinel scenario-neutral readiness marker
After=strongswan.service ipsec-sentinel-endpoint.service
Requires=strongswan.service ipsec-sentinel-endpoint.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ipsec-sentinel-ready

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ipsec-sentinel-topology.service strongswan.service \
  ipsec-sentinel-endpoint.service ipsec-sentinel-ready.service \
  ipsec-sentinel-watchdog.timer
systemctl restart ipsec-sentinel-topology.service
systemctl restart strongswan.service
swanctl --load-all
systemctl restart ipsec-sentinel-endpoint.service
systemctl restart ipsec-sentinel-ready.service
systemctl restart ipsec-sentinel-watchdog.timer

rm -rf /tmp/ipsec-sentinel-secrets /tmp/ipsec-sentinel-bundle
