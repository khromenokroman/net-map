#!/bin/bash
# Интеграционный тест наблюдения за DHCP в изолированной сети: два DHCP-сервера (dnsmasq) и три клиента
# (busybox udhcpc), два из них с одинаковым Client-ID, как у клонов с общим /etc/machine-id.
# Программа работает в режиме службы с активным поиском серверов. Права root не нужны.
# Код 77 — тест пропущен (нет user namespace, dnsmasq, busybox, curl или python3).
set -eu
BIN=$(realpath "$1")

if [ -z "${NETNS_INNER:-}" ]; then
    for tool in dnsmasq busybox curl python3; do
        command -v "$tool" >/dev/null || { echo "нет $tool, тест пропущен"; exit 77; }
    done
    unshare -rn true 2>/dev/null || { echo "user namespace недоступен, тест пропущен"; exit 77; }
    NETNS_INNER=1 exec unshare -rn bash "$0" "$BIN"
fi

TMP=$(mktemp -d)
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true; rm -rf "$TMP"' EXIT

ip link set lo up
ip link add br0 type bridge && ip link set br0 up
ip link add scan0 type veth peer name scan0-br
ip link set scan0-br master br0 && ip link set scan0-br up
ip addr add 10.88.0.5/24 dev scan0 && ip link set scan0 up

LAST=
mkns() {
    unshare -n sleep 120 &
    LAST=$!
    pids+=("$LAST")
    sleep 0.2
}
attach() { # имя mac pid
    ip link add "$1" type veth peer name "$1-br"
    ip link set "$1-br" master br0 && ip link set "$1-br" up
    ip link set "$1" address "$2" && ip link set "$1" netns "$3"
    nsenter -t "$3" -n sh -c "ip link set lo up; ip link set $1 up"
}
for i in 1 2; do
    mkns
    attach "srv$i" "00:0c:29:00:00:0$i" "$LAST"
    nsenter -t "$LAST" -n ip addr add "10.88.0.$i/24" dev "srv$i"
    nsenter -t "$LAST" -n dnsmasq --no-daemon --conf-file=/dev/null --port=0 --interface="srv$i" --bind-interfaces \
        --dhcp-range="10.88.0.$((i * 100)),10.88.0.$((i * 100 + 20)),1h" --pid-file="$TMP/dm$i.pid" \
        --dhcp-leasefile="$TMP/dm$i.leases" 2>/dev/null &
    pids+=("$!")
done
sleep 1

echo '{"listen_addr": "127.0.0.1", "port": 18089, "interfaces": ["scan0"], "arp_timeout_ms": 300, "scan_interval_sec": 5,
       "dhcp_probe": true, "dhcp_probe_interval_sec": 60}' > "$TMP/cfg.json"
"$BIN" "$TMP/cfg.json" &
app=$!
pids+=("$app")
for _ in $(seq 1 50); do
    curl -sf http://127.0.0.1:18089/api/network | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin)["dhcp"]["watching"] else 1)' && break
    sleep 0.2
done

ID=ff5cbbeb5e00020000ab11af86b5c9217d4733
client() { # имя mac опции...
    local name=$1 mac=$2
    shift 2
    mkns
    attach "$name" "$mac" "$LAST"
    nsenter -t "$LAST" -n busybox udhcpc -i "$name" -n -q -f -t 3 "$@" -s /bin/true >/dev/null 2>&1 || true
}
client cli1 54:02:02:03:52:50 -x 0x3d:$ID -x hostname:eve-img
client cli2 50:02:00:04:00:00 -x 0x3d:$ID -x hostname:eve-img6
client cli3 00:1b:21:3a:4b:5c -x hostname:build-01
sleep 1

curl -sf http://127.0.0.1:18089/api/network | python3 -c '
import json, sys
d = json.load(sys.stdin)
x = d["dhcp"]
servers = sorted(s["ip"] for s in x["servers"])
assert servers == ["10.88.0.1", "10.88.0.2"], f"серверы {servers}"
assert all(s["answered_probe"] for s in x["servers"]), x["servers"]
clients = {c["mac"]: c for c in x["clients"]}
assert set(clients) == {"54:02:02:03:52:50", "50:02:00:04:00:00", "00:1b:21:3a:4b:5c"}, sorted(clients)
assert clients["00:1b:21:3a:4b:5c"]["hostname"] == "build-01"
assert list(x["shared_client_ids"]) == ["ff5cbbeb5e00020000ab11af86b5c9217d4733"], x["shared_client_ids"]
kinds = [e["kind"] for e in d["events"]]
assert "dhcp_multiple_servers" in kinds and "dhcp_shared_client_id" in kinds, kinds
' || { echo "неверный ответ /api/network"; exit 1; }
kill -TERM "$app"
wait "$app" || { echo "программа завершилась с ошибкой"; exit 1; }
echo "DHCP: OK"
