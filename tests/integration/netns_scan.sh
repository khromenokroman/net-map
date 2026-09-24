#!/bin/bash
# Интеграционный тест ARP-сканера в изолированной сети: мост, интерфейс сканера и «хосты»
# в отдельных сетевых пространствах, два из них с одинаковым IP. Права root не нужны.
# Код 77 — тест пропущен (нет user namespace).
set -eu
BIN=$(realpath "$1")

if [ -z "${NETNS_INNER:-}" ]; then
    unshare -rn true 2>/dev/null || { echo "user namespace недоступен, тест пропущен"; exit 77; }
    NETNS_INNER=1 exec unshare -rn bash "$0" "$BIN"
fi

ip link set lo up
ip link add br0 type bridge && ip link set br0 up
ip link add scan0 type veth peer name scan0-br
ip link set scan0-br master br0 && ip link set scan0-br up
ip addr add 10.99.0.1/24 dev scan0 && ip link set scan0 up

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
n=0
for a in 10 20 30 50 50; do
    n=$((n + 1))
    unshare -n sleep 60 &
    pid=$!
    pids+=("$pid")
    sleep 0.2
    ip link add "h$n" type veth peer name "h$n-br"
    ip link set "h$n-br" master br0 && ip link set "h$n-br" up
    ip link set "h$n" netns "$pid"
    nsenter -t "$pid" -n sh -c "ip link set lo up; ip addr add 10.99.0.$a/24 dev h$n; ip link set h$n up"
done
sleep 1

CFG=$(mktemp)
echo '{"interfaces": ["scan0"], "arp_timeout_ms": 500}' > "$CFG"
OUT=$("$BIN" --once "$CFG")
rm -f "$CFG"
echo "$OUT"

hosts=$(echo "$OUT" | grep -E '^  10\.99\.0\.' | grep -vc 'ЭТА МАШИНА')
conflicts=$(echo "$OUT" | grep -E '^  10\.99\.0\.' | grep -c 'КОНФЛИКТ IP' || true)
[ "$hosts" -eq 5 ] || { echo "ожидалось 5 хостов, найдено $hosts"; exit 1; }
[ "$conflicts" -eq 2 ] || { echo "ожидалось 2 строки с конфликтом 10.99.0.50, найдено $conflicts"; exit 1; }
echo "$OUT" | grep -qE '^  10\.99\.0\.50.*КОНФЛИКТ IP' || { echo "конфликт не на 10.99.0.50"; exit 1; }
echo "$OUT" | grep -qE '^  10\.99\.0\.1\s.*ЭТА МАШИНА' || { echo "нет собственного адреса 10.99.0.1"; exit 1; }
echo "$OUT" | grep -q 'событие: Конфликт IP 10.99.0.50' || { echo "нет события о конфликте"; exit 1; }
echo "--once: OK"

command -v curl >/dev/null && command -v python3 >/dev/null || { echo "нет curl/python3, проверка веб-сервера пропущена"; exit 0; }
CFG=$(mktemp)
echo '{"listen_addr": "127.0.0.1", "port": 18081, "interfaces": ["scan0"], "arp_timeout_ms": 500, "scan_interval_sec": 5}' > "$CFG"
"$BIN" "$CFG" &
app=$!
pids+=("$app")
for _ in $(seq 1 50); do
    json=$(curl -sf http://127.0.0.1:18081/api/network || true)
    [ -n "$json" ] && [ "$(echo "$json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["scans"])')" -ge 1 ] && break
    sleep 0.2
done
rm -f "$CFG"
echo "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
others = [h for h in d["hosts"] if not h["self"]]
assert len(others) == 5, f"хостов {len(others)}"
assert len(d["subnets"]) == 1 and d["subnets"][0]["subnet"] == "10.99.0.0/24", d["subnets"]
conflict = sorted(h["mac"] for h in d["hosts"] if h["conflict"])
assert len(conflict) == 2 and all(h["ip"] == "10.99.0.50" for h in d["hosts"] if h["conflict"]), conflict
assert any(e["kind"] == "ip_conflict" for e in d["events"]), d["events"]
' || { echo "неверный ответ /api/network: $json"; exit 1; }
curl -sf http://127.0.0.1:18081/ | grep -q "<title>Карта сети</title>" || { echo "страница не отдаётся"; exit 1; }
kill -TERM "$app"
wait "$app" || { echo "программа завершилась с ошибкой"; exit 1; }
echo "веб-сервер: OK"
