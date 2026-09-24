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
echo "OK"
