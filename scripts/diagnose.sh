#!/bin/bash
# Диагностика обхода: что режет провайдер и какой способ tpws помогает.
# Запускать БЕЗ VPN. Системные настройки не меняет: tpws поднимается на тестовых портах.
#   scripts/diagnose.sh          — полная проверка (~7 минут)
#   scripts/diagnose.sh --quick  — быстрая проверка (2 способа, без Chrome)

# Из приложения передаются TPWS (путь к бинарнику) и DIAG_DIR (куда писать отчёт).
HERE="$(cd "$(dirname "$0")" && pwd)"
QUICK=0; [ "${1:-}" = "--quick" ] && QUICK=1

if [ -z "${TPWS:-}" ]; then
  for t in "$HERE/tpws" /Applications/ZapretBar.app/Contents/Resources/tpws "$HERE/../build/ZapretBar.app/Contents/Resources/tpws" "$HERE/../vendor/zapret/tpws/tpws"; do
    [ -x "$t" ] && { TPWS="$t"; break; }
  done
fi
[ -z "${TPWS:-}" ] && { echo "Не найден tpws — сначала scripts/build.sh"; exit 1; }
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

DIAG_DIR="${DIAG_DIR:-$HOME/Library/Application Support/ZapretBar/diagnostics}"
mkdir -p "$DIAG_DIR"
REPORT="$DIAG_DIR/report-$(date +%Y%m%d-%H%M%S).txt"
WORK=$(mktemp -d); trap 'pkill -P $$ 2>/dev/null; rm -rf "$WORK"' EXIT
exec > >(tee "$REPORT") 2>&1

URLS=(
  "youtube      https://www.youtube.com/"
  "ytimg        https://i.ytimg.com/"
  "googlevideo  https://redirector.googlevideo.com/report_mapping"
  "discord      https://discord.com/"
  "dc-gateway   https://gateway.discord.gg/"
  "dc-cdn       https://cdn.discordapp.com/"
  "x.com        https://x.com/"
  "rutracker    https://rutracker.org/"
  "instagram    https://www.instagram.com/"
  "linkedin     https://www.linkedin.com/"
  "[контроль]cf https://www.cloudflare.com/"
  "[контроль]ya https://ya.ru/"
)

STRATEGIES=(
  "--split-pos=1,midsld --hostcase"
  "--split-pos=1,midsld --oob --hostcase"
  "--tlsrec=1 --split-pos=1,midsld --hostcase"
  "--tlsrec=sniext+1 --split-pos=1,midsld --hostcase"
  "--tlsrec=sniext+1 --split-pos=1,host,midsld,endhost --oob --hostcase"
  "--split-pos=2"
  "--split-pos=sniext+1"
  "--split-pos=1,sniext+1,host+1,midsld,endhost-1"
  "--tlsrec=1 --split-pos=1,midsld --oob"
  "--split-pos=1 --oob"
  "--tlsrec=5 --split-pos=1,midsld"
)
# Подмена ClientHello (нужен доступ к /dev/bpf): приложение передаёт FAKE_LINK и FAKE_FILE.
if [ -n "${FAKE_LINK:-}" ] && [ -n "${FAKE_FILE:-}" ]; then
  STRATEGIES=("$FAKE_LINK --fake-tls=$FAKE_FILE --split-pos=1,midsld --hostcase"
              "$FAKE_LINK --fake-tls=$FAKE_FILE --split-pos=1,midsld --oob --hostcase"
              "$FAKE_LINK --fake-tls=$FAKE_FILE --fake-md5sig --split-pos=1,midsld --hostcase"
              "${STRATEGIES[@]}")
fi
[ $QUICK = 1 ] && STRATEGIES=("${STRATEGIES[@]:0:4}")

# Проверка WebSocket-шлюза Discord: подключение + получение HELLO.
cat > "$WORK/ws.py" <<'EOF'
import socket, ssl, struct, sys, os, base64
port = int(sys.argv[1]); host = "gateway.discord.gg"
try:
    if port:
        s = socket.create_connection(("127.0.0.1", port), timeout=8)
        s.sendall(b"\x05\x01\x00"); s.recv(2)
        h = host.encode(); s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", 443)); s.recv(10)
    else:
        s = socket.create_connection((host, 443), timeout=8)
    s.settimeout(8)
    t = ssl.create_default_context().wrap_socket(s, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    t.sendall(f"GET /?v=10&encoding=json HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode())
    data = b""
    while b"heartbeat_interval" not in data and len(data) < 65536:
        c = t.recv(4096)
        if not c: break
        data += c
    print("ok" if b"heartbeat_interval" in data else "nohello")
except Exception as e:
    print(type(e).__name__)
EOF

hr() { printf '%*s\n' 78 '' | tr ' ' '-'; }

# probe_all <port|0>  — параллельно проверяет все URLS, печатает таблицу.
probe_all() {
  local port=$1 i=0 px=() pids=()
  [ "$port" != 0 ] && px=(--socks5-hostname "127.0.0.1:$port")
  for entry in "${URLS[@]}"; do
    read -r name url <<<"$entry"
    ( r=$(curl -s -o /dev/null -m 8 -A "Mozilla/5.0" "${px[@]}" -w '%{http_code} tcp=%{time_connect} tls=%{time_appconnect} all=%{time_total} bytes=%{size_download}' "$url"); rc=$?
      printf "  %-13s %-62s rc=%s\n" "$name" "$r" "$rc" > "$WORK/p.$i" ) &
    pids+=($!); i=$((i+1))
  done
  # Ждём только свои curl: голый wait ждал бы и запущенный в фоне tpws.
  wait "${pids[@]}"
  for j in $(seq 0 $((i-1))); do cat "$WORK/p.$j"; done
  local ws=""; for k in 1 2 3; do ws="$ws $(python3 -I "$WORK/ws.py" "$port")"; done
  echo "  discord-ws   :$ws"
  if [ -n "${SPEED_URL:-}" ]; then
    echo "  скорость YT  : $(curl -s -o /dev/null -m 25 "${px[@]}" -w '%{size_download} байт за %{time_total} с = %{speed_download} Б/с' "$SPEED_URL"; echo " rc=$?")"
  fi
}

# chrome_test <port|0> <url> <n>  — настоящий Chrome (его TLS-приветствие отличается от curl).
chrome_test() {
  local port=$1 url=$2 n=$3 ok=0 marks="" px="--no-proxy-server"
  [ "$port" != 0 ] && px="--proxy-server=socks5://127.0.0.1:$port"
  for i in $(seq 1 "$n"); do
    local prof; prof=$(mktemp -d "$WORK/chrome.XXXX")
    "$CHROME" --headless=new --user-data-dir="$prof" --no-first-run --disable-quic "$px" \
      --timeout=12000 --dump-dom "$url" > "$WORK/dom" 2>/dev/null &
    local P=$!; ( sleep 18; kill $P 2>/dev/null ) & local W=$!
    wait $P 2>/dev/null; kill $W 2>/dev/null; wait $W 2>/dev/null
    if [ "$(wc -c < "$WORK/dom")" -gt 2000 ]; then ok=$((ok+1)); marks="$marks+"; else marks="$marks."; fi
    rm -rf "$prof"
  done
  printf "  %-40s %d/%d  %s\n" "$url" "$ok" "$n" "$marks"
}

start_tpws() { "$TPWS" --socks --bind-addr=127.0.0.1 --port="$1" "${@:2}" >/dev/null 2>&1 & TP=$!; sleep 0.5; }
stop_tpws() { kill "$TP" 2>/dev/null; wait "$TP" 2>/dev/null; }

echo "ZapretBar — диагностика $(date '+%Y-%m-%d %H:%M')  macOS $(sw_vers -productVersion)"
echo "tpws: $TPWS"
# VPN-клиенты вроде Happ/sing-box не трогают default, а ставят маршруты 0/1 и 128/1 — смотрим реальный путь.
iface=$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/{print $2}')
echo "Трафик в интернет идёт через: $iface"
if [[ "$iface" == utun* || "$iface" == ipsec* || "$iface" == ppp* ]] || scutil --nc list 2>/dev/null | grep -q "(Connected)"; then
  echo "!!! ПОХОЖЕ, ВКЛЮЧЁН VPN — результаты будут недостоверны. Выключите VPN и запустите снова."
fi
echo "Системный SOCKS-прокси: $(networksetup -getsocksfirewallproxy Wi-Fi 2>/dev/null | head -1)"
hr

echo "DNS: системный резолвер против DNS-over-HTTPS (Google)"
for d in www.youtube.com discord.com gateway.discord.gg x.com rutracker.org www.instagram.com www.linkedin.com; do
  sys=$(dig +short +time=3 +tries=1 "$d" | grep -E '^[0-9.]+$' | head -1)
  doh=$(curl -s -m 6 "https://dns.google/resolve?name=$d&type=A" | grep -oE '"data":"[0-9.]+"' | head -1 | cut -d'"' -f4)
  printf "  %-20s system=%-16s doh=%s\n" "$d" "${sys:--}" "${doh:-нет ответа}"
done
hr

# Адрес большого файла YouTube для замера скорости.
js=$(curl -s -m 10 -A "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/130 Safari/537.36" https://www.youtube.com/ | grep -oE '"jsUrl":"[^"]+"' | head -1 | cut -d'"' -f4)
[ -n "$js" ] && SPEED_URL="https://www.youtube.com$js" || SPEED_URL="https://www.youtube.com/s/player/11a45ffb/player_es6.vflset/de_DE/base.js"

echo "НАПРЯМУЮ (без обхода)"
probe_all 0
hr

port=11100
for s in "${STRATEGIES[@]}"; do
  echo "tpws $s"
  read -ra args <<<"$s"
  start_tpws $port "${args[@]}"
  if kill -0 "$TP" 2>/dev/null; then probe_all $port; else echo "  tpws не запустился с этими параметрами"; fi
  stop_tpws; port=$((port+1)); sleep 3
  hr
done

if [ $QUICK = 0 ] && [ -x "$CHROME" ]; then
  echo "НАСТОЯЩИЙ CHROME (headless, отдельный временный профиль)"
  echo "напрямую:"
  chrome_test 0 https://discord.com/login 4
  chrome_test 0 https://www.youtube.com/ 2
  for s in "${STRATEGIES[@]:0:3}"; do
    echo "tpws $s:"
    read -ra args <<<"$s"
    start_tpws $port "${args[@]}"
    chrome_test $port https://discord.com/login 5
    chrome_test $port https://www.youtube.com/ 2
    stop_tpws; port=$((port+1)); sleep 3
  done
  hr
fi

echo "НАПРЯМУЮ ещё раз (видно, не включил ли провайдер временную блокировку после тестов)"
probe_all 0
hr
echo "Готово. Отчёт: $REPORT"
