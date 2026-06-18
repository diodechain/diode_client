#!/usr/bin/env bash
# Capture TCP/socket stats during a diode fetch to eu2.
set -euo pipefail
EU2_IP="${EU2_IP:-157.173.98.132}"
EU2_PORT="${EU2_PORT:-41046}"
PCAP="${PCAP:-/tmp/diode-eu2.pcap}"
DURATION="${DURATION:-20}"
DB="${DB:-temp/client.db}"
URL="${URL:-http://ddriveupdate.diode.link/stable/}"

cd "$(dirname "$0")/.."
rm -f stable "$PCAP"

echo "=== starting fetch (background) ==="
./diode -dbpath="$DB" -diodeaddrs=eu2.prenet.diode.io fetch -url "$URL" > /tmp/fetch-out.log 2>&1 &
FETCH_PID=$!
echo "fetch pid=$FETCH_PID"

sleep 2
echo "=== client ss -ti (to $EU2_IP:$EU2_PORT) ==="
for i in $(seq 1 "$DURATION"); do
  if ss -tin "dst $EU2_IP" 2>/dev/null | grep -q "$EU2_PORT"; then
    echo "--- sample $i @ $(date +%T) ---"
    ss -tin "dst $EU2_IP" 2>/dev/null | grep -A1 "$EU2_PORT" || true
  fi
  sleep 1
done

if command -v tcpdump >/dev/null && [[ -w /tmp ]]; then
  echo "=== tcpdump ${DURATION}s -> $PCAP ==="
  timeout "$DURATION" tcpdump -i any -nn "host $EU2_IP and port $EU2_PORT" -s 96 -w "$PCAP" 2>/dev/null || true
fi

wait "$FETCH_PID" 2>/dev/null || true
echo "=== fetch exit: $(tail -1 /tmp/fetch-out.log 2>/dev/null || echo done) ==="

if [[ -f "$PCAP" ]] && command -v tshark >/dev/null; then
  echo "=== tshark summary ==="
  tshark -r "$PCAP" -q -z io,stat,0 2>/dev/null | tail -5
  echo "--- retransmissions ---"
  tshark -r "$PCAP" -Y "tcp.analysis.retransmission" -T fields -e frame.number 2>/dev/null | wc -l
  echo "--- duplicate ACKs ---"
  tshark -r "$PCAP" -Y "tcp.analysis.duplicate_ack" -T fields -e frame.number 2>/dev/null | wc -l
  echo "--- zero windows ---"
  tshark -r "$PCAP" -Y "tcp.analysis.zero_window" -T fields -e frame.number 2>/dev/null | wc -l
  echo "--- avg window (server->client, bytes) ---"
  tshark -r "$PCAP" -Y "ip.src==$EU2_IP && tcp.len>0" -T fields -e tcp.window_size_value 2>/dev/null | awk '{s+=$1;n++} END{if(n) printf "avg_win=%.0f min=%d max=%d samples=%d\n", s/n, min, max, n}' min=999999999 max=0
  echo "--- avg window (client->server, bytes) ---"
  tshark -r "$PCAP" -Y "ip.dst==$EU2_IP && tcp.len>0" -T fields -e tcp.window_size_value 2>/dev/null | awk '{s+=$1;n++; if($1<min||min==0)min=$1; if($1>max)max=$1} END{if(n) printf "avg_win=%.0f min=%d max=%d samples=%d\n", s/n, min, max, n}'
  echo "--- throughput by direction (Mbps) ---"
  tshark -r "$PCAP" -q -z conv,tcp 2>/dev/null | head -20
fi
